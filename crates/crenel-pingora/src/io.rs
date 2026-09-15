//! Body execution against the served fd.
//!
//! Two paths, pinned by the spike (docs/plans/-path-engine.md):
//! - `len <= inline_threshold`: pread INLINE on the async worker (per-request
//!   spawn_blocking measured ~9x slower on page-cache-hot small files; cold-small reads
//!   inline are the accepted nginx-default posture, design D4).
//! - larger: ONE blocking reader task streaming chunks through a bounded 2-slot channel
//!   so pread and downstream (TLS) writes PIPELINE, `fadvise(SEQUENTIAL)`
//!   first, cooperative `yield_now` between writes (sendfile_max_chunk fairness analog).
//!
//! The whole send runs under the response budget; expiry closes the connection
//! (Content-Length framing makes the truncation client-detectable). Reader tasks are
//! gated by the [`IoLimiter`] semaphore, acquired BEFORE the header commits so
//! sheds are clean 503s.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use pingora::protocols::http::ServerSession;
use rustix::fs::{fadvise, Advice};
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crenel::resolve::ServedFile;

use crate::config::Limits;
use crate::counters::Counters;

/// Outcome of executing a body plan. Anything but `Complete` means the connection must
/// not be reused (framing may be truncated).
#[derive(Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Complete {
        bytes: u64,
    },
    /// Client disconnected or stopped reading past the per-write timeout.
    ClientGone,
    /// Whole-response budget expired.
    DeadlineExceeded,
    /// Filesystem misbehaved mid-send (short read / pread error) after the header
    /// committed — abort so the client sees truncation, never padded garbage.
    IoFault,
}

/// IO semaphore with a bounded waiting room: `None` = shed (503).
pub struct IoLimiter {
    semaphore: Arc<Semaphore>,
    waiters: AtomicUsize,
    max_waiters: usize,
}

impl IoLimiter {
    pub fn new(permits: usize, max_waiters: usize) -> IoLimiter {
        IoLimiter {
            semaphore: Arc::new(Semaphore::new(permits.max(1))),
            waiters: AtomicUsize::new(0),
            max_waiters,
        }
    }

    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        // Fast path: a free permit means no queueing at all.
        if let Ok(permit) = Arc::clone(&self.semaphore).try_acquire_owned() {
            return Some(permit);
        }
        // Bounded waiting room; beyond it we shed instead of building unbounded queues.
        if self.waiters.fetch_add(1, Ordering::AcqRel) >= self.max_waiters {
            self.waiters.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        let acquired = Arc::clone(&self.semaphore).acquire_owned().await.ok();
        self.waiters.fetch_sub(1, Ordering::AcqRel);
        acquired
    }
}

/// Execute a resolved body range. The header MUST already be written; `permit` MUST be
/// `Some` for bodies above the inline threshold (acquired pre-header by the caller).
pub async fn send_body(
    session: &mut ServerSession,
    file: ServedFile,
    offset: u64,
    len: u64,
    limits: &Limits,
    counters: &Counters,
    permit: Option<OwnedSemaphorePermit>,
) -> SendOutcome {
    let budget = limits.response_budget(len);
    let outcome = tokio::time::timeout(budget, async {
        if len <= limits.inline_threshold {
            send_inline(session, &file, offset, len).await
        } else {
            send_streamed(session, file, offset, len, limits).await
        }
    })
    .await;
    // Reader-task teardown on deadline: dropping the receiver (inside the aborted
    // future) makes the blocking task's send fail and exit; the permit releases here.
    drop(permit);

    match outcome {
        Ok(SendOutcome::Complete { bytes }) => {
            counters.add_bytes(bytes);
            SendOutcome::Complete { bytes }
        }
        Ok(other) => {
            match &other {
                SendOutcome::ClientGone => {
                    counters.client_aborts.fetch_add(1, Ordering::Relaxed);
                }
                SendOutcome::IoFault => {
                    counters.io_faults.fetch_add(1, Ordering::Relaxed);
                }
                // WriteTimedout inside the budget window (slow client, same class).
                SendOutcome::DeadlineExceeded => {
                    counters.deadline_aborts.fetch_add(1, Ordering::Relaxed);
                }
                SendOutcome::Complete { .. } => {}
            }
            other
        }
        Err(_elapsed) => {
            counters.deadline_aborts.fetch_add(1, Ordering::Relaxed);
            session.shutdown().await;
            SendOutcome::DeadlineExceeded
        }
    }
}

async fn send_inline(
    session: &mut ServerSession,
    file: &ServedFile,
    offset: u64,
    len: u64,
) -> SendOutcome {
    let mut buf = BytesMut::zeroed(len as usize);
    let mut filled = 0usize;
    while filled < buf.len() {
        match rustix::io::pread(&file.fd, &mut buf[filled..], offset + filled as u64) {
            Ok(0) => return SendOutcome::IoFault, // shorter than the fstat snapshot
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return SendOutcome::IoFault,
        }
    }
    match session.write_response_body(buf.freeze(), true).await {
        Ok(()) => SendOutcome::Complete { bytes: len },
        Err(e) => classify_write_error_uncounted(&e),
    }
}

async fn send_streamed(
    session: &mut ServerSession,
    file: ServedFile,
    offset: u64,
    len: u64,
    limits: &Limits,
) -> SendOutcome {
    // Double-buffered readahead: capacity 2 keeps exactly one chunk in flight while the
    // previous one is being (TLS-)written downstream.
    let (chunk_tx, mut chunk_rx) = mpsc::channel::<Result<Bytes, ()>>(2);
    let chunk_bytes = limits.chunk_bytes.max(4096);

    let reader = tokio::task::spawn_blocking(move || {
        // Advisory readahead hint for the sequential scan; ignore failures.
        let _ = fadvise(
            &file.fd,
            offset,
            std::num::NonZeroU64::new(len),
            Advice::Sequential,
        );
        let mut remaining = len;
        let mut position = offset;
        while remaining > 0 {
            let want = chunk_bytes.min(remaining as usize);
            let mut buf = BytesMut::zeroed(want);
            let mut filled = 0usize;
            while filled < want {
                match rustix::io::pread(&file.fd, &mut buf[filled..], position + filled as u64) {
                    Ok(0) => {
                        let _ = chunk_tx.blocking_send(Err(()));
                        return;
                    }
                    Ok(n) => filled += n,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => {
                        let _ = chunk_tx.blocking_send(Err(()));
                        return;
                    }
                }
            }
            position += want as u64;
            remaining -= want as u64;
            if chunk_tx.blocking_send(Ok(buf.freeze())).is_err() {
                return; // writer gone (deadline/client abort): stop reading
            }
        }
    });

    let mut sent = 0u64;
    let outcome = loop {
        match chunk_rx.recv().await {
            Some(Ok(chunk)) => {
                let n = chunk.len() as u64;
                if let Err(e) = session.write_response_body(chunk, false).await {
                    break classify_write_error_uncounted(&e);
                }
                sent += n;
                // Fairness: never monopolize the worker between chunks.
                tokio::task::yield_now().await;
            }
            Some(Err(())) => break SendOutcome::IoFault,
            None => {
                // Reader finished cleanly: terminate the message framing.
                match session.write_response_body(Bytes::new(), true).await {
                    Ok(()) => break SendOutcome::Complete { bytes: sent },
                    Err(e) => break classify_write_error_uncounted(&e),
                }
            }
        }
    };
    drop(chunk_rx); // unblock the reader if we bailed early
    let _ = reader.await;
    outcome
}

/// Error mapping WITHOUT counter side effects (counting happens once in `send_body`).
fn classify_write_error_uncounted(e: &pingora::Error) -> SendOutcome {
    use pingora::ErrorType;
    match &e.etype {
        ErrorType::WriteTimedout => SendOutcome::DeadlineExceeded,
        _ => SendOutcome::ClientGone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limiter_sheds_beyond_waiting_room() {
        let limiter = IoLimiter::new(1, 0); // one permit, zero waiting room
        let held = limiter.acquire().await.expect("first permit");
        // Second acquire has no free permit and no waiter slot: immediate shed.
        assert!(limiter.acquire().await.is_none());
        drop(held);
        assert!(limiter.acquire().await.is_some());
    }

    #[tokio::test]
    async fn limiter_queues_within_waiting_room() {
        let limiter = Arc::new(IoLimiter::new(1, 8));
        let held = limiter.acquire().await.expect("permit");
        let waiter = {
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move { limiter.acquire().await.is_some() })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(held); // release -> queued waiter proceeds
        assert!(waiter.await.expect("join"));
    }
}

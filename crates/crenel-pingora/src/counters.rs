//! Telemetry counters, exporter-agnostic: the consumer (a host server's /metrics, or the
//! example binary's logs) snapshots and formats them itself.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Counters {
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
    pub bytes_sent: AtomicU64,
    /// IO-semaphore sheds (503 before the header was committed) — .
    pub sheds: AtomicU64,
    /// Whole-response deadline / write-timeout aborts (connection closed mid-body) — F7.
    pub deadline_aborts: AtomicU64,
    /// Client went away mid-response (WriteError / ConnectionClosed).
    pub client_aborts: AtomicU64,
    /// Unexpected filesystem faults (500-class or mid-body truncation aborts).
    pub io_faults: AtomicU64,
    /// Deploy-coupled root re-pins observed.
    pub repins: AtomicU64,
}

impl Counters {
    pub fn record_status(&self, status: u16) {
        let bucket = match status {
            200..=299 => &self.status_2xx,
            300..=399 => &self.status_3xx,
            400..=499 => &self.status_4xx,
            _ => &self.status_5xx,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Stable name → value pairs for exporters.
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let read = |c: &AtomicU64| c.load(Ordering::Relaxed);
        vec![
            ("crenel_status_2xx_total", read(&self.status_2xx)),
            ("crenel_status_3xx_total", read(&self.status_3xx)),
            ("crenel_status_4xx_total", read(&self.status_4xx)),
            ("crenel_status_5xx_total", read(&self.status_5xx)),
            ("crenel_bytes_sent_total", read(&self.bytes_sent)),
            ("crenel_io_sheds_total", read(&self.sheds)),
            ("crenel_deadline_aborts_total", read(&self.deadline_aborts)),
            ("crenel_client_aborts_total", read(&self.client_aborts)),
            ("crenel_io_faults_total", read(&self.io_faults)),
            ("crenel_root_repins_total", read(&self.repins)),
        ]
    }
}

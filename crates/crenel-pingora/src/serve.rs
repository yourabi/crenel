//! The serve orchestration: classify → (re-pin) → resolve → directory dispatch →
//! sidecar negotiation → plan → execute. This reproduces the golden-fixture harness's
//! `Engine::answer` (crenel tests/nginx_golden.rs) — the pinned reference — over a
//! real pingora `ServerSession`, taking `&mut ServerSession` so BOTH consumer shapes
//! work: a standalone `HttpServerApp`, and a host server's `request_filter` via
//! `session.as_downstream_mut`.

use std::sync::Arc;

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::protocols::http::ServerSession;

use crenel::headers;
use crenel::pipeline::{classify, Classification, Mount, Mounts};
use crenel::resolve::{Outcome, Root};
use crenel::semantics::{
    directory_action, plan_response, BodyPlan, DirectoryAction, FileFacts, RequestFacts,
    ResponsePolicy,
};
use crenel::sidecar::{negotiate, Encoding};

use crate::config::{MountSpec, OnMiss, StaticServerConfig};
use crate::counters::Counters;
use crate::io::{send_body, IoLimiter, SendOutcome};

/// What `serve` did with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// A response was written (or the connection deliberately aborted). `reusable`
    /// reports whether the H1 connection may be kept alive (complete framing).
    Done { reusable: bool },
    /// Not this crate's request (non-GET/HEAD, no mount, or a fallthrough miss): the
    /// caller routes it to the application. NOTHING was written.
    NotStatic,
}

/// Boot error: mount table or root pinning failed (all fail-closed).
#[derive(Debug)]
pub enum BuildError {
    Mount(crenel::pipeline::MountError),
    Root {
        prefix: String,
        error: crenel::resolve::RootError,
    },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::Mount(e) => write!(f, "mount table: {e}"),
            BuildError::Root { prefix, error } => {
                write!(f, "pinning docroot for mount {prefix:?}: {error}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

struct MountRuntime {
    spec: MountSpec,
    root: Root,
}

/// A configured static server: one pinned root per mount, shared IO limiter, counters.
pub struct StaticServer {
    mounts: Mounts,
    runtimes: Vec<MountRuntime>,
    limits: crate::config::Limits,
    limiter: IoLimiter,
    pub counters: Arc<Counters>,
}

impl StaticServer {
    pub fn new(config: StaticServerConfig) -> Result<StaticServer, BuildError> {
        let mut table = Vec::with_capacity(config.mounts.len());
        let mut runtimes = Vec::with_capacity(config.mounts.len());
        for spec in config.mounts {
            let mount = Mount::new(&spec.prefix, spec.allow_dotfiles).map_err(BuildError::Mount)?;
            let root = Root::pin(&spec.docroot, spec.symlink_policy).map_err(|error| {
                BuildError::Root {
                    prefix: spec.prefix.clone(),
                    error,
                }
            })?;
            table.push(mount);
            runtimes.push(MountRuntime { spec, root });
        }
        Ok(StaticServer {
            mounts: Mounts::new(table).map_err(BuildError::Mount)?,
            runtimes,
            limiter: IoLimiter::new(config.limits.io_permits, config.limits.io_max_waiters),
            limits: config.limits,
            counters: Arc::new(Counters::default()),
        })
    }

    /// Serve one already-read request (`session.read_request` must have returned
    /// true). Never panics on hostile input; never writes anything for `NotStatic`.
    pub async fn serve(&self, session: &mut ServerSession) -> Served {
        session.set_write_timeout(Some(self.limits.write_timeout));

        // Byte-exact request target; non-UTF-8 targets are hostile by the pipeline's
        // own screen (raw_path is the pre-normalization bytes — one parser).
        let (method, target) = {
            let req = session.req_header();
            let method = req.method.as_str().to_string();
            match std::str::from_utf8(req.raw_path()) {
                Ok(t) => (method, t.to_string()),
                Err(_) => return self.respond_error(session, 400).await,
            }
        };

        let candidate = match classify(&method, &target, &self.mounts) {
            Classification::NotStatic(_) => return Served::NotStatic,
            Classification::Reject(_) => return self.respond_error(session, 400).await,
            Classification::Miss { mount, .. } => {
                return self.miss(session, mount).await;
            }
            Classification::Candidate(c) => c,
        };
        let runtime = &self.runtimes[candidate.mount];

        // Deploy-coupled re-pin, amortized to once per static candidate.
        match runtime.root.check_repin() {
            Ok(true) => {
                self.counters
                    .repins
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(false) => {}
            Err(_) => return self.respond_error(session, 500).await,
        }

        // Directory dispatch (index / add-slash redirect / miss). : the dispatch
        // resolution is REUSED below — the earlier code discarded this Outcome for
        // every non-Directory result and re-resolved the identical rel inside
        // open_encoded, one wasted openat2 per request (hit and miss alike). Only the
        // ServeIndex branch re-resolves, because its rel genuinely changes.
        let (rel, identity) = match runtime.root.open_rel(&candidate.rel_path) {
            Outcome::Directory => {
                match directory_action(candidate.trailing_slash, runtime.spec.index) {
                    DirectoryAction::Miss => return self.miss(session, candidate.mount).await,
                    DirectoryAction::RedirectAddSlash => {
                        let query = raw_query(&target);
                        let location = headers::redirect_location(
                            self.mounts.get(candidate.mount).prefix(),
                            &candidate.rel_path,
                            query,
                        );
                        return self.redirect(session, location).await;
                    }
                    DirectoryAction::ServeIndex => {
                        let rel = if candidate.rel_path.is_empty() {
                            "index.html".to_string()
                        } else {
                            format!("{}/index.html", candidate.rel_path)
                        };
                        let identity = runtime.root.open_rel(&rel);
                        (rel, identity)
                    }
                }
            }
            other => (candidate.rel_path.clone(), other),
        };

        // Sidecar negotiation + resolution (identity is authoritative — ledger D8).
        let preference = if runtime.spec.sidecars {
            let accept = header_str(session, "accept-encoding");
            negotiate(accept.as_deref())
        } else {
            Vec::new()
        };
        let encoded = runtime
            .root
            .open_encoded_with_identity(&rel, &preference, identity);
        let (encoding, file) = match encoded.identity {
            Outcome::File(identity_file) => match encoded.sidecar {
                Some((encoding, sidecar)) => (encoding, sidecar),
                None => (Encoding::Identity, identity_file),
            },
            Outcome::Miss(_) => return self.miss(session, candidate.mount).await,
            Outcome::Directory => return self.miss(session, candidate.mount).await,
            Outcome::Shed => return self.respond_error(session, 503).await,
            Outcome::Fault(_) => {
                self.counters
                    .io_faults
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return self.respond_error(session, 500).await;
            }
        };

        // Plan the response from the chosen representation's snapshot.
        let facts = FileFacts {
            len: file.len,
            mtime_sec: file.mtime_sec,
            mtime_nsec: file.mtime_nsec,
            encoding,
            vary_applies: runtime.spec.sidecars,
            content_type: headers::content_type_for(&rel),
        };
        let if_match = header_str(session, "if-match");
        let if_none_match = header_str(session, "if-none-match");
        let if_modified_since = header_str(session, "if-modified-since");
        let if_unmodified_since = header_str(session, "if-unmodified-since");
        let if_range = header_str(session, "if-range");
        let range = header_str(session, "range");
        let req_facts = RequestFacts {
            head: method == "HEAD",
            if_match: if_match.as_deref(),
            if_none_match: if_none_match.as_deref(),
            if_modified_since: if_modified_since.as_deref(),
            if_unmodified_since: if_unmodified_since.as_deref(),
            if_range: if_range.as_deref(),
            range: range.as_deref(),
        };
        let policy = ResponsePolicy {
            cache_control: runtime.spec.cache_control.as_deref(),
        };
        let plan = plan_response(&req_facts, &facts, &policy);

        // Resolve the body work before committing the header, so sheds are clean 503s.
        let (body_offset, body_len) = match plan.body {
            BodyPlan::None => (0, 0),
            BodyPlan::Whole => (0, file.len),
            BodyPlan::Range { offset, len } => (offset, len),
        };
        let permit = if plan.body != BodyPlan::None && body_len > self.limits.inline_threshold {
            match self.limiter.acquire().await {
                Some(permit) => Some(permit),
                None => {
                    self.counters
                        .sheds
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return self.respond_error(session, 503).await;
                }
            }
        } else {
            None
        };

        self.counters.record_status(plan.status);
        let mut resp = match ResponseHeader::build(plan.status, Some(plan.headers.len())) {
            Ok(r) => r,
            Err(_) => return self.respond_error(session, 500).await,
        };
        for (name, value) in &plan.headers {
            if resp.append_header(*name, value).is_err() {
                return self.respond_error(session, 500).await;
            }
        }
        if session.write_response_header(Box::new(resp)).await.is_err() {
            return Served::Done { reusable: false };
        }

        if plan.body == BodyPlan::None {
            // HEAD / 304 / 412 / 416: terminate framing with an empty final write.
            let reusable = session
                .write_response_body(Bytes::new(), true)
                .await
                .is_ok();
            return Served::Done { reusable };
        }

        match send_body(
            session,
            file,
            body_offset,
            body_len,
            &self.limits,
            &self.counters,
            permit,
        )
        .await
        {
            SendOutcome::Complete { .. } => Served::Done { reusable: true },
            SendOutcome::DeadlineExceeded | SendOutcome::ClientGone | SendOutcome::IoFault => {
                Served::Done { reusable: false }
            }
        }
    }

    async fn miss(&self, session: &mut ServerSession, mount: usize) -> Served {
        match self.runtimes[mount].spec.on_miss {
            OnMiss::Fallthrough => Served::NotStatic,
            OnMiss::NotFound => self.respond_error(session, 404).await,
        }
    }

    async fn respond_error(&self, session: &mut ServerSession, status: u16) -> Served {
        self.counters.record_status(status);
        let reusable = session.respond_error(status).await.is_ok();
        Served::Done { reusable }
    }

    async fn redirect(&self, session: &mut ServerSession, location: String) -> Served {
        self.counters.record_status(301);
        let mut resp = match ResponseHeader::build(301, Some(3)) {
            Ok(r) => r,
            Err(_) => return self.respond_error(session, 500).await,
        };
        let ok = resp.append_header("location", &location).is_ok()
            && resp.append_header("content-length", "0").is_ok()
            && resp
                .append_header("x-content-type-options", "nosniff")
                .is_ok();
        if !ok {
            return self.respond_error(session, 500).await;
        }
        if session.write_response_header(Box::new(resp)).await.is_err() {
            return Served::Done { reusable: false };
        }
        let reusable = session
            .write_response_body(Bytes::new(), true)
            .await
            .is_ok();
        Served::Done { reusable }
    }
}

/// Owned copy of a request header value; `None` when absent or not valid UTF-8 (a
/// non-UTF-8 conditional value simply fails to constrain, per RFC 9110 §13.1).
fn header_str(session: &ServerSession, name: &str) -> Option<String> {
    session
        .get_header(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The raw query (bytes after the FIRST '?', consistent with the pipeline's raw split).
fn raw_query(target: &str) -> Option<&str> {
    target.split_once('?').map(|(_, q)| q)
}

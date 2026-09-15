//! # crenel-pingora
//!
//! Pingora adapter for the [crenel] static-file engine: streamed serving over the
//! pingora server `Session` with the mandated runtime protections — whole-response
//! deadline (F7), bounded IO semaphore (F8), read/write pipelining (F9) — and the
//! spike-pinned inline small reads.
//!
//! Two consumer shapes, one entry point ([`StaticServer::serve`], which takes
//! `&mut pingora::protocols::http::ServerSession`):
//! - a standalone app: wrap [`StaticServer`] in [`StaticApp`] (an `HttpServerApp`) —
//!   see the `crenel-serve` example binary;
//! - a proxy: inside `ProxyHttp::request_filter`, pass
//!   `session.as_downstream_mut`, and on [`Served::Done`] return `Ok(true)` to
//!   short-circuit the upstream; [`Served::NotStatic`] continues to the app.
//!
//! Linux-only (the engine's resolver is openat2-based); on other targets this crate is
//! an empty stub so workspace checks pass on non-Linux dev hosts.

#![cfg(target_os = "linux")]

pub mod config;
pub mod counters;
pub mod io;
pub mod serve;

pub use config::{Limits, MountSpec, OnMiss, StaticServerConfig};
pub use counters::Counters;
pub use serve::{BuildError, Served, StaticServer};

use std::sync::Arc;

use async_trait::async_trait;
use pingora::apps::{HttpPersistentSettings, HttpServerApp, ReusedHttpStream};
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;

/// Standalone static-file app: serves mounts, answers 404 for everything the engine
/// hands back (there is no application behind it to fall through to). The 404 carries
/// `x-crenel-fallthrough: 1` so consumers/tests can tell "engine declined" from
/// "engine said not found".
pub struct StaticApp {
    pub server: StaticServer,
}

#[async_trait]
impl HttpServerApp for StaticApp {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        match session.read_request().await {
            Ok(true) => {}
            Ok(false) | Err(_) => return None,
        }

        let reusable = match self.server.serve(&mut session).await {
            Served::Done { reusable } => reusable,
            Served::NotStatic => {
                self.server.counters.record_status(404);
                let mut resp = pingora::http::ResponseHeader::build(404, Some(2)).ok()?;
                resp.append_header("content-length", "0").ok()?;
                resp.append_header("x-crenel-fallthrough", "1").ok()?;
                session.write_response_header(Box::new(resp)).await.ok()?;
                session
                    .write_response_body(bytes::Bytes::new(), true)
                    .await
                    .is_ok()
            }
        };
        if !reusable {
            return None;
        }
        let settings = HttpPersistentSettings::for_session(&session);
        match session.finish().await {
            Ok(Some(stream)) => Some(ReusedHttpStream::new(stream, Some(settings))),
            _ => None,
        }
    }
}

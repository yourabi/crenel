//! # crenel
//!
//! Framework-agnostic engine for serving static files safely and fast.
//!
//! Two halves:
//!
//! - [`pipeline`] — pure, cross-platform request-path **classification**: one decode-once
//!   pipeline that turns a raw request target into "not static / structurally hostile (400) /
//!   policy miss / candidate file". The consumer (an HTTP server) must never re-derive
//!   static-eligibility from raw bytes — two parsers is how CVE-2013-4547-class bugs happen.
//! - [`resolve`] (Linux and macOS) — race-free **filesystem resolution** of a classified candidate:
//!   a pinned docroot dirfd plus kernel-scoped (`RESOLVE_BENEATH`) containment, so no
//!   separate check-then-open step is needed for containment.
//!
//! The request-path and resolver tests exercise these guarantees. See the public
//! [behavioral differences from nginx](https://github.com/yourabi/crenel/blob/main/docs/DIVERGENCES.md)
//! for the HTTP policies and their test coverage.

#![forbid(unsafe_code)]

pub mod headers;
pub mod pipeline;
pub mod semantics;
pub mod sidecar;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod resolve;

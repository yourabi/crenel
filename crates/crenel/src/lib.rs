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
//! - [`resolve`] (Linux-only) — race-free **filesystem resolution** of a classified candidate:
//!   a pinned docroot dirfd plus `openat2(RESOLVE_BENEATH)` containment, so no
//!   check-then-open TOCTOU window exists at all (strictly better than nginx
//!   `disable_symlinks`, which its own docs concede is racy).
//!
//! The security posture is documented in the repo's `docs/DESIGN.md` and every property is
//! traceable to a named CVE/RUSTSEC advisory or review finding.

#![forbid(unsafe_code)]

pub mod headers;
pub mod pipeline;
pub mod semantics;
pub mod sidecar;

#[cfg(target_os = "linux")]
pub mod resolve;

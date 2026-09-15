//! Boot configuration: mounts (URL prefix → pinned docroot + per-mount policy) and the
//! runtime limits mandated by review: deadline, IO semaphore, and chunking.

use std::path::PathBuf;
use std::time::Duration;

use crenel::resolve::SymlinkPolicy;

/// What a mount does with a static miss (design D6.1): hand the request back to the app
/// (nginx `try_files $uri @app` shape) or answer 404 itself (fingerprinted `/assets`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnMiss {
    Fallthrough,
    NotFound,
}

/// One URL-prefix → docroot mapping plus its policy knobs.
#[derive(Debug, Clone)]
pub struct MountSpec {
    pub prefix: String,
    pub docroot: PathBuf,
    /// Default deny (request-time `RESOLVE_NO_SYMLINKS`); boot audit explains rejects.
    pub symlink_policy: SymlinkPolicy,
    pub allow_dotfiles: bool,
    /// Serve `index.html` behind a trailing slash; 301 to add the slash otherwise.
    pub index: bool,
    /// Emitted verbatim on success responses when set.
    pub cache_control: Option<String>,
    /// Try `.br`/`.zst`/`.gz` sidecars by Accept-Encoding.
    pub sidecars: bool,
    pub on_miss: OnMiss,
}

impl MountSpec {
    /// Conservative defaults: symlinks denied, dotfiles denied, no index, sidecars on,
    /// strict 404 on miss.
    pub fn new(prefix: impl Into<String>, docroot: impl Into<PathBuf>) -> MountSpec {
        MountSpec {
            prefix: prefix.into(),
            docroot: docroot.into(),
            symlink_policy: SymlinkPolicy::Deny,
            allow_dotfiles: false,
            index: false,
            cache_control: None,
            sidecars: true,
            on_miss: OnMiss::NotFound,
        }
    }

    /// Parse the canonical spec string `PREFIX=DIR[,opt,…]` shared by every consumer
    /// (crenel-serve flags, or a host server's `--static-mount`/env). Options: `index`,
    /// `fallthrough`, `dotfiles`, `symlinks-within-root`, `no-sidecars`,
    /// `cache-control=VALUE` (encode commas inside VALUE as `%2C`). Unknown options
    /// fail closed — config typos must not silently weaken policy.
    pub fn parse(raw: &str) -> Result<MountSpec, String> {
        let (prefix, rest) = raw
            .split_once('=')
            .ok_or_else(|| format!("mount spec must be PREFIX=DIR[,opts]: {raw:?}"))?;
        let mut parts = rest.split(',');
        let dir = parts.next().unwrap_or_default();
        if dir.is_empty() {
            return Err(format!("mount spec {raw:?}: empty directory"));
        }
        let mut spec = MountSpec::new(prefix, dir);
        for opt in parts {
            match opt {
                "index" => spec.index = true,
                "fallthrough" => spec.on_miss = OnMiss::Fallthrough,
                "dotfiles" => spec.allow_dotfiles = true,
                "symlinks-within-root" => spec.symlink_policy = SymlinkPolicy::AllowWithinRoot,
                "no-sidecars" => spec.sidecars = false,
                _ => match opt.strip_prefix("cache-control=") {
                    Some(value) => spec.cache_control = Some(value.replace("%2C", ",")),
                    None => return Err(format!("mount spec {raw:?}: unknown option {opt:?}")),
                },
            }
        }
        Ok(spec)
    }
}

/// Runtime limits. Every default is a reviewed posture, overridable per deployment.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Bodies at or below this read INLINE on the async worker (spike-pinned 2026-07-10:
    /// per-request spawn_blocking measured ~9x slower at 1 KiB). Cold-small reads inline
    /// are the accepted nginx-default risk posture (design D4).
    pub inline_threshold: u64,
    /// Reader-task chunk size for large bodies.
    pub chunk_bytes: usize,
    /// Per-write timeout handed to the pingora session (H1+H2).
    pub write_timeout: Duration,
    /// Whole-response budget = clamp(len / min_throughput, floor, cap) — a
    /// slow reader must not hold resources for chunks x timeout on a multi-GB file.
    pub min_throughput_bytes_per_sec: u64,
    pub deadline_floor: Duration,
    pub deadline_cap: Duration,
    /// Concurrent blocking-pool file tasks.
    pub io_permits: usize,
    /// Waiters allowed to queue for a permit before shedding 503.
    pub io_max_waiters: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            inline_threshold: 64 * 1024,
            chunk_bytes: 256 * 1024,
            write_timeout: Duration::from_secs(10),
            min_throughput_bytes_per_sec: 64 * 1024,
            deadline_floor: Duration::from_secs(30),
            deadline_cap: Duration::from_secs(3600),
            io_permits: 64,
            io_max_waiters: 128,
        }
    }
}

impl Limits {
    /// The whole-response budget for a body of `len` bytes.
    pub fn response_budget(&self, len: u64) -> Duration {
        let throughput = self.min_throughput_bytes_per_sec.max(1);
        let secs = len / throughput + 1;
        Duration::from_secs(secs).clamp(self.deadline_floor, self.deadline_cap)
    }
}

#[derive(Debug, Clone)]
pub struct StaticServerConfig {
    pub mounts: Vec<MountSpec>,
    pub limits: Limits,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_spec_parse_covers_options_and_fails_closed() {
        let spec = MountSpec::parse("/assets=/srv/app/shared/public/assets,cache-control=public%2Cmax-age=31536000%2Cimmutable")
            .expect("assets spec");
        assert_eq!(spec.prefix, "/assets");
        assert_eq!(
            spec.cache_control.as_deref(),
            Some("public,max-age=31536000,immutable")
        );
        assert_eq!(spec.on_miss, OnMiss::NotFound);
        assert_eq!(spec.symlink_policy, SymlinkPolicy::Deny);

        let spec = MountSpec::parse(
            "/=/srv/site,index,fallthrough,dotfiles,symlinks-within-root,no-sidecars",
        )
        .expect("root spec");
        assert!(spec.index && spec.allow_dotfiles && !spec.sidecars);
        assert_eq!(spec.on_miss, OnMiss::Fallthrough);
        assert_eq!(spec.symlink_policy, SymlinkPolicy::AllowWithinRoot);

        // Fail-closed: typos and malformed specs are errors, never silent defaults.
        assert!(MountSpec::parse("/assets").is_err());
        assert!(MountSpec::parse("/assets=").is_err());
        assert!(MountSpec::parse("/a=/b,fallthru").is_err());
    }

    #[test]
    fn response_budget_clamps_both_ends() {
        let limits = Limits::default();
        // Tiny body: floor.
        assert_eq!(limits.response_budget(1), Duration::from_secs(30));
        // 64 KiB/s over 1 GiB ~ 16384s -> capped at 3600.
        assert_eq!(
            limits.response_budget(1024 * 1024 * 1024),
            Duration::from_secs(3600)
        );
        // Mid-range scales with size: 64 MiB at 64 KiB/s = 1024s + 1.
        assert_eq!(
            limits.response_budget(64 * 1024 * 1024),
            Duration::from_secs(1025)
        );
    }
}

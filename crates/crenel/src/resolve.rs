//! Race-free filesystem resolution for classified candidates (Linux ≥ 5.6 only).
//!
//! Containment model: the docroot is pinned once at boot as an `O_PATH` dirfd on its
//! PHYSICAL location (`realpath` first — a Capistrano `current` symlink is followed at
//! pin time, ), and every request is a single
//! `openat2(dirfd, rel, RESOLVE_BENEATH [| RESOLVE_NO_SYMLINKS])`. The kernel enforces
//! that resolution never leaves the pinned tree — there is no check-then-open window,
//! which is strictly stronger than nginx `disable_symlinks` (its own docs concede the
//! race; miniserve CVE-2025-67124 is the same class).
//!
//! Open flags carry `O_NONBLOCK | O_NOCTTY`: opening a writer-less FIFO must
//! return immediately instead of parking a blocking-pool thread forever (nginx parity —
//! `ngx_open_and_stat_file` opens `O_NONBLOCK`), and a character device must not become
//! our controlling terminal before fstat rejects it. `O_NONBLOCK` is a no-op for regular
//! file reads.
//!
//! Deploy coupling: [`Root::check_repin`] compares the CONFIGURED path's
//! `(dev, ino)` against the pinned one and atomically re-pins (ArcSwap handoff — requests
//! holding the old dirfd finish on the old tree) bumping a `generation` that callers use
//! as a cache-flush key. Re-pin is caller-cadenced (per cache miss / reload signal), never
//! timer-based — a TTL would create the post-deploy 404 window nginx doesn't have.
//!
//! All metadata comes from `fstat` on the fd actually served — never from a path re-stat
//! (no old-fd/new-stat mixing, design D2.9).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustix::fs::{fstat, open, openat2, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use std::os::fd::OwnedFd;

/// Cap on entries visited by the boot audit walk; exceeding it fails closed with advice
/// rather than silently skipping coverage (design: no silent caps).
const AUDIT_ENTRY_LIMIT: usize = 500_000;

/// Bounded retries for openat2 `EAGAIN` (the kernel's rename/mount race detection during
/// scoped resolution) before shedding — deploys are rename-heavy, so this maps
/// to a retryable 503, not a 500.
const EAGAIN_RETRIES: u32 = 3;

/// Symlink policy INSIDE the pinned tree. `RESOLVE_BENEATH` containment applies in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// `RESOLVE_NO_SYMLINKS`: any symlink anywhere in resolution fails (default posture).
    /// The boot audit hard-errors on every symlink in the tree so the operator learns at
    /// deploy time, not from request-time 404s.
    Deny,
    /// `RESOLVE_BENEATH` only: symlinks that stay inside the pinned tree resolve; absolute
    /// targets and escapes still fail with `EXDEV`. The boot audit hard-errors only on
    /// links BENEATH would reject (absolute targets / escapes).
    AllowWithinRoot,
}

/// Why pinning (or re-pinning) a root failed. All fail closed at boot.
#[derive(Debug)]
pub enum RootError {
    /// Filesystem error touching the configured path.
    Io(io::Error),
    /// The configured path does not resolve to a directory.
    NotADirectory(PathBuf),
    /// `openat2` is unavailable (kernel < 5.6). Fail-closed: there is no fallback walk
    /// (a hand-rolled walk would reintroduce the TOCTOU class this crate exists to kill).
    Openat2Unsupported,
    /// The tree contains symlinks the configured policy would reject at request time.
    /// Listing them at boot with advice beats silently serving nothing ( — the
    /// Capistrano `linked_dirs` failure mode).
    HostileSymlinks { entries: Vec<String> },
    /// The audit walk exceeded [`AUDIT_ENTRY_LIMIT`]; split the mount or shrink the tree.
    AuditTooLarge { scanned: usize },
    /// The root filesystem appears to be case-insensitive (name aliasing breaks
    /// byte-comparison guarantees — baseline item 11, e.g. WSL `/mnt/c`).
    CaseInsensitiveRoot(PathBuf),
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootError::Io(e) => write!(f, "root pin io error: {e}"),
            RootError::NotADirectory(p) => write!(f, "static root is not a directory: {p:?}"),
            RootError::Openat2Unsupported => {
                write!(
                    f,
                    "openat2 unavailable (kernel < 5.6); crenel fails closed without it"
                )
            }
            RootError::HostileSymlinks { entries } => write!(
                f,
                "static root contains symlinks the symlink policy would reject at request \
                 time ({} shown): {}. Fix: mount the PHYSICAL target directory directly \
                 (e.g. Capistrano linked_dirs -> point the mount at shared/), remove the \
                 links, or relax the mount's symlink policy to allow-within-root.",
                entries.len(),
                entries.join(", ")
            ),
            RootError::AuditTooLarge { scanned } => write!(
                f,
                "boot symlink audit exceeded {scanned} entries; split the mount into \
                 smaller roots or reduce the tree"
            ),
            RootError::CaseInsensitiveRoot(p) => write!(
                f,
                "static root {p:?} appears case-insensitive; byte-exact path guarantees \
                 do not hold (move the docroot to a case-sensitive filesystem)"
            ),
        }
    }
}

impl std::error::Error for RootError {}

impl From<io::Error> for RootError {
    fn from(e: io::Error) -> Self {
        RootError::Io(e)
    }
}

impl From<Errno> for RootError {
    fn from(e: Errno) -> Self {
        RootError::Io(e.into())
    }
}

/// Why a candidate did not resolve to a servable file. Dispatched per the mount's miss
/// policy by the consumer; none of these carry paths (no reflection into error bodies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissKind {
    /// `ENOENT` — nothing there.
    NotFound,
    /// `ENOTDIR` — a non-directory sat where a directory component was needed.
    NotDir,
    /// `EACCES`/`EPERM` — permission denied. A miss, not a 500: status differentials
    /// between "absent" and "present but unreadable" leak tree layout (design D2.10).
    Access,
    /// `ELOOP` — a symlink was hit under [`SymlinkPolicy::Deny`] (or a symlink loop).
    SymlinkDenied,
    /// `EXDEV` — resolution tried to escape the pinned tree (absolute symlink target or
    /// a cross-mount walk). The containment working as designed.
    EscapesRoot,
    /// Opened, `fstat`ed, and found to be neither a regular file nor a directory
    /// (FIFO/device/socket — nginx serves FIFOs; we are deliberately stricter), or the
    /// open failed with `ENXIO` (socket / no device).
    NotRegular,
}

/// Result of resolving one candidate rel-path against a pinned root.
#[derive(Debug)]
pub enum Outcome {
    /// A regular file, opened and fstat'ed — serve from this fd only.
    File(ServedFile),
    /// Resolved to a directory; index/redirect semantics are the caller's.
    Directory,
    /// Not servable; see [`MissKind`].
    Miss(MissKind),
    /// `EAGAIN` persisted through retries (scoped-resolution race detection under heavy
    /// rename traffic): shed with a retryable 503, never a 500.
    Shed,
    /// Unexpected filesystem error: 500-class, counted by the consumer.
    Fault(io::Error),
}

/// An opened regular file plus the one fstat snapshot everything must derive from.
#[derive(Debug)]
pub struct ServedFile {
    /// Owned fd; read via `pread` so no seek state is shared.
    pub fd: OwnedFd,
    /// Size in bytes at fstat time.
    pub len: u64,
    /// Modification time seconds (validator input).
    pub mtime_sec: i64,
    /// Modification time nanoseconds (ns-mtime ETag, owner decision 2026-07-10).
    pub mtime_nsec: i64,
    /// Root generation this file was resolved under — cache keys must include it so a
    /// re-pin atomically invalidates.
    pub generation: u64,
}

struct Pinned {
    dirfd: OwnedFd,
    canonical: PathBuf,
    dev: u64,
    ino: u64,
    generation: u64,
}

/// A pinned docroot: the anchor every request resolves beneath.
pub struct Root {
    configured: PathBuf,
    policy: SymlinkPolicy,
    pinned: ArcSwap<Pinned>,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.pinned.load();
        f.debug_struct("Root")
            .field("configured", &self.configured)
            .field("canonical", &p.canonical)
            .field("generation", &p.generation)
            .field("policy", &self.policy)
            .finish()
    }
}

impl Root {
    /// Pin `configured` (symlinks in the configured path itself are followed — physical
    /// pinning, ), probe `openat2` support, audit the tree against `policy`, and
    /// heuristically refuse case-insensitive roots.
    pub fn pin(configured: &Path, policy: SymlinkPolicy) -> Result<Root, RootError> {
        let pinned = pin_once(configured, policy, 0)?;
        Ok(Root {
            configured: configured.to_path_buf(),
            policy,
            pinned: ArcSwap::from_pointee(pinned),
        })
    }

    /// The generation of the current pin (cache-flush key).
    pub fn generation(&self) -> u64 {
        self.pinned.load().generation
    }

    /// The canonical (physical) path currently pinned.
    pub fn canonical(&self) -> PathBuf {
        self.pinned.load().canonical.clone()
    }

    /// Deploy-coupled re-pin check: stat the CONFIGURED path (following symlinks) and,
    /// if its `(dev, ino)` no longer matches the pin, re-pin atomically (old dirfd stays
    /// alive for in-flight requests via the swapped-out Arc). Returns whether a re-pin
    /// happened. Callers decide cadence (per cache miss / explicit reload — never a TTL).
    pub fn check_repin(&self) -> Result<bool, RootError> {
        let current = rustix::fs::stat(&self.configured).map_err(RootError::from)?;
        let loaded = self.pinned.load();
        if (current.st_dev, current.st_ino) == (loaded.dev, loaded.ino) {
            return Ok(false);
        }
        let next = pin_once(&self.configured, self.policy, loaded.generation + 1)?;
        self.pinned.store(Arc::new(next));
        Ok(true)
    }

    /// Resolve a classified candidate rel-path (the [`crate::pipeline`] `Candidate`
    /// contract: relative, normalized, validated segments; empty = the root itself).
    pub fn open_rel(&self, rel: &str) -> Outcome {
        // Belt-and-braces re-validation of the pipeline contract. The pipeline is the
        // only legitimate producer of rel paths, but this boundary is exactly where the
        // RUSTSEC PathBuf-push class lived — verify, don't trust.
        if !rel_is_valid(rel) {
            return Outcome::Fault(Errno::INVAL.into());
        }
        let target: &str = if rel.is_empty() { "." } else { rel };
        let pinned = self.pinned.load();
        let resolve = match self.policy {
            SymlinkPolicy::Deny => ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            SymlinkPolicy::AllowWithinRoot => ResolveFlags::BENEATH,
        };
        // O_NONBLOCK: writer-less FIFO opens return instead of blocking a thread (F1).
        // O_NOCTTY: a char device cannot become our controlling terminal pre-fstat (F1).
        let oflags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY;

        let mut attempt = 0;
        let fd = loop {
            match openat2(&pinned.dirfd, target, oflags, Mode::empty(), resolve) {
                Ok(fd) => break fd,
                Err(Errno::AGAIN) => {
                    attempt += 1;
                    if attempt > EAGAIN_RETRIES {
                        return Outcome::Shed;
                    }
                }
                Err(Errno::NOENT) => return Outcome::Miss(MissKind::NotFound),
                Err(Errno::NOTDIR) => return Outcome::Miss(MissKind::NotDir),
                Err(Errno::ACCESS) | Err(Errno::PERM) => return Outcome::Miss(MissKind::Access),
                Err(Errno::LOOP) => return Outcome::Miss(MissKind::SymlinkDenied),
                Err(Errno::XDEV) => return Outcome::Miss(MissKind::EscapesRoot),
                Err(Errno::NXIO) => return Outcome::Miss(MissKind::NotRegular),
                Err(e) => return Outcome::Fault(e.into()),
            }
        };

        let stat = match fstat(&fd) {
            Ok(s) => s,
            Err(e) => return Outcome::Fault(e.into()),
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => Outcome::File(ServedFile {
                fd,
                len: stat.st_size as u64,
                mtime_sec: stat.st_mtime as i64,
                mtime_nsec: stat.st_mtime_nsec as i64,
                generation: pinned.generation,
            }),
            FileType::Directory => Outcome::Directory,
            // FIFO/device/socket: opened non-blocking, rejected post-fstat (stricter than
            // nginx, which will happily serve a FIFO).
            _ => Outcome::Miss(MissKind::NotRegular),
        }
    }
}

/// The identity file plus the sidecar actually selected, if any.
#[derive(Debug)]
pub struct EncodedOutcome {
    /// Resolution of the identity (uncompressed) path — authoritative for existence:
    /// a sidecar is NEVER served unless this is `Outcome::File` (Caddy rule,  —
    /// a stray `x.br` must not shadow a deleted `x`).
    pub identity: Outcome,
    /// First preference-order sidecar that resolved to a regular file. Validators and
    /// Content-Length must come from THIS snapshot.
    pub sidecar: Option<(crate::sidecar::Encoding, ServedFile)>,
}

impl Root {
    /// Resolve `rel` and, when it is a regular file, try its precompressed sidecars in
    /// the given preference order (from [`crate::sidecar::negotiate`]). Sidecar opens
    /// that miss for ANY reason are skipped silently — the identity file is always the
    /// safe answer; only the identity result carries error semantics.
    pub fn open_encoded(
        &self,
        rel: &str,
        preference: &[crate::sidecar::Encoding],
    ) -> EncodedOutcome {
        let identity = self.open_rel(rel);
        self.open_encoded_with_identity(rel, preference, identity)
    }

    /// The sidecar-probe half of [`open_encoded`](Self::open_encoded), for callers that
    /// already hold `rel`'s resolution (: the serve loop's directory dispatch
    /// resolves `rel` first and used to DISCARD that outcome, re-resolving the identical
    /// path here — one wasted `openat2` per request, hit and miss alike). Threading the
    /// outcome through is a pure de-duplication: no cache, no staleness semantics — the
    /// identity outcome is from THIS request's own resolution of THIS rel.
    ///
    /// Contract: `identity` MUST be the result of `open_rel(rel)` on this same `Root`
    /// generation; passing a stale or foreign outcome re-introduces exactly the
    /// double-resolution races this function exists to avoid.
    pub fn open_encoded_with_identity(
        &self,
        rel: &str,
        preference: &[crate::sidecar::Encoding],
        identity: Outcome,
    ) -> EncodedOutcome {
        let sidecar = match (&identity, rel.is_empty()) {
            (Outcome::File(_), false) => preference.iter().find_map(|&encoding| {
                let suffix = encoding.file_suffix()?;
                match self.open_rel(&format!("{rel}{suffix}")) {
                    Outcome::File(file) => Some((encoding, file)),
                    _ => None,
                }
            }),
            _ => None,
        };
        EncodedOutcome { identity, sidecar }
    }
}

/// The pipeline `Candidate::rel_path` contract, re-checked defensively.
fn rel_is_valid(rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    if rel.starts_with('/') || rel.contains('\0') {
        return false;
    }
    for segment in rel.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
    }
    // Structural audit mirroring the RUSTSEC-class kill: every component must be Normal.
    Path::new(rel)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
}

fn pin_once(
    configured: &Path,
    policy: SymlinkPolicy,
    generation: u64,
) -> Result<Pinned, RootError> {
    let canonical = fs::canonicalize(configured)?;
    let meta = fs::metadata(&canonical)?;
    if !meta.is_dir() {
        return Err(RootError::NotADirectory(canonical));
    }
    let dirfd = open(
        &canonical,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(RootError::from)?;

    // Fail-closed openat2 probe (kernel >= 5.6, design D2.8).
    match openat2(
        &dirfd,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH,
    ) {
        Ok(_) => {}
        Err(Errno::NOSYS) => return Err(RootError::Openat2Unsupported),
        Err(e) => return Err(RootError::from(e)),
    }

    let stat = rustix::fs::stat(&canonical).map_err(RootError::from)?;
    audit_tree(&canonical, policy)?;
    detect_case_insensitivity(&canonical)?;

    Ok(Pinned {
        dirfd,
        canonical,
        dev: stat.st_dev,
        ino: stat.st_ino,
        generation,
    })
}

/// Boot audit: find symlinks the request-time policy would reject and fail
/// loudly with advice, instead of silently 404ing every asset after deploy.
fn audit_tree(canonical_root: &Path, policy: SymlinkPolicy) -> Result<(), RootError> {
    let mut hostile: Vec<String> = Vec::new();
    let mut stack = vec![canonical_root.to_path_buf()];
    let mut scanned = 0usize;

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            // Unreadable subdir: request-time opens there will miss with EACCES; the
            // audit's job is symlink policy, not permissions — skip, don't fail boot.
            Err(_) => continue,
        };
        for entry in entries {
            let entry = entry?;
            scanned += 1;
            if scanned > AUDIT_ENTRY_LIMIT {
                return Err(RootError::AuditTooLarge { scanned });
            }
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                match policy {
                    // Under Deny every symlink is a request-time ELOOP.
                    SymlinkPolicy::Deny => push_hostile(&mut hostile, canonical_root, &path),
                    SymlinkPolicy::AllowWithinRoot => {
                        if symlink_escapes(canonical_root, &path) {
                            push_hostile(&mut hostile, canonical_root, &path);
                        }
                    }
                }
            } else if meta.is_dir() {
                stack.push(path);
            }
        }
    }

    if hostile.is_empty() {
        Ok(())
    } else {
        hostile.sort();
        hostile.truncate(20); // actionable, not exhaustive
        Err(RootError::HostileSymlinks { entries: hostile })
    }
}

fn push_hostile(hostile: &mut Vec<String>, root: &Path, path: &Path) {
    let shown = path.strip_prefix(root).unwrap_or(path);
    hostile.push(shown.to_string_lossy().into_owned());
}

/// Would RESOLVE_BENEATH reject this link? Absolute targets always; relative targets if
/// their physical resolution leaves the root. Dangling links are NOT hostile — at request
/// time they are a plain ENOENT miss.
fn symlink_escapes(canonical_root: &Path, link: &Path) -> bool {
    let Ok(target) = fs::read_link(link) else {
        return false;
    };
    if target.is_absolute() {
        return true;
    }
    let joined = match link.parent() {
        Some(parent) => parent.join(&target),
        None => return true,
    };
    match fs::canonicalize(&joined) {
        Ok(resolved) => !resolved.starts_with(canonical_root),
        Err(_) => false, // dangling -> request-time ENOENT
    }
}

/// Read-only case-insensitivity heuristic (baseline item 11: WSL /mnt/c, vfat): for the
/// first few top-level names containing letters, stat the case-swapped variant and compare
/// inodes. Inconclusive trees (no alphabetic names) pass — documented limitation.
fn detect_case_insensitivity(canonical_root: &Path) -> Result<(), RootError> {
    let entries = match fs::read_dir(canonical_root) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten().take(64) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().any(|b| b.is_ascii_alphabetic()) {
            continue;
        }
        let swapped: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        if swapped == name {
            continue;
        }
        let original = entry.path();
        let variant = canonical_root.join(&swapped);
        let (Ok(a), Ok(b)) = (
            fs::symlink_metadata(&original),
            fs::symlink_metadata(&variant),
        ) else {
            // Variant absent: case-sensitive as far as this name proves.
            return Ok(());
        };
        use std::os::unix::fs::MetadataExt;
        if a.dev() == b.dev() && a.ino() == b.ino() {
            return Err(RootError::CaseInsensitiveRoot(canonical_root.to_path_buf()));
        }
        return Ok(());
    }
    Ok(())
}

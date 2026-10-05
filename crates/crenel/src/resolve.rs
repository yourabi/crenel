//! Race-free filesystem resolution for classified candidates (Linux ≥ 5.6 and macOS).
//!
//! Containment model: the docroot is pinned once at boot as a directory fd on its
//! PHYSICAL location (`realpath` first follows a Capistrano `current` symlink at
//! pin time), and every request is a single kernel-scoped open beneath it:
//! `openat2(dirfd, rel, RESOLVE_BENEATH [| RESOLVE_NO_SYMLINKS])` on Linux,
//! `openat(dirfd, rel, O_RESOLVE_BENEATH [| O_NOFOLLOW_ANY])` on macOS. The kernel
//! enforces that resolution never leaves the pinned tree. Containment is checked during
//! resolution, without a separate path check before opening the file.
//!
//! macOS volumes are commonly case- and normalization-insensitive, so a hit there is
//! served only when the opened file's on-disk name (`F_GETPATH`) equals the requested
//! bytes; the engine's byte-exact guarantees hold on both platforms.
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
//! (no old-fd/new-stat mixing).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustix::fs::{fstat, open, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::os::fd::OwnedFd;

/// Cap on entries visited by the boot audit walk; exceeding it fails closed with advice
/// rather than silently skipping part of the tree.
const AUDIT_ENTRY_LIMIT: usize = 500_000;

/// Bounded retries for openat2 `EAGAIN` (the kernel's rename/mount race detection during
/// scoped resolution) before shedding — deploys are rename-heavy, so this maps
/// to a retryable 503, not a 500.
const EAGAIN_RETRIES: u32 = 3;

/// Symlink policy INSIDE the pinned tree. `RESOLVE_BENEATH` containment applies in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// `RESOLVE_NO_SYMLINKS` (macOS: `O_NOFOLLOW_ANY`): any symlink anywhere in
    /// resolution fails (default posture). The boot audit hard-errors on every symlink in
    /// the tree so the operator learns at deploy time, not from request-time 404s.
    Deny,
    /// `RESOLVE_BENEATH` only: symlinks that stay inside the pinned tree resolve; absolute
    /// targets and escapes still fail with `EXDEV` (macOS: `ENOTCAPABLE`). The boot audit
    /// hard-errors only on links BENEATH would reject (absolute targets / escapes).
    AllowWithinRoot,
}

/// Why pinning (or re-pinning) a root failed. All fail closed at boot.
#[derive(Debug)]
pub enum RootError {
    /// Filesystem error touching the configured path.
    Io(io::Error),
    /// The configured path does not resolve to a directory.
    NotADirectory(PathBuf),
    /// Kernel-scoped resolution is unavailable or not enforced (`openat2` on Linux
    /// < 5.6; `O_RESOLVE_BENEATH` on older macOS). Fail-closed: there is no fallback
    /// walk (a hand-rolled walk would reintroduce the TOCTOU class this crate exists
    /// to kill).
    ScopedResolutionUnsupported,
    /// The tree contains symlinks the configured policy would reject at request time.
    /// Reports them at boot with advice so configurations such as Capistrano
    /// `linked_dirs` do not silently produce request-time misses.
    HostileSymlinks { entries: Vec<String> },
    /// The boot audit exceeded its entry limit; split the mount or shrink the tree.
    AuditTooLarge { scanned: usize },
    /// The root filesystem appears to be case-insensitive (name aliasing breaks
    /// byte-comparison guarantees, for example on a case-insensitive WSL `/mnt/c`).
    CaseInsensitiveRoot(PathBuf),
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootError::Io(e) => write!(f, "root pin io error: {e}"),
            RootError::NotADirectory(p) => write!(f, "static root is not a directory: {p:?}"),
            RootError::ScopedResolutionUnsupported => {
                write!(
                    f,
                    "kernel-scoped path resolution unavailable (Linux needs openat2, kernel \
                     >= 5.6; macOS needs O_RESOLVE_BENEATH); crenel fails closed without it"
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
    /// between "absent" and "present but unreadable" leak tree layout.
    Access,
    /// `ELOOP` — a symlink was hit under [`SymlinkPolicy::Deny`] (or a symlink loop).
    SymlinkDenied,
    /// `EXDEV` (macOS: `ENOTCAPABLE`) — resolution tried to escape the pinned tree
    /// (absolute symlink target or a cross-mount walk). The containment working as
    /// designed.
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
    /// Modification time nanoseconds (validator input).
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
    /// The dirfd's on-disk path as the kernel reports it (`F_GETPATH`): the prefix every
    /// served name must match byte-for-byte.
    #[cfg(target_os = "macos")]
    physical: Vec<u8>,
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
    /// Follow symlinks in `configured` and pin its physical directory, probe that the
    /// kernel enforces scoped resolution, audit the tree against `policy`, and (Linux)
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
        if (dev_key(&current), current.st_ino) == (loaded.dev, loaded.ino) {
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
        // O_NONBLOCK: writer-less FIFO opens return instead of blocking a thread.
        // O_NOCTTY: a char device cannot become our controlling terminal before fstat.
        let oflags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY;

        let mut attempt = 0;
        let fd = loop {
            match open_beneath(&pinned.dirfd, target, oflags, self.policy) {
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
                Err(e) if escapes_root(e) => return Outcome::Miss(MissKind::EscapesRoot),
                Err(Errno::NXIO) => return Outcome::Miss(MissKind::NotRegular),
                Err(e) => return Outcome::Fault(e.into()),
            }
        };

        // Byte-exact names on case/normalization-folding volumes (see `name_is_exact`).
        #[cfg(target_os = "macos")]
        match name_is_exact(&pinned, &fd, target, rel, self.policy) {
            Ok(true) => {}
            Ok(false) => return Outcome::Miss(MissKind::NotFound),
            Err(e) => return Outcome::Fault(e.into()),
        }

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
    /// a sidecar is served only if this is `Outcome::File`. A stray `x.br` must not
    /// shadow a deleted `x`.
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

    /// The sidecar-probe half of [`open_encoded`](Self::open_encoded), for callers
    /// that already hold this request's resolution of `rel`. Reusing that outcome
    /// avoids a duplicate `openat2` call and keeps identity handling consistent.
    ///
    /// Contract: `identity` MUST be this request's result of `open_rel(rel)` on
    /// this same `Root` generation. Do not pass a stale outcome, an outcome from
    /// another root, or an outcome for a different relative path.
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
    // Every component must be Normal; reject alternate path forms at this boundary.
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
    let dirfd = pin_dirfd(&canonical).map_err(RootError::from)?;
    probe_scoped_resolution(&dirfd)?;

    let stat = rustix::fs::stat(&canonical).map_err(RootError::from)?;
    audit_tree(&canonical, policy)?;
    // macOS verifies every hit's on-disk name instead (see `name_is_exact`).
    #[cfg(target_os = "linux")]
    detect_case_insensitivity(&canonical)?;
    #[cfg(target_os = "macos")]
    let physical = rustix::fs::getpath(&dirfd)
        .map_err(RootError::from)?
        .into_bytes();

    Ok(Pinned {
        dirfd,
        canonical,
        dev: dev_key(&stat),
        ino: stat.st_ino,
        generation,
        #[cfg(target_os = "macos")]
        physical,
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

/// Read-only case-insensitivity heuristic (for example, WSL /mnt/c or vfat): for the
/// first few top-level names containing letters, stat the case-swapped variant and compare
/// inodes. Inconclusive trees (no alphabetic names) pass — documented limitation.
#[cfg(target_os = "linux")]
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

// ---- platform seam ---------------------------------------------------------------
//
// Everything above is shared. The three functions below are the only places the two
// kernels differ: how the root dirfd is pinned, how one scoped open is issued, and which
// errno means "resolution tried to leave the tree". macOS adds a fourth, the on-disk
// name check, because its default volumes fold case and Unicode normalization.

/// Pin the physical docroot as the anchor for every scoped open.
#[cfg(target_os = "linux")]
fn pin_dirfd(canonical: &Path) -> Result<OwnedFd, Errno> {
    open(
        canonical,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// macOS has no `O_PATH`; a read-only directory fd is the `openat` anchor.
#[cfg(target_os = "macos")]
fn pin_dirfd(canonical: &Path) -> Result<OwnedFd, Errno> {
    open(
        canonical,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// One scoped open beneath `dirfd`: the kernel refuses any resolution that would leave
/// the pinned tree, and under [`SymlinkPolicy::Deny`] any symlink at all.
#[cfg(target_os = "linux")]
fn open_beneath(
    dirfd: &OwnedFd,
    target: &str,
    oflags: OFlags,
    policy: SymlinkPolicy,
) -> Result<OwnedFd, Errno> {
    use rustix::fs::{openat2, ResolveFlags};
    let resolve = match policy {
        SymlinkPolicy::Deny => ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        SymlinkPolicy::AllowWithinRoot => ResolveFlags::BENEATH,
    };
    openat2(dirfd, target, oflags, Mode::empty(), resolve)
}

/// XNU `sys/fcntl.h`: `O_RESOLVE_BENEATH` makes `openat` refuse any resolution that would
/// leave the dirfd's directory (`..` climbs, absolute paths, escaping symlinks) with
/// `ENOTCAPABLE`; `O_NOFOLLOW_ANY` refuses any symlink in the path with `ELOOP`. rustix
/// does not expose the first for Apple targets, so both bits are named here;
/// [`probe_scoped_resolution`] proves at pin time that the running kernel honors the
/// containment flag, and the resolver tests prove the symlink taxonomy.
#[cfg(target_os = "macos")]
const O_RESOLVE_BENEATH: u32 = 0x0000_1000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_ANY: u32 = 0x2000_0000;

/// XNU `sys/errno.h`: the errno `O_RESOLVE_BENEATH` returns on an escape attempt.
#[cfg(target_os = "macos")]
const ENOTCAPABLE: Errno = Errno::from_raw_os_error(107);

#[cfg(target_os = "macos")]
fn open_beneath(
    dirfd: &OwnedFd,
    target: &str,
    oflags: OFlags,
    policy: SymlinkPolicy,
) -> Result<OwnedFd, Errno> {
    let mut flags = oflags | OFlags::from_bits_retain(O_RESOLVE_BENEATH);
    if policy == SymlinkPolicy::Deny {
        // A symlink anywhere in the path fails with ELOOP, the same taxonomy as
        // Linux `RESOLVE_NO_SYMLINKS`.
        flags |= OFlags::from_bits_retain(O_NOFOLLOW_ANY);
    }
    rustix::fs::openat(dirfd, target, flags, Mode::empty())
}

/// Device identity for the deploy-flip check; `st_dev` is `u64` on Linux and `i32` on
/// macOS.
#[cfg(target_os = "linux")]
fn dev_key(stat: &rustix::fs::Stat) -> u64 {
    stat.st_dev
}

#[cfg(target_os = "macos")]
fn dev_key(stat: &rustix::fs::Stat) -> u64 {
    stat.st_dev as u64
}

/// Did a scoped open fail because resolution tried to leave the pinned tree?
fn escapes_root(e: Errno) -> bool {
    #[cfg(target_os = "macos")]
    if e == ENOTCAPABLE {
        return true;
    }
    e == Errno::XDEV
}

/// Fail-closed probe that this kernel really scopes resolution. Linux reports a missing
/// `openat2` as `ENOSYS`; macOS must additionally prove the flag is enforced rather than
/// ignored, so `..` from the pinned directory is required to fail as an escape.
fn probe_scoped_resolution(dirfd: &OwnedFd) -> Result<(), RootError> {
    let dir = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY;
    match open_beneath(dirfd, ".", dir, SymlinkPolicy::AllowWithinRoot) {
        Ok(_) => {}
        Err(Errno::NOSYS) => return Err(RootError::ScopedResolutionUnsupported),
        Err(e) => return Err(RootError::from(e)),
    }
    #[cfg(target_os = "macos")]
    match open_beneath(dirfd, "..", dir, SymlinkPolicy::AllowWithinRoot) {
        Err(e) if escapes_root(e) => {}
        Ok(_) => return Err(RootError::ScopedResolutionUnsupported),
        Err(e) => return Err(RootError::from(e)),
    }
    Ok(())
}

/// Serve a hit only if what the kernel opened is named exactly as requested.
///
/// APFS's default volumes fold case and Unicode normalization, so `Assets/App.JS` opens
/// `assets/app.js`. The pipeline's guarantees are byte-exact (Linux refuses such roots
/// outright), so the opened vnode's stored path (`F_GETPATH`, one fcntl per hit) must
/// equal the pinned prefix plus the requested bytes.
///
/// Under [`SymlinkPolicy::AllowWithinRoot`] a symlink alias legitimately reports its
/// target's path. A second open with symlinks forbidden tells the cases apart: `ELOOP`
/// proves a link was involved (containment was already kernel-enforced, and the link's
/// own name is the operator's choice), anything else means a real name alias. A case
/// alias of a symlink's own name is therefore not caught under that opt-in policy.
#[cfg(target_os = "macos")]
fn name_is_exact(
    pinned: &Pinned,
    fd: &OwnedFd,
    target: &str,
    rel: &str,
    policy: SymlinkPolicy,
) -> Result<bool, Errno> {
    let actual = rustix::fs::getpath(fd)?;
    let actual = actual.as_bytes();
    let root = pinned.physical.as_slice();
    let exact = if rel.is_empty() {
        actual == root
    } else {
        actual.len() == root.len() + 1 + rel.len()
            && actual.starts_with(root)
            && actual[root.len()] == b'/'
            && &actual[root.len() + 1..] == rel.as_bytes()
    };
    if exact || policy == SymlinkPolicy::Deny {
        return Ok(exact);
    }
    let probe = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY;
    Ok(matches!(
        open_beneath(&pinned.dirfd, target, probe, SymlinkPolicy::Deny),
        Err(Errno::LOOP)
    ))
}

//! Request-target classification: ONE decode-once pipeline.
//!
//! The consumer (an HTTP server) hands the raw request target here and never re-derives
//! static-eligibility from raw bytes itself — a router matching raw bytes while the engine
//! matches decoded bytes is two parsers, which is the CVE-2013-4547 / decode-order-differential
//! bug class.
//!
//! Pipeline order (each step exactly once):
//! 1. method gate (GET/HEAD) → origin-form gate (leading `/`)
//! 2. strip query at the RAW first `?` — an encoded `%3F` therefore stays a filename byte
//! 3. percent-decode exactly once; never again downstream
//! 4. byte screens: NUL, C0/DEL controls, UTF-8
//! 5. capture the trailing-slash flag BEFORE segmentation (segmentation erases it and
//!    directory/index logic needs it — )
//! 6. segment: merge duplicate slashes, drop interior `.` (nginx parity, test-pinned),
//!    reject any `..`
//! 7. boundary-aware longest-prefix mount match on SEGMENTS (an off-by-slash like
//!    `/assets../x` can never match `/assets` because segments, not string prefixes, compare)
//! 8. per-mount dotfile policy → `Miss` (not reject: `/.well-known` is legitimate app
//!    namespace under a fallthrough mount —  verdict)
//!
//! Structural hostility (bad escape, NUL, control bytes, non-UTF-8, `..`) is a fixed-400
//! [`Classification::Reject`] regardless of whether any mount matched: mount-independent
//! rejection removes the 400-vs-fallthrough status differential that would otherwise let an
//! attacker enumerate the mount map. Several screens are deliberately stricter
//! than nginx and belong in the golden-fixture divergence ledger: global `..` rejection
//! (nginx textually resolves interior dot-dot), decoded-control rejection, and UTF-8-only
//! paths (baseline: treat aliasing-prone byte paths as hostile; Rails assets are UTF-8).
//!
//! The RUSTSEC `PathBuf::push`-replacement traversal class (RUSTSEC-2021-0135, 2022-0043,
//! 2022-0069, 2022-0082) is killed structurally: client input is never pushed into a
//! `PathBuf`; the resolver receives a joined string of individually validated plain segments.

use std::fmt;

/// Not static-eligible — the request flows to the application exactly as it would today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotStaticReason {
    /// Only GET and HEAD are static-eligible; everything else is app traffic by definition.
    MethodNotGetOrHead,
    /// Target is not origin-form (no leading `/`): H1 absolute-form, `OPTIONS *`, CONNECT.
    /// Explicitly classified rather than left ambiguous; the app's existing
    /// validation owns these shapes.
    NonOriginForm,
    /// No configured mount prefix matched the normalized path.
    NoMountMatched,
}

/// Structurally hostile target: the server MUST answer a fixed 400 and MUST NOT fall
/// through to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralReject {
    /// `%` not followed by two hex digits.
    InvalidEscape,
    /// Decoded NUL (`%00`) — the classic suffix-truncation bypass primitive
    /// (CVE-2009-2629-era hardening; baseline checklist item 2).
    NulByte,
    /// Any other decoded C0 control or DEL. Stricter than nginx (ledger entry); kills
    /// CRLF-into-`Location` header injection at the source.
    ControlByte,
    /// Decoded path is not valid UTF-8. Stricter than nginx (ledger entry); byte-alias
    /// path handling is the lesson of the Windows path CVE family (baseline item 11).
    NotUtf8,
    /// A `..` component survived decoding (arrived literally or as `%2e%2e`/`..%2f`
    /// variants). Rejected globally, mount-independent — stricter than nginx, which
    /// textually resolves interior dot-dot (ledger entry).
    DotDotComponent,
}

/// A policy miss under a matched mount; dispatched per that mount's miss policy
/// (fall through to the app, or strict 404 — the consumer's choice, design D6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMiss {
    /// A dot-segment below a mount that denies dotfiles (the default). A miss, NOT a
    /// reject: under a fallthrough mount, paths like `/.well-known/...` remain
    /// legitimate application namespace.
    DotfileDenied,
}

/// The classification of one request target against a mount table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    NotStatic(NotStaticReason),
    Reject(StructuralReject),
    Miss { mount: usize, reason: PolicyMiss },
    Candidate(Candidate),
}

/// A static-eligible request, fully normalized and safe to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Index into the [`Mounts`] table used for classification.
    pub mount: usize,
    /// Path relative to the mount's docroot: decoded, normalized, no leading `/`, and
    /// possibly empty (the mount root itself). Every segment is a plain non-empty name
    /// containing no `/`, NUL, or control bytes, and is neither `.` nor `..`.
    pub rel_path: String,
    /// Whether the once-decoded path ended with `/` (captured before segmentation,
    /// which erases it — ). Drives directory-index/redirect semantics.
    pub trailing_slash: bool,
}

/// Errors constructing a [`Mount`] or [`Mounts`] table. All fail-closed at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountError {
    /// Mount prefix must start with `/`.
    NotAbsolute(String),
    /// Mount prefix contains a `.`/`..` segment or a forbidden byte
    /// (`%`, `?`, `#`, NUL, C0 control, DEL). Prefixes are operator literals; percent
    /// escapes in config would reintroduce a second decode site.
    HostileSegment(String),
    /// Two mounts normalize to the same prefix.
    Duplicate(String),
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::NotAbsolute(p) => write!(f, "mount prefix must start with '/': {p:?}"),
            MountError::HostileSegment(p) => write!(
                f,
                "mount prefix contains a forbidden segment or byte (., .., %, ?, #, control): {p:?}"
            ),
            MountError::Duplicate(p) => {
                write!(f, "duplicate mount prefix after normalization: {p:?}")
            }
        }
    }
}

impl std::error::Error for MountError {}

/// One URL-prefix → docroot mapping (the docroot itself lives with the resolver).
#[derive(Debug, Clone)]
pub struct Mount {
    prefix: String,
    prefix_segments: Vec<String>,
    allow_dotfiles: bool,
}

impl Mount {
    /// Validate and normalize a mount prefix (`"/"` or `"/assets"` or `"/a/b"`;
    /// trailing slashes and duplicate slashes are normalized away).
    pub fn new(prefix: &str, allow_dotfiles: bool) -> Result<Mount, MountError> {
        if !prefix.starts_with('/') {
            return Err(MountError::NotAbsolute(prefix.to_string()));
        }
        let mut segments = Vec::new();
        for segment in prefix.split('/') {
            match segment {
                "" => continue,
                "." | ".." => return Err(MountError::HostileSegment(prefix.to_string())),
                s => {
                    let forbidden = s
                        .bytes()
                        .any(|b| b < 0x20 || b == 0x7f || b == b'%' || b == b'?' || b == b'#');
                    if forbidden {
                        return Err(MountError::HostileSegment(prefix.to_string()));
                    }
                    segments.push(s.to_string());
                }
            }
        }
        let normalized = if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        };
        Ok(Mount {
            prefix: normalized,
            prefix_segments: segments,
            allow_dotfiles,
        })
    }

    /// The normalized prefix (`"/"` for the root mount).
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Whether dot-segments below this mount are served (default posture is deny).
    pub fn allow_dotfiles(&self) -> bool {
        self.allow_dotfiles
    }
}

/// A validated mount table. Matching is boundary-aware longest-prefix on segments.
#[derive(Debug, Clone)]
pub struct Mounts {
    mounts: Vec<Mount>,
}

impl Mounts {
    /// Build a table, rejecting duplicate normalized prefixes. Nested mounts are fine
    /// (`"/"` plus `"/assets"`); the longest segment-prefix wins at classify time.
    pub fn new(mounts: Vec<Mount>) -> Result<Mounts, MountError> {
        for (i, a) in mounts.iter().enumerate() {
            if mounts[..i].iter().any(|b| b.prefix == a.prefix) {
                return Err(MountError::Duplicate(a.prefix.clone()));
            }
        }
        Ok(Mounts { mounts })
    }

    /// The mount at `index` (as reported in [`Classification`]).
    pub fn get(&self, index: usize) -> &Mount {
        &self.mounts[index]
    }

    /// Number of mounts.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// Whether the table is empty (classification then never yields a candidate).
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

/// Classify one request target. `method` is the raw HTTP method token (case-sensitive per
/// RFC 9110 — `get` is NOT `GET`); `raw_target` is the request-target exactly as received
/// (H1 request line target or H2 `:path`), query string still attached.
pub fn classify(method: &str, raw_target: &str, mounts: &Mounts) -> Classification {
    if method != "GET" && method != "HEAD" {
        return Classification::NotStatic(NotStaticReason::MethodNotGetOrHead);
    }
    if !raw_target.starts_with('/') {
        return Classification::NotStatic(NotStaticReason::NonOriginForm);
    }
    // Query strips at the RAW '?', before decoding — %3F therefore decodes into a plain
    // filename byte and can never shift the query boundary.
    let raw_path = match raw_target.find('?') {
        Some(idx) => &raw_target[..idx],
        None => raw_target,
    };

    let decoded = match decode_once(raw_path.as_bytes()) {
        Ok(bytes) => bytes,
        Err(reject) => return Classification::Reject(reject),
    };
    if decoded.contains(&0) {
        return Classification::Reject(StructuralReject::NulByte);
    }
    if decoded.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return Classification::Reject(StructuralReject::ControlByte);
    }
    let decoded = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => return Classification::Reject(StructuralReject::NotUtf8),
    };

    // Captured before segmentation erases it.
    let trailing_slash = decoded.ends_with('/');

    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            // Duplicate-slash merge and interior-'.' drop: deliberate nginx-parity
            // normalization, pinned by tests rather than happening silently.
            "" | "." => continue,
            ".." => return Classification::Reject(StructuralReject::DotDotComponent),
            s => segments.push(s),
        }
    }

    // Longest segment-prefix mount match. Comparing SEGMENTS is what makes matching
    // boundary-aware: "/assets../x" segments to ["assets..", "x"], which no ["assets"]
    // prefix can match (alias off-by-slash class, baseline item 8).
    let mut best: Option<(usize, usize)> = None;
    for (index, mount) in mounts.mounts.iter().enumerate() {
        let prefix = &mount.prefix_segments;
        let matches =
            prefix.len() <= segments.len() && prefix.iter().zip(&segments).all(|(m, s)| m == s);
        if matches && best.is_none_or(|(_, len)| prefix.len() > len) {
            best = Some((index, prefix.len()));
        }
    }
    let Some((mount_index, prefix_len)) = best else {
        return Classification::NotStatic(NotStaticReason::NoMountMatched);
    };

    let rel_segments = &segments[prefix_len..];
    if !mounts.mounts[mount_index].allow_dotfiles && rel_segments.iter().any(|s| s.starts_with('.'))
    {
        return Classification::Miss {
            mount: mount_index,
            reason: PolicyMiss::DotfileDenied,
        };
    }

    Classification::Candidate(Candidate {
        mount: mount_index,
        rel_path: rel_segments.join("/"),
        trailing_slash,
    })
}

/// Percent-decode exactly once. Strict: a `%` not followed by two hex digits is hostile
/// (nginx parity), not passthrough — lenient decoders are how double-decode bugs start.
fn decode_once(input: &[u8]) -> Result<Vec<u8>, StructuralReject> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        if byte == b'%' {
            let hi = input.get(i + 1).copied().and_then(hex_value);
            let lo = input.get(i + 2).copied().and_then(hex_value);
            match (hi, lo) {
                (Some(hi), Some(lo)) => {
                    out.push(hi * 16 + lo);
                    i += 3;
                }
                _ => return Err(StructuralReject::InvalidEscape),
            }
        } else {
            out.push(byte);
            i += 1;
        }
    }
    Ok(out)
}

/// Fuzz-only export of the private decoder (`cargo fuzz` builds with `--cfg fuzzing`).
/// Not part of the public API.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn decode_once_for_fuzzing(input: &[u8]) -> Result<Vec<u8>, StructuralReject> {
    decode_once(input)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_once_handles_boundaries() {
        assert_eq!(decode_once(b"abc").unwrap(), b"abc");
        assert_eq!(decode_once(b"%41").unwrap(), b"A");
        assert_eq!(decode_once(b"%4a%4A").unwrap(), b"JJ");
        assert_eq!(decode_once(b"a%"), Err(StructuralReject::InvalidEscape));
        assert_eq!(decode_once(b"a%4"), Err(StructuralReject::InvalidEscape));
        assert_eq!(decode_once(b"a%zz"), Err(StructuralReject::InvalidEscape));
        // Decode happens exactly once: %2541 yields the three bytes "%41", not "A".
        assert_eq!(decode_once(b"%2541").unwrap(), b"%41");
    }

    #[test]
    fn mount_prefix_normalization() {
        assert_eq!(Mount::new("/", false).unwrap().prefix(), "/");
        assert_eq!(Mount::new("/assets/", false).unwrap().prefix(), "/assets");
        assert_eq!(Mount::new("//a//b/", false).unwrap().prefix(), "/a/b");
        assert!(matches!(
            Mount::new("assets", false),
            Err(MountError::NotAbsolute(_))
        ));
        assert!(matches!(
            Mount::new("/a/../b", false),
            Err(MountError::HostileSegment(_))
        ));
        assert!(matches!(
            Mount::new("/a%2f", false),
            Err(MountError::HostileSegment(_))
        ));
        assert!(matches!(
            Mount::new("/a?b", false),
            Err(MountError::HostileSegment(_))
        ));
    }

    #[test]
    fn duplicate_mounts_rejected() {
        let a = Mount::new("/assets", false).unwrap();
        let b = Mount::new("/assets/", true).unwrap();
        assert!(matches!(
            Mounts::new(vec![a, b]),
            Err(MountError::Duplicate(_))
        ));
    }
}

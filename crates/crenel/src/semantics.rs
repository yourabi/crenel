//! Response planning: turn (request facts, served-file facts, mount policy) into a complete
//! HTTP response plan — status, headers, and a body range — with RFC 9110 §13.2.2
//! conditional evaluation and hardened single-range handling.
//!
//! Pure computation over fstat-snapshot numbers: no fd, no IO — fully testable on any
//! platform. The consumer resolves the file (and sidecar) first, then calls
//! [`plan_response`]; the adapter executes the returned [`BodyPlan`] against the fd.
//!
//! Range hardening (CVE-2017-7529 class): all arithmetic is checked `u64`; a multi-range
//! or malformed `Range` header is IGNORED (200 full body — precedented by
//! `static-files-module`, and it structurally removes multipart-amplification,
//! CVE-2011-3192 class); only start > end-of-representation yields 416.

use crate::headers;
use crate::sidecar::Encoding;

/// The conditional/range request headers, pre-extracted by the consumer. The engine never
/// sees raw header blocks — extraction is the HTTP library's job, evaluation is ours.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestFacts<'a> {
    /// HEAD instead of GET: identical status/headers, `BodyPlan::None`.
    pub head: bool,
    pub if_match: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub if_modified_since: Option<&'a str>,
    pub if_unmodified_since: Option<&'a str>,
    pub if_range: Option<&'a str>,
    pub range: Option<&'a str>,
}

/// The chosen representation's fstat snapshot (from the SIDECAR fd when one was selected —
/// validators and lengths always describe the bytes actually sent).
#[derive(Debug, Clone, Copy)]
pub struct FileFacts {
    pub len: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    /// Encoding of these bytes (`Identity` when no sidecar was selected).
    pub encoding: Encoding,
    /// Whether sidecar negotiation applies to this path's mount at all. Drives
    /// `Vary: Accept-Encoding` on EVERY response — identity and 304 included.
    pub vary_applies: bool,
    /// From [`headers::content_type_for`] on the ORIGINAL rel path (a `.js.br` sidecar is
    /// still `text/javascript`).
    pub content_type: &'static str,
}

/// Per-mount response policy knobs relevant to header synthesis.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResponsePolicy<'a> {
    /// Emitted verbatim as `Cache-Control` when present (e.g. the Rails-preset
    /// `public, max-age=31536000, immutable` for fingerprinted assets).
    pub cache_control: Option<&'a str>,
}

/// How the adapter must produce the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPlan {
    /// No body bytes (HEAD, 304, 412, 416).
    None,
    /// The whole representation (`len` bytes from offset 0).
    Whole,
    /// One contiguous byte range of the representation.
    Range { offset: u64, len: u64 },
}

/// A fully planned response. `headers` is emission-ready (values synthesized and safe);
/// `Content-Length` is included for every plan that has a defined representation length —
/// including HEAD, whose `BodyPlan::None` still advertises the would-be length.
#[derive(Debug)]
pub struct ResponsePlan {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: BodyPlan,
}

/// Plan the response for a resolved, opened file. Evaluation order is RFC 9110 §13.2.2:
/// If-Match → If-Unmodified-Since → If-None-Match → If-Modified-Since → (Range +) If-Range.
pub fn plan_response(
    req: &RequestFacts<'_>,
    file: &FileFacts,
    policy: &ResponsePolicy<'_>,
) -> ResponsePlan {
    let etag = headers::etag(file.mtime_sec, file.mtime_nsec, file.len, file.encoding);
    let last_modified_time = headers::system_time_for(file.mtime_sec);

    // §13.2.2 step 1: If-Match, strong comparison ("*" = any current representation).
    if let Some(condition) = req.if_match {
        if !etag_list_matches(condition, &etag, true) {
            return precondition_failed(file);
        }
    } else if let Some(condition) = req.if_unmodified_since {
        // Step 2 (only when If-Match is absent): 412 if modified since the given date.
        // A malformed date fails to constrain (condition passes) — RFC 9110 §13.1.4.
        if let Some(date) = headers::parse_http_date(condition) {
            if last_modified_time > date {
                return precondition_failed(file);
            }
        }
    }

    // Step 3: If-None-Match, weak comparison; on match GET/HEAD answer 304.
    if let Some(condition) = req.if_none_match {
        if etag_list_matches(condition, &etag, false) {
            return not_modified(file, &etag);
        }
    } else if let Some(condition) = req.if_modified_since {
        // Step 4 (only when If-None-Match is absent): EXACT date match → 304. nginx's
        // default (`if_modified_since exact`) — a client date NEWER than ours must NOT
        // suppress a rollback's changed content.
        if let Some(date) = headers::parse_http_date(condition) {
            if date == last_modified_time {
                return not_modified(file, &etag);
            }
        }
    }

    // Step 5: Range, gated by If-Range. An If-Range that doesn't match (weak ETags never
    // strong-match; dates compare exactly) downgrades to the full representation.
    let mut range_header = req.range;
    if range_header.is_some() {
        if let Some(condition) = req.if_range {
            let matches = if condition.starts_with('"') || condition.starts_with("W/") {
                strong_compare(condition.trim(), &etag)
            } else {
                headers::parse_http_date(condition) == Some(last_modified_time)
            };
            if !matches {
                range_header = None;
            }
        }
    }

    match range_header.map(|h| parse_range(h, file.len)) {
        Some(RangeOutcome::Satisfiable { offset, len }) => {
            let mut plan_headers = common_success_headers(file, &etag, policy);
            plan_headers.push(("content-length", len.to_string()));
            plan_headers.push((
                "content-range",
                format!("bytes {}-{}/{}", offset, offset + (len - 1), file.len),
            ));
            ResponsePlan {
                status: 206,
                headers: plan_headers,
                body: if req.head {
                    BodyPlan::None
                } else {
                    BodyPlan::Range { offset, len }
                },
            }
        }
        Some(RangeOutcome::Unsatisfiable) => {
            let mut plan_headers = base_headers(file);
            plan_headers.push(("content-range", format!("bytes */{}", file.len)));
            ResponsePlan {
                status: 416,
                headers: plan_headers,
                body: BodyPlan::None,
            }
        }
        // No Range header, ignored-invalid, or If-Range downgrade: full representation.
        Some(RangeOutcome::Ignored) | None => {
            let mut plan_headers = common_success_headers(file, &etag, policy);
            plan_headers.push(("content-length", file.len.to_string()));
            ResponsePlan {
                status: 200,
                headers: plan_headers,
                body: if req.head {
                    BodyPlan::None
                } else {
                    BodyPlan::Whole
                },
            }
        }
    }
}

fn precondition_failed(file: &FileFacts) -> ResponsePlan {
    ResponsePlan {
        status: 412,
        headers: base_headers(file),
        body: BodyPlan::None,
    }
}

/// 304 carries the headers a 200 would have carried that direct cache updates
/// (RFC 9110 §15.4.5): validators, Cache-Control is the consumer's 200-set minus
/// representation metadata; Vary included.
fn not_modified(file: &FileFacts, etag: &str) -> ResponsePlan {
    let mut plan_headers = base_headers(file);
    plan_headers.push(("etag", etag.to_string()));
    plan_headers.push(("last-modified", headers::last_modified(file.mtime_sec)));
    ResponsePlan {
        status: 304,
        headers: plan_headers,
        body: BodyPlan::None,
    }
}

/// Headers on EVERY plan: nosniff always (baseline item 21), Vary whenever sidecar
/// negotiation applies to the mount.
fn base_headers(file: &FileFacts) -> Vec<(&'static str, String)> {
    let mut plan_headers: Vec<(&'static str, String)> =
        vec![("x-content-type-options", "nosniff".to_string())];
    if file.vary_applies {
        plan_headers.push(("vary", "Accept-Encoding".to_string()));
    }
    plan_headers
}

fn common_success_headers(
    file: &FileFacts,
    etag: &str,
    policy: &ResponsePolicy<'_>,
) -> Vec<(&'static str, String)> {
    let mut plan_headers = base_headers(file);
    plan_headers.push(("content-type", file.content_type.to_string()));
    plan_headers.push(("etag", etag.to_string()));
    plan_headers.push(("last-modified", headers::last_modified(file.mtime_sec)));
    plan_headers.push(("accept-ranges", "bytes".to_string()));
    if let Some(encoding) = file.encoding.content_encoding() {
        plan_headers.push(("content-encoding", encoding.to_string()));
    }
    if let Some(cache_control) = policy.cache_control {
        plan_headers.push(("cache-control", cache_control.to_string()));
    }
    plan_headers
}

/// Strong comparison (RFC 9110 §8.8.3.2): equal opaque values, neither weak. Our ETags are
/// always strong, so any `W/` on the client side fails.
fn strong_compare(candidate: &str, ours: &str) -> bool {
    !candidate.starts_with("W/") && candidate == ours
}

/// Weak comparison: strip `W/` from both sides, compare opaque values.
fn weak_compare(candidate: &str, ours: &str) -> bool {
    candidate.strip_prefix("W/").unwrap_or(candidate) == ours.strip_prefix("W/").unwrap_or(ours)
}

/// Evaluate a comma-separated entity-tag list (`If-Match` / `If-None-Match`) against ours.
fn etag_list_matches(header: &str, ours: &str, strong: bool) -> bool {
    let header = header.trim();
    if header == "*" {
        // "*" matches any CURRENT representation — and one exists (we opened it).
        return true;
    }
    // Opaque tags cannot contain ',' (RFC 9110 etagc excludes it), so a comma split is
    // faithful tokenization.
    header.split(',').map(str::trim).any(|candidate| {
        if strong {
            strong_compare(candidate, ours)
        } else {
            weak_compare(candidate, ours)
        }
    })
}

/// What to do when a candidate resolved to a DIRECTORY (design D3; uses the pipeline's
/// trailing-slash flag, which segmentation would otherwise erase — ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryAction {
    /// Re-resolve `<rel>/index.html` and serve it.
    ServeIndex,
    /// 301 to the slash-terminated form (Location via [`headers::redirect_location`] —
    /// ; nginx-parity status).
    RedirectAddSlash,
    /// No index configured: a plain miss under the mount's miss policy.
    Miss,
}

/// Directory dispatch: index only behind a trailing slash; redirect only when an index
/// would then be served (no probe-y redirects onto nothing).
pub fn directory_action(trailing_slash: bool, index_enabled: bool) -> DirectoryAction {
    match (index_enabled, trailing_slash) {
        (false, _) => DirectoryAction::Miss,
        (true, true) => DirectoryAction::ServeIndex,
        (true, false) => DirectoryAction::RedirectAddSlash,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeOutcome {
    /// Header malformed / multi-range / non-bytes unit: ignore, serve 200 full
    /// (RFC 9110 §14.2 MAY-ignore; design D3 single-range hardening).
    Ignored,
    Satisfiable {
        offset: u64,
        len: u64,
    },
    /// The one 416 case: a syntactically valid single spec that selects nothing.
    Unsatisfiable,
}

/// Parse `Range: bytes=<spec>` with exactly one spec. Saturating arithmetic throughout —
/// a 20-digit attack value clamps to `u64::MAX` and lands in the unsatisfiable branch
/// instead of wrapping into a small offset (CVE-2017-7529 class kill; golden-verified
/// against nginx 1.28: overflow and inverted specs are 416, not ignored).
fn parse_range(header: &str, len: u64) -> RangeOutcome {
    if len == 0 {
        // nginx parity (golden-verified): the range filter is bypassed entirely for
        // empty representations — plain 200 with an empty body.
        return RangeOutcome::Ignored;
    }
    let header = header.trim();
    let Some(specs) = header
        .strip_prefix("bytes=")
        .or_else(|| header.strip_prefix("Bytes="))
    else {
        return RangeOutcome::Ignored; // other-units or garbage: not ours to satisfy
    };
    if specs.contains(',') {
        return RangeOutcome::Ignored; // multi-range: whole body by design (ledger D3)
    }
    let spec = specs.trim();
    let Some((start_str, end_str)) = spec.split_once('-') else {
        return RangeOutcome::Ignored;
    };
    let (start_str, end_str) = (start_str.trim(), end_str.trim());

    if start_str.is_empty() {
        // suffix-length form "-N": the final N bytes.
        let Some(suffix_len) = parse_u64_saturating(end_str) else {
            return RangeOutcome::Ignored;
        };
        if suffix_len == 0 {
            // "-0" selects nothing (RFC 9110 §14.1.2); nginx answers 416.
            return RangeOutcome::Unsatisfiable;
        }
        let effective = suffix_len.min(len);
        return RangeOutcome::Satisfiable {
            offset: len - effective,
            len: effective,
        };
    }

    let Some(start) = parse_u64_saturating(start_str) else {
        return RangeOutcome::Ignored;
    };
    if start >= len {
        // Includes saturated overflow values (nginx parity: 416).
        return RangeOutcome::Unsatisfiable;
    }
    let end = if end_str.is_empty() {
        len - 1 // "N-": to the end
    } else {
        match parse_u64_saturating(end_str) {
            // last-byte-pos beyond EOF clamps to EOF (RFC 9110 §14.1.2).
            Some(end) => end.min(len - 1),
            None => return RangeOutcome::Ignored,
        }
    };
    if start > end {
        // Inverted spec selects nothing: 416 (nginx parity, golden-verified).
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Satisfiable {
        offset: start,
        len: end - start + 1,
    }
}

/// Strict ASCII-digit u64 parse — no signs, no whitespace; `None` on any non-digit;
/// overflow saturates to `u64::MAX` (reads as "absurdly large", never wraps).
fn parse_u64_saturating(digits: &str) -> Option<u64> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: u64 = 0;
    for b in digits.bytes() {
        value = value.saturating_mul(10).saturating_add(u64::from(b - b'0'));
    }
    Some(value)
}

/// Fuzz-only exports (`cargo fuzz` builds with `--cfg fuzzing`). Not public API.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn parse_range_for_fuzzing(header: &str, len: u64) -> (bool, Option<(u64, u64)>) {
    match parse_range(header, len) {
        RangeOutcome::Ignored => (false, None),
        RangeOutcome::Unsatisfiable => (true, None),
        RangeOutcome::Satisfiable { offset, len } => (true, Some((offset, len))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parser_edges() {
        assert_eq!(
            parse_range("bytes=0-499", 1000),
            RangeOutcome::Satisfiable {
                offset: 0,
                len: 500
            }
        );
        assert_eq!(
            parse_range("bytes=500-", 1000),
            RangeOutcome::Satisfiable {
                offset: 500,
                len: 500
            }
        );
        assert_eq!(
            parse_range("bytes=-300", 1000),
            RangeOutcome::Satisfiable {
                offset: 700,
                len: 300
            }
        );
        // Suffix longer than the file: whole file (RFC 9110 §14.1.2).
        assert_eq!(
            parse_range("bytes=-5000", 1000),
            RangeOutcome::Satisfiable {
                offset: 0,
                len: 1000
            }
        );
        // Clamp last-byte-pos to EOF.
        assert_eq!(
            parse_range("bytes=900-99999", 1000),
            RangeOutcome::Satisfiable {
                offset: 900,
                len: 100
            }
        );
        assert_eq!(
            parse_range("bytes=1000-", 1000),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(parse_range("bytes=-0", 1000), RangeOutcome::Unsatisfiable);
        // Inverted and overflowing specs are 416, never a wrapped offset (nginx parity,
        // golden-verified; CVE-2017-7529 class).
        assert_eq!(
            parse_range("bytes=500-100", 1000),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            parse_range("bytes=99999999999999999999-", 1000),
            RangeOutcome::Unsatisfiable
        );
        // Empty representation: range filter bypassed entirely (nginx parity).
        assert_eq!(parse_range("bytes=0-", 0), RangeOutcome::Ignored);
        assert_eq!(parse_range("bytes=-5", 0), RangeOutcome::Ignored);
        // Ignored (200 full body): multi-range, malformed, non-bytes unit.
        assert_eq!(parse_range("bytes=0-1,5-9", 1000), RangeOutcome::Ignored);
        assert_eq!(parse_range("bytes=+3-9", 1000), RangeOutcome::Ignored);
        assert_eq!(parse_range("items=0-5", 1000), RangeOutcome::Ignored);
        assert_eq!(parse_range("bytes=", 1000), RangeOutcome::Ignored);
    }
}

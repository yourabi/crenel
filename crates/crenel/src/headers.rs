//! Header-value synthesis: validators (ETag / Last-Modified), MIME mapping, and redirect
//! `Location` construction. Pure string work — cross-platform, no filesystem.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::sidecar::Encoding;

/// Strong ETag from the served fd's fstat snapshot (design D3 + owner decision 2026-07-10):
/// `"hex(mtime_ns)-hex(size)"` where `mtime_ns = mtime_sec * 1e9 + mtime_nsec`.
///
/// Nanosecond granularity closes nginx's same-second-same-size swap collision (its ETag is
/// second-granular) — a strictly-better divergence recorded in the golden-fixture ledger.
/// Sidecar-encoded variants get a `-br`/`-gz`/`-zst` suffix so representations never share
/// a validator (RFC 9110 §8.8.3: distinct representations need distinct ETags).
///
/// Negative (pre-epoch) mtimes format as the two's-complement hex of the i128 product —
/// deterministic and collision-free, which is all a validator needs.
pub fn etag(mtime_sec: i64, mtime_nsec: i64, len: u64, encoding: Encoding) -> String {
    let ns: i128 = (mtime_sec as i128) * 1_000_000_000 + (mtime_nsec as i128);
    match encoding.etag_suffix() {
        Some(suffix) => format!("\"{ns:x}-{len:x}{suffix}\""),
        None => format!("\"{ns:x}-{len:x}\""),
    }
}

/// `Last-Modified` value (IMF-fixdate). HTTP dates are second-granular; pre-epoch mtimes
/// clamp to the epoch (representable, monotone, and irrelevant for real asset trees).
pub fn last_modified(mtime_sec: i64) -> String {
    httpdate::fmt_http_date(system_time_for(mtime_sec))
}

/// Last second of year 9999 — the ceiling of what HTTP-dates can express (and where
/// `httpdate` panics). A file with a farther-future mtime is corrupt or hostile; clamping
/// keeps every derived value (Last-Modified, date comparisons) total and deterministic
/// while the ns-exact ETag still distinguishes the actual timestamps.
/// Found by `fuzz_conditionals` (mtime = i64::MAX panicked SystemTime addition).
const MAX_HTTP_DATE_UNIX_SECS: i64 = 253_402_300_799;

/// The second-granular `SystemTime` used for date comparisons (`If-Modified-Since` exact
/// match, `If-Unmodified-Since`, date-form `If-Range`). Clamped to the HTTP-date
/// representable window `[epoch, 9999-12-31]` — never panics on hostile mtimes.
pub fn system_time_for(mtime_sec: i64) -> SystemTime {
    let clamped = mtime_sec.clamp(0, MAX_HTTP_DATE_UNIX_SECS);
    UNIX_EPOCH + Duration::from_secs(clamped as u64)
}

/// Parse an HTTP-date in any of the three RFC 9110 §5.6.7 formats. `None` on garbage —
/// per RFC a malformed date simply fails the condition it appears in.
pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(value).ok()
}

/// Deterministic Content-Type from the FINAL path segment's extension (lowercased ASCII
/// compare). Unknown → `application/octet-stream`; never sniffed (baseline item 21 — the
/// response side always carries `X-Content-Type-Options: nosniff`). No charset rewriting:
/// the nginx charset-module CVE class (CVE-2026-48142/-42934) is omitted by construction;
/// UTF-8 charsets are baked into the table entries where the type defines a default.
pub fn content_type_for(rel_path: &str) -> &'static str {
    let final_segment = rel_path.rsplit('/').next().unwrap_or(rel_path);
    // Extension = after the LAST dot, and only when it isn't a bare-dotfile prefix
    // ("archive.tar.gz" -> "gz"; ".env" has no extension).
    let ext = match final_segment.rfind('.') {
        Some(0) | None => return "application/octet-stream",
        Some(idx) => &final_segment[idx + 1..],
    };
    // Longest extension in the table is 5 bytes; a stack buffer keeps this allocation-free.
    let mut lower = [0u8; 8];
    if ext.len() > lower.len() || !ext.is_ascii() {
        return "application/octet-stream";
    }
    for (i, b) in ext.bytes().enumerate() {
        lower[i] = b.to_ascii_lowercase();
    }
    lookup_mime(&lower[..ext.len()])
}

/// ~60 conservative entries (design D3). Media containers (mp4/webm/…) are opaque bytes —
/// range-based pseudo-streaming needs no parsing, and the nginx mp4-module CVE family
/// (CVE-2012-2089 … CVE-2026-32647) is omitted by construction.
fn lookup_mime(ext: &[u8]) -> &'static str {
    match ext {
        // text (UTF-8 charset where the consumer ecosystem expects it)
        b"html" | b"htm" => "text/html; charset=utf-8",
        b"css" => "text/css; charset=utf-8",
        b"js" | b"mjs" => "text/javascript; charset=utf-8",
        b"txt" => "text/plain; charset=utf-8",
        b"md" => "text/markdown; charset=utf-8",
        b"csv" => "text/csv; charset=utf-8",
        b"xml" => "application/xml",
        b"json" => "application/json",
        b"map" => "application/json",
        b"webmanifest" => "application/manifest+json",
        b"ics" => "text/calendar; charset=utf-8",
        b"vtt" => "text/vtt; charset=utf-8",
        // images
        b"png" => "image/png",
        b"jpg" | b"jpeg" => "image/jpeg",
        b"gif" => "image/gif",
        b"webp" => "image/webp",
        b"avif" => "image/avif",
        b"svg" => "image/svg+xml",
        b"ico" => "image/x-icon",
        b"bmp" => "image/bmp",
        b"tif" | b"tiff" => "image/tiff",
        b"apng" => "image/apng",
        // fonts
        b"woff" => "font/woff",
        b"woff2" => "font/woff2",
        b"ttf" => "font/ttf",
        b"otf" => "font/otf",
        b"eot" => "application/vnd.ms-fontobject",
        // audio/video as opaque byte streams
        b"mp3" => "audio/mpeg",
        b"ogg" | b"oga" => "audio/ogg",
        b"wav" => "audio/wav",
        b"flac" => "audio/flac",
        b"m4a" => "audio/mp4",
        b"aac" => "audio/aac",
        b"mp4" | b"m4v" => "video/mp4",
        b"webm" => "video/webm",
        b"ogv" => "video/ogg",
        b"mov" => "video/quicktime",
        b"avi" => "video/x-msvideo",
        b"ts" => "video/mp2t",
        // archives / binaries / documents
        b"gz" => "application/gzip",
        b"br" => "application/octet-stream",
        b"zst" => "application/zstd",
        b"zip" => "application/zip",
        b"tar" => "application/x-tar",
        b"7z" => "application/x-7z-compressed",
        b"pdf" => "application/pdf",
        b"wasm" => "application/wasm",
        b"rtf" => "application/rtf",
        b"eps" | b"ps" => "application/postscript",
        // misc web
        b"atom" => "application/atom+xml",
        b"rss" => "application/rss+xml",
        b"jsonld" => "application/ld+json",
        b"otml" => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

/// Trailing-slash redirect `Location`: rebuilt from VALIDATED segments only,
/// never echoed from raw request bytes.
///
/// - each rel segment is percent-encoded with an unreserved-only allowlist (everything
///   else, including any control byte that somehow survived, becomes `%XX`);
/// - the mount prefix is the operator's validated literal (boot-rejected if hostile);
/// - result always has exactly one leading `/` and cannot start `//` (scheme-relative
///   open-redirect shape), because the mount prefix is `/`-rooted and segments are
///   non-empty — asserted in tests;
/// - the raw query is preserved verbatim after `?` (nginx parity; it is not decoded and
///   cannot terminate the header because CR/LF never survive the pipeline OR the encode).
pub fn redirect_location(mount_prefix: &str, rel_path: &str, raw_query: Option<&str>) -> String {
    debug_assert!(mount_prefix.starts_with('/'));
    let mut out = String::with_capacity(mount_prefix.len() + rel_path.len() + 16);
    out.push_str(mount_prefix);
    for segment in rel_path.split('/').filter(|s| !s.is_empty()) {
        if !out.ends_with('/') {
            out.push('/');
        }
        encode_segment_into(&mut out, segment);
    }
    if !out.ends_with('/') {
        out.push('/');
    }
    if let Some(q) = raw_query {
        out.push('?');
        out.push_str(q);
    }
    out
}

/// RFC 3986 unreserved set only: ALPHA / DIGIT / `-` / `.` / `_` / `~`. Conservative on
/// purpose — over-encoding is always safe in a path segment.
fn encode_segment_into(out: &mut String, segment: &str) {
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((byte >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((byte & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_is_ns_granular_and_encoding_suffixed() {
        let base = etag(1_700_000_000, 123_456_789, 4096, Encoding::Identity);
        let same_second_later = etag(1_700_000_000, 123_456_790, 4096, Encoding::Identity);
        // The nginx same-second-same-size collision this format exists to close.
        assert_ne!(base, same_second_later);
        assert!(base.starts_with('"') && base.ends_with('"'));
        let br = etag(1_700_000_000, 123_456_789, 4096, Encoding::Brotli);
        assert!(br.ends_with("-br\""));
        assert_ne!(base, br);
    }

    #[test]
    fn pre_epoch_mtime_is_deterministic() {
        let a = etag(-5, 0, 10, Encoding::Identity);
        let b = etag(-5, 0, 10, Encoding::Identity);
        assert_eq!(a, b);
        assert_eq!(last_modified(-5), last_modified(0));
    }

    #[test]
    fn hostile_extreme_mtimes_never_panic() {
        // fuzz_conditionals regression: i64::MAX overflowed SystemTime; beyond-9999
        // dates panic httpdate. Both clamp; the ETag still tells them apart.
        for mtime in [i64::MAX, i64::MIN, MAX_HTTP_DATE_UNIX_SECS + 1] {
            let _ = last_modified(mtime);
            let _ = system_time_for(mtime);
        }
        assert_eq!(
            last_modified(i64::MAX),
            last_modified(MAX_HTTP_DATE_UNIX_SECS)
        );
        assert_ne!(
            etag(i64::MAX, 0, 10, Encoding::Identity),
            etag(MAX_HTTP_DATE_UNIX_SECS, 0, 10, Encoding::Identity)
        );
    }

    #[test]
    fn http_date_roundtrip_and_three_formats() {
        let lm = last_modified(784_111_777);
        assert_eq!(lm, "Sun, 06 Nov 1994 08:49:37 GMT");
        let t = parse_http_date(&lm).unwrap();
        assert_eq!(t, system_time_for(784_111_777));
        // RFC 850 and asctime forms parse to the same instant (RFC 9110 §5.6.7).
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap(),
            t
        );
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994").unwrap(), t);
        assert!(parse_http_date("yesterday-ish").is_none());
    }

    #[test]
    fn content_type_table_edges() {
        assert_eq!(
            content_type_for("app-abc123.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type_for("a/b/style.CSS"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("archive.tar.gz"), "application/gzip");
        assert_eq!(content_type_for("font.woff2"), "font/woff2");
        assert_eq!(content_type_for("clip.mp4"), "video/mp4");
        // Dotfile is a name, not an extension.
        assert_eq!(content_type_for(".env"), "application/octet-stream");
        assert_eq!(content_type_for("noext"), "application/octet-stream");
        assert_eq!(content_type_for("weird.zzz"), "application/octet-stream");
        assert_eq!(content_type_for(""), "application/octet-stream");
    }

    #[test]
    fn redirect_location_is_reencoded_and_single_rooted() {
        assert_eq!(redirect_location("/assets", "docs", None), "/assets/docs/");
        assert_eq!(
            redirect_location("/", "a b/c%d", Some("x=1&y=2")),
            "/a%20b/c%25d/?x=1&y=2"
        );
        // A segment that decoded to a CR/LF-bearing name can never split the header.
        let loc = redirect_location("/", "evil\r\nSet-Cookie: x", None);
        assert!(!loc.contains('\r') && !loc.contains('\n'));
        assert_eq!(loc, "/evil%0D%0ASet-Cookie%3A%20x/");
        // Root mount + empty rel: exactly "/" — never "//" (scheme-relative shape).
        assert_eq!(redirect_location("/", "", None), "/");
        assert!(!redirect_location("/", "host.evil", None).starts_with("//"));
    }
}

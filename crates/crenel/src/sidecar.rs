//! Precompressed-sidecar negotiation: parse `Accept-Encoding` q-values and produce the
//! preference-ordered list of sidecar encodings to try (`.br` / `.zst` / `.gz` files next
//! to the asset — design D3). Pure parsing; the Linux resolver does the opening.
//!
//! Rules:
//! - a sidecar is served only if the UNCOMPRESSED file exists (the resolver enforces this
//!   by resolving the identity file first);
//! - all validators and Content-Length come from the SIDECAR fd's snapshot;
//! - `Vary: Accept-Encoding` goes on EVERY response for sidecar-eligible mounts —
//!   identity and 304 included (strictly better than nginx `gzip_static`, ledger entry).

/// A servable representation encoding. `Identity` is the file itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Identity,
    Brotli,
    Zstd,
    Gzip,
}

impl Encoding {
    /// Sidecar filename suffix (`None` for identity).
    pub fn file_suffix(self) -> Option<&'static str> {
        match self {
            Encoding::Identity => None,
            Encoding::Brotli => Some(".br"),
            Encoding::Zstd => Some(".zst"),
            Encoding::Gzip => Some(".gz"),
        }
    }

    /// `Content-Encoding` token (`None` for identity — the header is omitted).
    pub fn content_encoding(self) -> Option<&'static str> {
        match self {
            Encoding::Identity => None,
            Encoding::Brotli => Some("br"),
            Encoding::Zstd => Some("zstd"),
            Encoding::Gzip => Some("gzip"),
        }
    }

    /// ETag suffix so distinct representations never share a validator (RFC 9110 §8.8.3).
    pub fn etag_suffix(self) -> Option<&'static str> {
        match self {
            Encoding::Identity => None,
            Encoding::Brotli => Some("-br"),
            Encoding::Zstd => Some("-zst"),
            Encoding::Gzip => Some("-gz"),
        }
    }
}

/// Compressed encodings in the tie-break preference order (design D3: br > zstd > gzip
/// at equal q — smaller payloads win ties).
const PREFERENCE: [Encoding; 3] = [Encoding::Brotli, Encoding::Zstd, Encoding::Gzip];

/// Negotiate the sidecar TRY order from a raw `Accept-Encoding` value.
///
/// Returns compressed encodings the client accepts (q > 0), highest q first, [`PREFERENCE`]
/// order within a q tie. Empty means "serve identity only". Absent header → identity only
/// (a client that says nothing gets the canonical bytes — nginx `gzip_static` parity).
///
/// Identity fallback is unconditional: even `identity;q=0` serves identity rather than 406
/// (nginx parity — a static server has nothing else to offer; noted for the ledger).
/// Unparseable list members are skipped, not fatal (lenient like nginx).
pub fn negotiate(accept_encoding: Option<&str>) -> Vec<Encoding> {
    let Some(header) = accept_encoding else {
        return Vec::new();
    };
    // q values have at most 3 decimals (RFC 9110 §12.4.2); scale ×1000 to stay integral.
    let mut wildcard_q: Option<u16> = None;
    let mut explicit: [Option<u16>; 3] = [None, None, None];

    for member in header.split(',') {
        let member = member.trim();
        if member.is_empty() {
            continue;
        }
        let (token, q) = match member.split_once(';') {
            None => (member.trim(), 1000u16),
            Some((token, params)) => match parse_q(params) {
                Some(q) => (token.trim(), q),
                None => continue, // malformed member: skip, don't fail the header
            },
        };
        if token == "*" {
            wildcard_q = Some(q);
            continue;
        }
        let idx = match () {
            _ if token.eq_ignore_ascii_case("br") => 0,
            _ if token.eq_ignore_ascii_case("zstd") => 1,
            _ if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") => 2,
            _ => continue, // identity/deflate/unknown: no sidecar for it
        };
        explicit[idx] = Some(q);
    }

    let mut accepted: Vec<(u16, usize)> = Vec::new();
    for (idx, _) in PREFERENCE.iter().enumerate() {
        let q = explicit[idx].or(wildcard_q).unwrap_or(0);
        if q > 0 {
            accepted.push((q, idx));
        }
    }
    // Highest q first; PREFERENCE index breaks ties (sort is stable, so sorting by q
    // descending preserves the br > zstd > gzip construction order within a tie).
    accepted.sort_by_key(|&(q, _)| std::cmp::Reverse(q));
    accepted
        .into_iter()
        .map(|(_, idx)| PREFERENCE[idx])
        .collect()
}

/// Parse `;q=...` params of one list member. `None` = malformed (skip the member).
/// Accepts `q` case-insensitively, 0/1 with up to three decimals (RFC 9110 §12.4.2).
fn parse_q(params: &str) -> Option<u16> {
    let mut q = 1000u16;
    for param in params.split(';') {
        let param = param.trim();
        let (name, value) = param.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("q") {
            continue; // unknown parameter: ignored per RFC
        }
        let value = value.trim();
        let (int_part, frac) = match value.split_once('.') {
            None => (value, ""),
            Some((i, f)) => (i, f),
        };
        let base = match int_part {
            "0" => 0u16,
            "1" => 1000u16,
            _ => return None,
        };
        if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut fraction = 0u16;
        for (i, b) in frac.bytes().enumerate() {
            fraction += u16::from(b - b'0') * [100u16, 10, 1][i];
        }
        if base == 1000 && fraction != 0 {
            return None; // q must be <= 1
        }
        q = base + fraction;
    }
    Some(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_orders_by_q_then_preference() {
        assert_eq!(negotiate(None), vec![]);
        assert_eq!(negotiate(Some("")), vec![]);
        assert_eq!(
            negotiate(Some("gzip, br")),
            vec![Encoding::Brotli, Encoding::Gzip]
        );
        assert_eq!(
            negotiate(Some("gzip;q=1, br;q=0.5")),
            vec![Encoding::Gzip, Encoding::Brotli]
        );
        assert_eq!(
            negotiate(Some("br;q=0, gzip")),
            vec![Encoding::Gzip] // q=0 excludes
        );
        assert_eq!(
            negotiate(Some("zstd, br, gzip")),
            vec![Encoding::Brotli, Encoding::Zstd, Encoding::Gzip]
        );
    }

    #[test]
    fn wildcard_and_case_and_malformed_members() {
        assert_eq!(
            negotiate(Some("*")),
            vec![Encoding::Brotli, Encoding::Zstd, Encoding::Gzip]
        );
        assert_eq!(
            negotiate(Some("*;q=0, gzip;q=0.8")),
            vec![Encoding::Gzip] // wildcard-zero excludes the others
        );
        assert_eq!(negotiate(Some("GZIP")), vec![Encoding::Gzip]);
        assert_eq!(negotiate(Some("x-gzip")), vec![Encoding::Gzip]);
        // Malformed q on one member skips that member only.
        assert_eq!(negotiate(Some("br;q=nope, gzip")), vec![Encoding::Gzip]);
        assert_eq!(negotiate(Some("br;q=1.5")), vec![]);
        // deflate/identity/unknown tokens produce no sidecar attempts.
        assert_eq!(negotiate(Some("deflate, identity")), vec![]);
    }
}

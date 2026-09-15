# Divergence ledger — deliberate behavioral differences vs nginx

Every entry here is asserted BOTH ways by the golden-fixture harness
(`tests/nginx_golden.rs`, gated on `CRENEL_NGINX_FIXTURES=1` against the pinned
`tests/fixtures/nginx-golden.conf`): the fixture fails if nginx and crenel agree where a
divergence is claimed, or disagree anywhere one isn't. Any new mismatch is a bug until it
earns a row here with a rationale.

| ID | Behavior | Nginx | Crenel | Rationale |
|----|----------|-------|--------|-----------|
| D1 | ETag granularity | `hex(mtime_sec)-hex(size)` | `hex(mtime_ns)-hex(size)` (+`-gz`/`-br`/`-zst` per encoding) | Owner decision 2026-07-10: closes nginx's same-second-same-size swap collision (stale-served-as-fresh); per-encoding suffix satisfies RFC 9110 §8.8.3 distinct-representation rule. |
| D2 | `Vary: Accept-Encoding` scope | Only on encoded responses (gzip_static) | On EVERY response of a sidecar-eligible mount — identity, 304, 416 included | An un-Vary'd identity response cached by a shared cache under `immutable` locks all clients to uncompressed bytes (RFC 9110 §12.5.5). Strictly better. |
| D3 | Multi-range requests | 206 `multipart/byteranges` | Header ignored → 200 full body | Design D3: structurally eliminates multipart amplification (CVE-2011-3192 class) and the CVE-2017-7529 multipart surface; precedented by `static-files-module`. Single ranges are fully supported. |
| D4 | Interior `..` (`/docs/../a.txt`) | Textually resolved (200) | Fixed 400, mount-independent | Global reject removes the traversal grammar entirely and the 400-vs-fallthrough mount-map oracle; no legitimate asset URL contains `..`. |
| D5 | Dotfiles (`/.hidden.txt`) | Served (200) | Policy miss → 404 (per-mount opt-in to allow) | Baseline item 10: `.git`/`.env` exposure is a recurring pen-test finding; deny-by-default with opt-in beats nginx's serve-by-default. |
| D6 | Directory without index, trailing slash | 403 | Miss → 404 (or fallthrough per mount) | 403 confirms existence — an information leak; a miss is indistinguishable from absence and composes with the fallthrough policy. |
| D7 | Decoded control bytes / non-UTF-8 paths | Mostly passed through to the filesystem | Fixed 400 | Pipeline screens: kills CRLF-into-`Location` at the source and byte-alias filesystem hazards (Windows-CVE-family lesson, baseline item 11). Not fixture-comparable per case; enforced by the pipeline corpus. |
| D8 | Orphan sidecar (`x.js.gz` present, `x.js` absent) | Gzip_static serves the `.gz` (200) | 404 — uncompressed must exist | Caddy rule: a stray/planted sidecar must not shadow a deleted or never-published asset. |
| D9 | FIFO/device in docroot | Opened and served | Miss (`NotRegular`), non-blocking open | `O_NONBLOCK|O_NOCTTY` + fstat reject. nginx will stream a FIFO; that is a hang primitive, not a feature. Enforced by `writerless_fifo_returns_immediately_as_not_regular`. |

Parity notes (NOT divergences, easily mistaken for them):
- `If-Modified-Since` uses EXACT date match — that IS nginx's default (`if_modified_since exact`).
- `identity;q=0` still serves identity rather than 406 — nginx does the same; a static
  server has nothing else to offer.
- 301 directory redirect — same status; nginx emits an absolute `Location` URL by default
  (`absolute_redirect on`), crenel emits a relative one. Statuses compare; Location shape
  is the consumer's concern and intentionally uncompared in the harness.

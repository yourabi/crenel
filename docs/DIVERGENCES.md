# Divergence ledger — deliberate behavioral differences vs nginx

The [golden-fixture harness](../crates/crenel/tests/nginx_golden.rs) compares selected
responses from Crenel and a local nginx using the
[reference configuration](../crates/crenel/tests/fixtures/nginx-golden.conf).
Enable it with `CRENEL_NGINX_FIXTURES=1`. It checks ETag inequality for D1 and
the expected status on each side for D3, D4, D5, D6, and D8. For other cases it
compares statuses and selected header values when both sides emit them.

Other differences have Crenel-only coverage: D2's `Vary` behavior is asserted by
[`semantics_corpus.rs`](../crates/crenel/tests/semantics_corpus.rs), D7's path screens
by [`pipeline_corpus.rs`](../crates/crenel/tests/pipeline_corpus.rs), and D9's
non-blocking FIFO rejection by
[`resolve.rs`](../crates/crenel/tests/resolve.rs). The golden harness does
not compare `Vary`, response bodies, or every header; it does not establish nginx's
side of D2, D7, or D9. This ledger documents the intended behavior, with coverage
limited to the assertions described here.

| ID | Behavior | Nginx | Crenel | Rationale |
|----|----------|-------|--------|-----------|
| D1 | ETag granularity | `hex(mtime_sec)-hex(size)` | `hex(mtime_ns)-hex(size)` (+`-gz`/`-br`/`-zst` per encoding) | Closes nginx's same-second-same-size swap collision (stale-served-as-fresh); per-encoding suffix satisfies RFC 9110 §8.8.3 distinct-representation rule. |
| D2 | `Vary: Accept-Encoding` scope | Only on encoded responses (gzip_static) | On EVERY response of a sidecar-eligible mount — identity, 304, 416 included | An un-Vary'd identity response cached by a shared cache under `immutable` locks all clients to uncompressed bytes (RFC 9110 §12.5.5). |
| D3 | Multi-range requests | 206 `multipart/byteranges` | Header ignored → 200 full body | Avoids multipart amplification (CVE-2011-3192 class) and the CVE-2017-7529 multipart surface; precedented by `static-files-module`. Single ranges are fully supported. |
| D4 | Interior `..` (`/docs/../a.txt`) | Textually resolved (200) | Fixed 400, mount-independent | Global reject removes the traversal grammar entirely and the 400-vs-fallthrough mount-map oracle; no legitimate asset URL contains `..`. |
| D5 | Dotfiles (`/.hidden.txt`) | Served (200) | Policy miss → 404 (per-mount opt-in to allow) | Denying dotfiles by default reduces accidental publication of `.git` and `.env`; a mount can opt in to serving them. |
| D6 | Directory without index, trailing slash | 403 | Miss → 404 (or fallthrough per mount) | 403 confirms existence — an information leak; a miss is indistinguishable from absence and composes with the fallthrough policy. |
| D7 | Decoded control bytes / non-UTF-8 paths | Mostly passed through to the filesystem | Fixed 400 | Path screens reject CRLF before `Location` construction and exclude non-UTF-8 filename bytes. Crenel behavior is asserted by the pipeline corpus. |
| D8 | Orphan sidecar (`x.js.gz` present, `x.js` absent) | Gzip_static serves the `.gz` (200) | 404 — uncompressed must exist | A stray sidecar must not shadow a deleted or never-published asset. |
| D9 | FIFO/device in docroot | Opened and served | Miss (`NotRegular`), non-blocking open | `O_NONBLOCK\|O_NOCTTY` + fstat reject. Rejecting non-regular files prevents a request from waiting indefinitely for a FIFO writer. Enforced by `writerless_fifo_returns_immediately_as_not_regular`. |

Parity notes (NOT divergences, easily mistaken for them):
- `If-Modified-Since` uses EXACT date match — that IS nginx's default (`if_modified_since exact`).
- `identity;q=0` still serves identity rather than 406 — nginx does the same; a static
  server has nothing else to offer.
- 301 directory redirect — same status; nginx emits an absolute `Location` URL by default
  (`absolute_redirect on`), crenel emits a relative one. Statuses compare; Location shape
  is the consumer's concern and intentionally uncompared in the harness.

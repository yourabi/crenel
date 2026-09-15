# crenel

Static file serving for [Pingora](https://github.com/cloudflare/pingora)-based servers.

A crenel is the opening in the battlement your assets are served through, while the wall keeps
everything else out. That's what this is for serving files on pingora-based servers.

The core engine is deliberately framework-agnostic: it has zero Pingora dependencies and
is usable from hyper, axum, or anything else.

## Crates

- **`crenel`** — the engine: request-path classification (single decode-once
  pipeline), race-free docroot containment via `openat2(RESOLVE_BENEATH)`, HTTP
  conditional/range/sidecar semantics, and header synthesis.
  `#![forbid(unsafe_code)]`. The filesystem resolver is Linux-only (kernel >= 5.6
  required, fail-closed); the pure pipeline compiles everywhere.
- **`crenel-pingora`** — a thin adapter driving a Pingora `Session`: streamed writes,
  whole-response deadline, and a static-IO semaphore. Ships a `crenel-serve` binary as a
  standalone consumer and e2e test vehicle.

## Design bar

"At least as fast and at least as secure as nginx for static files, over TLS" — the claim
is scoped, per-cell, and test-mapped. Security properties trace to named CVE/RUSTSEC
advisories and land as named tests.

Notable strictly-better-than-nginx choices: single-syscall symlink containment (no
`disable_symlinks` TOCTOU), writer-less-FIFO immunity (`O_NONBLOCK` open), `Vary:
Accept-Encoding` on identity/304 responses, nanosecond-mtime ETags, no media parsers,
and memory-safe parsing throughout.

Deliberate behavioral differences from nginx are enumerated with rationale in
[`docs/DIVERGENCES.md`](docs/DIVERGENCES.md); each is asserted both ways by a
golden-fixture harness pinned against a real nginx configuration.

## Status

Early / alpha. The API is not yet stable.

## Build

```sh
cargo build --workspace
cargo test  --workspace
```

The nginx golden-fixture suite is manual-gated: it runs only with
`CRENEL_NGINX_FIXTURES=1` and a local nginx available.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional terms or
conditions.

# crenel

Static file serving for [Pingora](https://github.com/cloudflare/pingora)-based servers.

A crenel is the opening in the battlement your assets are served through, while the wall keeps
everything else out. That's what this is for serving files on pingora-based servers.

The core engine is deliberately framework-agnostic: it has zero Pingora dependencies and
is usable from hyper, axum, or anything else.

## Crates

- **`crenel`** — the engine: request-path classification (single decode-once
  pipeline), race-free docroot containment via kernel-scoped opens
  (`openat2(RESOLVE_BENEATH)` on Linux, `openat(O_RESOLVE_BENEATH)` on macOS), HTTP
  conditional/range/sidecar semantics, and header synthesis.
  `#![forbid(unsafe_code)]`. The filesystem resolver runs on Linux (kernel >= 5.6
  required, fail-closed) and macOS, where hits on case-folding volumes are served
  only under their byte-exact on-disk name; the pure pipeline compiles everywhere.
- **`crenel-pingora`** — a thin adapter driving a Pingora `Session`: streamed writes,
  whole-response deadline, and a static-IO semaphore. Ships a `crenel-serve` binary as a
  standalone consumer and e2e test vehicle.

## Design

Crenel aims to provide efficient static-file serving with explicit containment and
resource limits. The engine uses kernel-enforced path containment, non-blocking
opens for special files, memory-safe parsing, nanosecond-mtime ETags, and
`Vary: Accept-Encoding` on negotiated representations. The adapter bounds IO
concurrency and response duration.

[Behavioral differences from nginx](docs/DIVERGENCES.md) describe the HTTP policies
and their test coverage. The golden-fixture harness compares selected behavior
against nginx; Crenel's own test suites cover additional invariants. These are
correctness tests, not comparative performance measurements.

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

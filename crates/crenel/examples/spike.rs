//! IO microbench spike — the gate for the small-file read placement decision
//!: does per-request `spawn_blocking` dispatch eat the syscall-bound
//! small-hot budget, and how does it compare to reading inline on the async worker
//! (nginx's default posture) and to `tokio::fs`?
//!
//! Every strategy includes the REAL request-path work: openat2(RESOLVE_BENEATH) +
//! fstat + full read, via `Root::open_rel`. RELATIVE numbers decide; absolute numbers
//! from WSL are indicative-only (real-host confirmation at the bench gate).
//!
//! Run: `cargo run --release --example spike`

fn main() {
    #[cfg(target_os = "linux")]
    spike::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("spike is Linux-only (the resolver is Linux-only)");
}

#[cfg(target_os = "linux")]
mod spike {
    use std::io::Read;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crenel::resolve::{Outcome, Root, SymlinkPolicy};

    const CONCURRENCY: usize = 64;
    const CELL_SECONDS: u64 = 2;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Mode {
        /// open+fstat+read directly on the async worker thread (nginx-default risk
        /// posture: page-cache-hot reads block the event loop for microseconds).
        Inline,
        /// One combined spawn_blocking(open+fstat+read) per request (design D4 draft).
        SpawnBlocking,
        /// spawn_blocking dispatch overhead alone (empty closure) — the tax being measured.
        DispatchOnly,
        /// tokio::fs::read by full path (no openat2 containment) — framework reference.
        TokioFs,
    }

    fn read_via_root(root: &Root, rel: &str) -> usize {
        match root.open_rel(rel) {
            Outcome::File(f) => {
                let mut file = std::fs::File::from(f.fd);
                let mut buf = Vec::with_capacity(1 << 17);
                file.read_to_end(&mut buf).expect("read");
                buf.len()
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    async fn cell(root: Arc<Root>, full_path: Arc<PathBuf>, rel: &'static str, mode: Mode) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(CELL_SECONDS);
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let root = Arc::clone(&root);
            let full_path = Arc::clone(&full_path);
            handles.push(tokio::spawn(async move {
                let mut ops = 0u64;
                while Instant::now() < deadline {
                    match mode {
                        Mode::Inline => {
                            read_via_root(&root, rel);
                        }
                        Mode::SpawnBlocking => {
                            let root = Arc::clone(&root);
                            tokio::task::spawn_blocking(move || read_via_root(&root, rel))
                                .await
                                .expect("join");
                        }
                        Mode::DispatchOnly => {
                            tokio::task::spawn_blocking(|| ()).await.expect("join");
                        }
                        Mode::TokioFs => {
                            let bytes = tokio::fs::read(full_path.as_ref()).await.expect("read");
                            std::hint::black_box(bytes.len());
                        }
                    }
                    ops += 1;
                }
                ops
            }));
        }
        let mut total = 0u64;
        for handle in handles {
            total += handle.await.expect("join");
        }
        total
    }

    pub fn run() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let small = vec![0xABu8; 1024];
        let medium = vec![0xCDu8; 64 * 1024];
        std::fs::write(tmp.path().join("small.bin"), &small).unwrap();
        std::fs::write(tmp.path().join("med.bin"), &medium).unwrap();
        let root = Arc::new(Root::pin(tmp.path(), SymlinkPolicy::Deny).expect("pin"));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");

        println!(
            "crenel IO spike: concurrency={CONCURRENCY}, {CELL_SECONDS}s/cell, page-cache hot"
        );
        println!("(WSL numbers are indicative-only; decision is by RELATIVE comparison)");
        println!(
            "{:<16} {:>8} {:>12} {:>12} {:>10}",
            "mode", "size", "ops", "ops/s", "us/op"
        );

        for (rel, size) in [("small.bin", 1024usize), ("med.bin", 64 * 1024)] {
            let full = Arc::new(root.canonical().join(rel));
            for mode in [
                Mode::Inline,
                Mode::SpawnBlocking,
                Mode::DispatchOnly,
                Mode::TokioFs,
            ] {
                // Warmup.
                runtime.block_on(async {
                    let _ = read_via_root(&root, rel);
                });
                let start = Instant::now();
                let ops = runtime.block_on(cell(Arc::clone(&root), Arc::clone(&full), rel, mode));
                let elapsed = start.elapsed().as_secs_f64();
                let ops_per_sec = ops as f64 / elapsed;
                let us_per_op = elapsed * 1e6 * CONCURRENCY as f64 / ops as f64;
                println!(
                    "{:<16} {:>8} {:>12} {:>12.0} {:>10.2}",
                    format!("{mode:?}"),
                    size,
                    ops,
                    ops_per_sec,
                    us_per_op
                );
            }
        }
    }
}

//! Fuzz the full classification pipeline (baseline item 29). Invariants: no panic ever;
//! any Candidate satisfies the resolver contract (relative, normalized, no hostile
//! segments, no control bytes) — the property the RUSTSEC PathBuf-push class violated.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use crenel::pipeline::{classify, Classification, Mount, Mounts};

fn mounts() -> &'static Mounts {
    static MOUNTS: OnceLock<Mounts> = OnceLock::new();
    MOUNTS.get_or_init(|| {
        Mounts::new(vec![
            Mount::new("/", false).unwrap(),
            Mount::new("/assets", false).unwrap(),
            Mount::new("/assets/deep", true).unwrap(),
        ])
        .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(target) = std::str::from_utf8(data) else { return };
    // Split fuzz bytes: first byte selects the method casing to also poke the gate.
    let method = match data.first() {
        Some(b) if b % 3 == 0 => "GET",
        Some(b) if b % 3 == 1 => "HEAD",
        _ => "POST",
    };
    if let Classification::Candidate(c) = classify(method, target, mounts()) {
        assert!(!c.rel_path.starts_with('/'));
        assert!(!c.rel_path.contains('\0'));
        if !c.rel_path.is_empty() {
            for seg in c.rel_path.split('/') {
                assert!(!seg.is_empty(), "empty segment in {:?}", c.rel_path);
                assert!(seg != "." && seg != "..", "dot segment in {:?}", c.rel_path);
                assert!(
                    seg.bytes().all(|b| b >= 0x20 && b != 0x7f),
                    "control byte in {:?}",
                    c.rel_path
                );
            }
        }
    }
});

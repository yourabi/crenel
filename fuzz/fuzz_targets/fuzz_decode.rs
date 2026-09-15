//! Fuzz the percent-decoder (baseline item 29: fuzz the decoder — the
//! CVE-2009-2629/CVE-2013-4547 parser classes). Invariants: no panic; decoded output
//! never exceeds input length; a decode error is one of the two escape-shaped rejects.
#![no_main]

use libfuzzer_sys::fuzz_target;
use crenel::pipeline::StructuralReject;

fuzz_target!(|data: &[u8]| {
    match crenel::pipeline::decode_once_for_fuzzing(data) {
        Ok(out) => assert!(out.len() <= data.len()),
        Err(e) => assert!(matches!(e, StructuralReject::InvalidEscape)),
    }
});

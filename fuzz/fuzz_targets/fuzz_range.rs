//! Fuzz the Range parser (CVE-2017-7529 class, baseline item 29). Invariants: no panic;
//! any satisfiable range lies strictly inside the representation with non-zero length
//! and non-overflowing end arithmetic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use crenel::semantics::parse_range_for_fuzzing;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let len = u64::from_le_bytes(data[..8].try_into().unwrap());
    let Ok(header) = std::str::from_utf8(&data[8..]) else { return };
    let (_, satisfiable) = parse_range_for_fuzzing(header, len);
    if let Some((offset, range_len)) = satisfiable {
        assert!(range_len > 0, "zero-length satisfiable range");
        assert!(offset < len, "offset {offset} outside representation {len}");
        let end = offset.checked_add(range_len).expect("range end overflow");
        assert!(end <= len, "range end {end} beyond representation {len}");
    }
});

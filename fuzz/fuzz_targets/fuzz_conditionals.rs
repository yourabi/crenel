//! Fuzz the full conditional/negotiation surface: plan_response with fuzz-controlled
//! header values plus the Accept-Encoding q-value parser. Invariants: no panic; status is
//! one of the five the design admits; body plans are consistent with status and length.
#![no_main]

use libfuzzer_sys::fuzz_target;
use crenel::semantics::{plan_response, BodyPlan, FileFacts, RequestFacts, ResponsePolicy};
use crenel::sidecar::{negotiate, Encoding};

fuzz_target!(|data: &[u8]| {
    if data.len() < 17 {
        return;
    }
    let len = u64::from_le_bytes(data[..8].try_into().unwrap());
    let mtime = i64::from_le_bytes(data[8..16].try_into().unwrap());
    let flags = data[16];
    let Ok(text) = std::str::from_utf8(&data[17..]) else { return };

    // One fuzz string, five views: slice it at pseudo-random points into header values.
    let parts: Vec<&str> = text.split('|').collect();
    let get = |i: usize| parts.get(i).copied().filter(|s| !s.is_empty());

    negotiate(get(0)); // must never panic on any q-value garbage

    let req = RequestFacts {
        head: flags & 1 != 0,
        if_match: get(1),
        if_none_match: get(2),
        if_modified_since: get(3),
        if_unmodified_since: get(4),
        if_range: get(5),
        range: get(0), // reuse the wildest slice as Range too
    };
    let file = FileFacts {
        len,
        mtime_sec: mtime,
        mtime_nsec: (flags as i64) * 1_000_000,
        encoding: if flags & 2 != 0 { Encoding::Brotli } else { Encoding::Identity },
        vary_applies: flags & 4 != 0,
        content_type: "application/octet-stream",
    };
    let plan = plan_response(&req, &file, &ResponsePolicy::default());
    assert!(matches!(plan.status, 200 | 206 | 304 | 412 | 416), "status {}", plan.status);
    match plan.body {
        BodyPlan::Range { offset, len: rlen } => {
            assert_eq!(plan.status, 206);
            assert!(rlen > 0 && offset < len && offset.checked_add(rlen).unwrap() <= len);
        }
        BodyPlan::Whole => assert!(matches!(plan.status, 200)),
        BodyPlan::None => {}
    }
});

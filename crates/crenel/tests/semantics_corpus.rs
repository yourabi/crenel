//! §13.2.2 conditional-evaluation corpus + response-plan header contract.
//! Pure semantics — runs on every platform.

use crenel::headers;
use crenel::semantics::{
    directory_action, plan_response, BodyPlan, DirectoryAction, FileFacts, RequestFacts,
    ResponsePlan, ResponsePolicy,
};
use crenel::sidecar::Encoding;

const MTIME: i64 = 784_111_777; // "Sun, 06 Nov 1994 08:49:37 GMT"
const NSEC: i64 = 123_456_789;
const LEN: u64 = 1000;

fn facts() -> FileFacts {
    FileFacts {
        len: LEN,
        mtime_sec: MTIME,
        mtime_nsec: NSEC,
        encoding: Encoding::Identity,
        vary_applies: false,
        content_type: "text/css; charset=utf-8",
    }
}

fn etag() -> String {
    headers::etag(MTIME, NSEC, LEN, Encoding::Identity)
}

fn lm() -> String {
    headers::last_modified(MTIME)
}

fn plan(req: RequestFacts<'_>) -> ResponsePlan {
    plan_response(&req, &facts(), &ResponsePolicy::default())
}

fn header<'a>(plan: &'a ResponsePlan, name: &str) -> Option<&'a str> {
    plan.headers
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.as_str())
}

// ---- unconditional ----

#[test]
fn plain_get_is_200_with_full_validator_set() {
    let p = plan(RequestFacts::default());
    assert_eq!((p.status, p.body), (200, BodyPlan::Whole));
    assert_eq!(header(&p, "etag").unwrap(), etag());
    assert_eq!(header(&p, "last-modified").unwrap(), lm());
    assert_eq!(header(&p, "content-length").unwrap(), "1000");
    assert_eq!(header(&p, "accept-ranges").unwrap(), "bytes");
    assert_eq!(header(&p, "x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        header(&p, "content-type").unwrap(),
        "text/css; charset=utf-8"
    );
    assert!(header(&p, "vary").is_none());
    assert!(header(&p, "content-encoding").is_none());
    assert!(header(&p, "cache-control").is_none());
}

#[test]
fn head_gets_identical_headers_and_no_body() {
    let p = plan(RequestFacts {
        head: true,
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (200, BodyPlan::None));
    assert_eq!(header(&p, "content-length").unwrap(), "1000");
}

#[test]
fn cache_control_policy_is_emitted_verbatim() {
    let policy = ResponsePolicy {
        cache_control: Some("public, max-age=31536000, immutable"),
    };
    let p = plan_response(&RequestFacts::default(), &facts(), &policy);
    assert_eq!(
        header(&p, "cache-control").unwrap(),
        "public, max-age=31536000, immutable"
    );
}

// ---- §13.2.2 step 1: If-Match (strong) ----

#[test]
fn if_match_star_passes() {
    let p = plan(RequestFacts {
        if_match: Some("*"),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

#[test]
fn if_match_matching_strong_etag_passes() {
    let tag = etag();
    let p = plan(RequestFacts {
        if_match: Some(&tag),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

#[test]
fn if_match_mismatch_is_412() {
    let p = plan(RequestFacts {
        if_match: Some("\"deadbeef-1\""),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (412, BodyPlan::None));
}

#[test]
fn if_match_weak_tag_never_strong_matches() {
    let weak = format!("W/{}", etag());
    let p = plan(RequestFacts {
        if_match: Some(&weak),
        ..Default::default()
    });
    assert_eq!(p.status, 412);
}

#[test]
fn if_match_list_matches_any_member() {
    let list = format!("\"nope-1\", {}", etag());
    let p = plan(RequestFacts {
        if_match: Some(&list),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

// ---- §13.2.2 step 2: If-Unmodified-Since (only when If-Match absent) ----

#[test]
fn ius_older_date_when_modified_is_412() {
    let p = plan(RequestFacts {
        if_unmodified_since: Some("Sun, 06 Nov 1994 08:49:36 GMT"),
        ..Default::default()
    });
    assert_eq!(p.status, 412);
}

#[test]
fn ius_equal_or_newer_date_passes() {
    for date in [lm().as_str(), "Mon, 07 Nov 1994 00:00:00 GMT"] {
        let p = plan(RequestFacts {
            if_unmodified_since: Some(date),
            ..Default::default()
        });
        assert_eq!(p.status, 200, "date {date:?}");
    }
}

#[test]
fn ius_malformed_date_fails_to_constrain() {
    let p = plan(RequestFacts {
        if_unmodified_since: Some("not a date"),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

#[test]
fn if_match_present_masks_ius() {
    // Step 2 runs ONLY when If-Match is absent: matching If-Match + violating IUS = 200.
    let tag = etag();
    let p = plan(RequestFacts {
        if_match: Some(&tag),
        if_unmodified_since: Some("Sun, 06 Nov 1994 08:49:36 GMT"),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

// ---- §13.2.2 step 3: If-None-Match (weak) ----

#[test]
fn inm_matching_etag_is_304_with_validators_no_body() {
    let tag = etag();
    let p = plan(RequestFacts {
        if_none_match: Some(&tag),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (304, BodyPlan::None));
    assert_eq!(header(&p, "etag").unwrap(), etag());
    assert_eq!(header(&p, "last-modified").unwrap(), lm());
    assert!(header(&p, "content-length").is_none());
    assert!(header(&p, "content-type").is_none());
}

#[test]
fn inm_weak_comparison_matches_weak_client_tag() {
    let weak = format!("W/{}", etag());
    let p = plan(RequestFacts {
        if_none_match: Some(&weak),
        ..Default::default()
    });
    assert_eq!(p.status, 304);
}

#[test]
fn inm_star_is_304() {
    let p = plan(RequestFacts {
        if_none_match: Some("*"),
        ..Default::default()
    });
    assert_eq!(p.status, 304);
}

#[test]
fn inm_mismatch_is_200() {
    let p = plan(RequestFacts {
        if_none_match: Some("\"deadbeef-1\""),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

// ---- §13.2.2 step 4: If-Modified-Since (only when If-None-Match absent; EXACT match) ----

#[test]
fn ims_exact_match_is_304() {
    let date = lm();
    let p = plan(RequestFacts {
        if_modified_since: Some(&date),
        ..Default::default()
    });
    assert_eq!(p.status, 304);
}

#[test]
fn ims_newer_date_is_200_nginx_exact_semantics() {
    // A NEWER client date must not suppress a rollback's changed content (nginx
    // `if_modified_since exact`, design D3).
    let p = plan(RequestFacts {
        if_modified_since: Some("Mon, 07 Nov 1994 00:00:00 GMT"),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

#[test]
fn inm_mismatch_masks_ims_match() {
    // Step 4 runs ONLY when If-None-Match is absent (RFC 9110 §13.1.3): a mismatching
    // INM forces 200 even though IMS matches exactly.
    let date = lm();
    let p = plan(RequestFacts {
        if_none_match: Some("\"deadbeef-1\""),
        if_modified_since: Some(&date),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

// ---- §13.2.2 step 5: Range + If-Range ----

#[test]
fn single_range_is_206_with_content_range() {
    let p = plan(RequestFacts {
        range: Some("bytes=200-499"),
        ..Default::default()
    });
    assert_eq!(
        (p.status, p.body),
        (
            206,
            BodyPlan::Range {
                offset: 200,
                len: 300
            }
        )
    );
    assert_eq!(header(&p, "content-range").unwrap(), "bytes 200-499/1000");
    assert_eq!(header(&p, "content-length").unwrap(), "300");
}

#[test]
fn head_with_range_plans_no_body() {
    let p = plan(RequestFacts {
        head: true,
        range: Some("bytes=0-9"),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (206, BodyPlan::None));
}

#[test]
fn multi_range_is_ignored_full_200() {
    let p = plan(RequestFacts {
        range: Some("bytes=0-1,5-9"),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (200, BodyPlan::Whole));
}

#[test]
fn unsatisfiable_range_is_416_with_star_content_range() {
    let p = plan(RequestFacts {
        range: Some("bytes=5000-"),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (416, BodyPlan::None));
    assert_eq!(header(&p, "content-range").unwrap(), "bytes */1000");
    assert!(header(&p, "etag").is_none());
}

#[test]
fn if_range_matching_strong_etag_applies_range() {
    let tag = etag();
    let p = plan(RequestFacts {
        range: Some("bytes=0-9"),
        if_range: Some(&tag),
        ..Default::default()
    });
    assert_eq!(p.status, 206);
}

#[test]
fn if_range_mismatch_downgrades_to_full_200() {
    let p = plan(RequestFacts {
        range: Some("bytes=0-9"),
        if_range: Some("\"deadbeef-1\""),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (200, BodyPlan::Whole));
}

#[test]
fn if_range_weak_etag_never_matches() {
    let weak = format!("W/{}", etag());
    let p = plan(RequestFacts {
        range: Some("bytes=0-9"),
        if_range: Some(&weak),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

#[test]
fn if_range_exact_date_applies_range_other_dates_do_not() {
    let date = lm();
    let p = plan(RequestFacts {
        range: Some("bytes=0-9"),
        if_range: Some(&date),
        ..Default::default()
    });
    assert_eq!(p.status, 206);
    let p = plan(RequestFacts {
        range: Some("bytes=0-9"),
        if_range: Some("Mon, 07 Nov 1994 00:00:00 GMT"),
        ..Default::default()
    });
    assert_eq!(p.status, 200);
}

#[test]
fn conditionals_precede_range_412_and_304_have_no_range() {
    let tag = etag();
    let p = plan(RequestFacts {
        if_match: Some("\"deadbeef-1\""),
        range: Some("bytes=0-9"),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (412, BodyPlan::None));
    let p = plan(RequestFacts {
        if_none_match: Some(&tag),
        range: Some("bytes=0-9"),
        ..Default::default()
    });
    assert_eq!((p.status, p.body), (304, BodyPlan::None));
    assert!(header(&p, "content-range").is_none());
}

// ---- sidecar representation + Vary ----

#[test]
fn sidecar_representation_uses_sidecar_snapshot_and_encoding() {
    let file = FileFacts {
        len: 400, // the .br file's length, not the identity's
        encoding: Encoding::Brotli,
        vary_applies: true,
        ..facts()
    };
    let p = plan_response(&RequestFacts::default(), &file, &ResponsePolicy::default());
    assert_eq!(header(&p, "content-encoding").unwrap(), "br");
    assert_eq!(header(&p, "content-length").unwrap(), "400");
    assert!(header(&p, "etag").unwrap().ends_with("-br\""));
    // Range applies to the ENCODED bytes.
    let p = plan_response(
        &RequestFacts {
            range: Some("bytes=0-99"),
            ..Default::default()
        },
        &file,
        &ResponsePolicy::default(),
    );
    assert_eq!(header(&p, "content-range").unwrap(), "bytes 0-99/400");
}

#[test]
fn vary_is_on_every_response_when_negotiation_applies_incl_identity_and_304() {
    let file = FileFacts {
        vary_applies: true,
        ..facts()
    }; // identity representation
    let p = plan_response(&RequestFacts::default(), &file, &ResponsePolicy::default());
    assert_eq!(header(&p, "vary").unwrap(), "Accept-Encoding"); // identity 200
    let tag = headers::etag(MTIME, NSEC, LEN, Encoding::Identity);
    let p = plan_response(
        &RequestFacts {
            if_none_match: Some(&tag),
            ..Default::default()
        },
        &file,
        &ResponsePolicy::default(),
    );
    assert_eq!(header(&p, "vary").unwrap(), "Accept-Encoding"); // 304 too
    let p = plan_response(
        &RequestFacts {
            range: Some("bytes=9999-"),
            ..Default::default()
        },
        &file,
        &ResponsePolicy::default(),
    );
    assert_eq!(header(&p, "vary").unwrap(), "Accept-Encoding"); // even 416
}

// ---- directory semantics (design D3, /F14) ----

#[test]
fn directory_dispatch_matrix() {
    assert_eq!(directory_action(true, true), DirectoryAction::ServeIndex);
    assert_eq!(
        directory_action(false, true),
        DirectoryAction::RedirectAddSlash
    );
    assert_eq!(directory_action(true, false), DirectoryAction::Miss);
    assert_eq!(directory_action(false, false), DirectoryAction::Miss);
}

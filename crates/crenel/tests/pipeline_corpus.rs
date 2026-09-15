//! Hostile-corpus and semantics-pinning tests for the classification pipeline.
//!
//! Every case cites the attack class or review finding it pins. These run on every
//! platform (the pipeline is pure); resolver behavior is covered in `resolve_linux.rs`.

use crenel::pipeline::{
    classify, Candidate, Classification, Mount, Mounts, NotStaticReason, PolicyMiss,
    StructuralReject,
};

fn assets_only() -> Mounts {
    Mounts::new(vec![Mount::new("/assets", false).unwrap()]).unwrap()
}

fn root_and_assets() -> Mounts {
    Mounts::new(vec![
        Mount::new("/", false).unwrap(),
        Mount::new("/assets", false).unwrap(),
    ])
    .unwrap()
}

fn candidate(c: &Classification) -> &Candidate {
    match c {
        Classification::Candidate(c) => c,
        other => panic!("expected candidate, got {other:?}"),
    }
}

#[test]
fn plain_hit_under_mount() {
    let c = classify("GET", "/assets/app-abc123.js", &assets_only());
    let c = candidate(&c);
    assert_eq!(
        (c.mount, c.rel_path.as_str(), c.trailing_slash),
        (0, "app-abc123.js", false)
    );
}

#[test]
fn head_is_eligible_other_methods_are_not() {
    let mounts = assets_only();
    assert!(matches!(
        classify("HEAD", "/assets/a.js", &mounts),
        Classification::Candidate(_)
    ));
    for method in ["POST", "PUT", "DELETE", "OPTIONS", "PATCH", "get", "Get"] {
        assert_eq!(
            classify(method, "/assets/a.js", &mounts),
            Classification::NotStatic(NotStaticReason::MethodNotGetOrHead),
            "method {method} must not be static-eligible (case-sensitive per RFC 9110)"
        );
    }
}

#[test]
fn non_origin_form_targets_are_classified_not_guessed() {
    // absolute-form, OPTIONS-*, and empty targets get an explicit disposition.
    let mounts = assets_only();
    for target in ["*", "http://evil.example/assets/a.js", "", "assets/a.js"] {
        assert_eq!(
            classify("GET", target, &mounts),
            Classification::NotStatic(NotStaticReason::NonOriginForm),
            "target {target:?}"
        );
    }
}

#[test]
fn traversal_is_rejected_in_every_encoding() {
    // CVE-2013-4547/decode-order class + RUSTSEC PathBuf-push class: all '..' spellings
    // must land in the same mount-independent Reject, matched mount or not.
    let mounts = root_and_assets();
    for target in [
        "/assets/../etc/passwd",
        "/assets/%2e%2e/etc/passwd",
        "/assets/..%2fetc%2fpasswd",
        "/assets%2f..%2fetc%2fpasswd",
        "/..",
        "/../",
        "/a/../../b",
        "/%2e%2e",
        "/assets/.%2e/x", // ".̣." assembled from '.' + %2e
    ] {
        assert_eq!(
            classify("GET", target, &mounts),
            Classification::Reject(StructuralReject::DotDotComponent),
            "target {target:?}"
        );
    }
}

#[test]
fn rejects_are_mount_independent_no_oracle() {
    // the same hostile path must classify identically whether or not it sits
    // under a configured mount — otherwise the status differential enumerates mounts.
    let mounts = assets_only();
    assert_eq!(
        classify("GET", "/not-a-mount/../x", &mounts),
        Classification::Reject(StructuralReject::DotDotComponent)
    );
    assert_eq!(
        classify("GET", "/not-a-mount/%00", &mounts),
        Classification::Reject(StructuralReject::NulByte)
    );
}

#[test]
fn nul_control_utf8_and_escape_screens() {
    let mounts = assets_only();
    assert_eq!(
        classify("GET", "/assets/a%00.js", &mounts),
        Classification::Reject(StructuralReject::NulByte)
    );
    // CRLF and other decoded controls: kills Location-header injection at the source (F14).
    for target in ["/assets/a%0d%0ax", "/assets/a%09b", "/assets/a%7fb"] {
        assert_eq!(
            classify("GET", target, &mounts),
            Classification::Reject(StructuralReject::ControlByte),
            "target {target:?}"
        );
    }
    assert_eq!(
        classify("GET", "/assets/a%ff.js", &mounts),
        Classification::Reject(StructuralReject::NotUtf8)
    );
    for target in ["/assets/a%zz", "/assets/a%4", "/assets/a%"] {
        assert_eq!(
            classify("GET", target, &mounts),
            Classification::Reject(StructuralReject::InvalidEscape),
            "target {target:?}"
        );
    }
}

#[test]
fn off_by_slash_cannot_match_a_mount() {
    // The alias/off-by-slash class (Orange Tsai 2018; baseline item 8): "/assets../x"
    // must not match mount "/assets" — segment comparison makes this structural.
    let mounts = assets_only();
    assert_eq!(
        classify("GET", "/assets../secret", &mounts),
        Classification::NotStatic(NotStaticReason::NoMountMatched)
    );
    assert_eq!(
        classify("GET", "/assetsx/y", &mounts),
        Classification::NotStatic(NotStaticReason::NoMountMatched)
    );
}

#[test]
fn duplicate_slash_merge_and_interior_dot_drop_are_pinned() {
    // these normalizations are deliberate nginx-parity choices, not accidents.
    let mounts = assets_only();
    let c = classify("GET", "//assets///sub//app.js", &mounts);
    assert_eq!(candidate(&c).rel_path, "sub/app.js");
    let c = classify("GET", "/./assets/./sub/./app.js", &mounts);
    assert_eq!(candidate(&c).rel_path, "sub/app.js");
    let c = classify("GET", "/assets/%2e/app.js", &mounts);
    assert_eq!(candidate(&c).rel_path, "app.js");
}

#[test]
fn trailing_slash_flag_survives_normalization() {
    // components-style processing erases the trailing slash; we keep it.
    let mounts = assets_only();
    assert!(candidate(&classify("GET", "/assets/dir/", &mounts)).trailing_slash);
    assert!(!candidate(&classify("GET", "/assets/dir", &mounts)).trailing_slash);
    let c = classify("GET", "/assets/", &mounts);
    let c = candidate(&c);
    assert_eq!((c.rel_path.as_str(), c.trailing_slash), ("", true));
    let c = classify("GET", "/assets", &mounts);
    let c = candidate(&c);
    assert_eq!((c.rel_path.as_str(), c.trailing_slash), ("", false));
}

#[test]
fn query_splits_on_raw_question_mark_only() {
    // %3F decodes to a filename byte and cannot shift the query boundary.
    let mounts = assets_only();
    let c = classify("GET", "/assets/app.js?v=123&x=%2e%2e", &mounts);
    assert_eq!(candidate(&c).rel_path, "app.js");
    let c = classify("GET", "/assets/app%3Fv=1.js", &mounts);
    assert_eq!(candidate(&c).rel_path, "app?v=1.js");
}

#[test]
fn encoded_slash_behaves_as_separator_in_the_one_pipeline() {
    // with a single parser there is no router-vs-engine differential; %2F is a
    // separator everywhere, so it can neither create nor erase a mount boundary
    // *differentially*. Both spellings classify identically.
    let mounts = assets_only();
    let a = classify("GET", "/assets/sub%2Fapp.js", &mounts);
    let b = classify("GET", "/assets/sub/app.js", &mounts);
    assert_eq!(a, b);
    assert_eq!(candidate(&a).rel_path, "sub/app.js");
    // And an encoded prefix spelling matches the same mount as the literal one.
    let a = classify("GET", "/%61ssets/app.js", &mounts); // %61 = 'a'
    let b = classify("GET", "/assets/app.js", &mounts);
    assert_eq!(
        a, b,
        "encoded and literal mount spellings must classify identically"
    );
}

#[test]
fn dotfiles_are_a_policy_miss_not_a_reject() {
    //  verdict: dotfile denial is a MISS (per-mount on_miss dispatch), because
    // /.well-known etc. are legitimate app namespace under a fallthrough mount.
    let mounts = root_and_assets();
    assert_eq!(
        classify("GET", "/.well-known/acme-challenge/tok", &mounts),
        Classification::Miss {
            mount: 0,
            reason: PolicyMiss::DotfileDenied
        }
    );
    assert_eq!(
        classify("GET", "/assets/.hidden", &mounts),
        Classification::Miss {
            mount: 1,
            reason: PolicyMiss::DotfileDenied
        }
    );
    // Dot ANYWHERE below the mount, not just the first segment.
    assert_eq!(
        classify("GET", "/assets/sub/.git/config", &mounts),
        Classification::Miss {
            mount: 1,
            reason: PolicyMiss::DotfileDenied
        }
    );
    // Opt-in mount serves dotfiles.
    let permissive = Mounts::new(vec![Mount::new("/assets", true).unwrap()]).unwrap();
    assert!(matches!(
        classify("GET", "/assets/.hidden", &permissive),
        Classification::Candidate(_)
    ));
}

#[test]
fn longest_prefix_wins_and_matching_is_case_sensitive() {
    let mounts = root_and_assets();
    assert_eq!(
        candidate(&classify("GET", "/assets/a.js", &mounts)).mount,
        1
    );
    assert_eq!(candidate(&classify("GET", "/other/page", &mounts)).mount, 0);
    // Case-sensitivity: Unix semantics; case-insensitive filesystems are refused at boot
    // by the resolver, not papered over here (baseline item 11).
    let strict = assets_only();
    assert_eq!(
        classify("GET", "/ASSETS/a.js", &strict),
        Classification::NotStatic(NotStaticReason::NoMountMatched)
    );
}

#[test]
fn candidate_rel_path_invariants_hold() {
    // The resolver's contract: no leading '/', no empty/'.'/'..' segments, no controls.
    let mounts = root_and_assets();
    for target in [
        "/assets/a/b/c.js",
        "/assets//x/./y.png",
        "/deep/nested/path/file.woff2",
        "/assets/%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82.js", // valid UTF-8 (cyrillic)
    ] {
        if let Classification::Candidate(c) = classify("GET", target, &mounts) {
            assert!(!c.rel_path.starts_with('/'), "{target}");
            for seg in c.rel_path.split('/').filter(|s| !s.is_empty()) {
                assert_ne!(seg, ".");
                assert_ne!(seg, "..");
                assert!(seg.bytes().all(|b| b >= 0x20 && b != 0x7f), "{target}");
            }
            assert!(!c.rel_path.contains("//"), "{target}");
        } else {
            panic!("expected candidate for {target}");
        }
    }
}

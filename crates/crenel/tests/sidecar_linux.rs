//! Linux resolver sidecar tests: the uncompressed-must-exist rule and preference-order
//! selection through the same openat2 discipline.
#![cfg(target_os = "linux")]

use std::fs;

use crenel::resolve::{Outcome, Root, SymlinkPolicy};
use crenel::sidecar::Encoding;

fn root_with(files: &[(&str, &[u8])]) -> (tempfile::TempDir, Root) {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, contents) in files {
        fs::write(dir.path().join(name), contents).expect("write");
    }
    let root = Root::pin(dir.path(), SymlinkPolicy::Deny).expect("pin");
    (dir, root)
}

const PREFER_BR_GZ: &[Encoding] = &[Encoding::Brotli, Encoding::Gzip];

#[test]
fn preferred_existing_sidecar_is_selected_with_its_own_snapshot() {
    let (_dir, root) = root_with(&[
        ("app.js", b"var x = 1; // identity, twelve bytes plus"),
        ("app.js.br", b"BR"),
        ("app.js.gz", b"GZIPGZ"),
    ]);
    let out = root.open_encoded("app.js", PREFER_BR_GZ);
    assert!(matches!(out.identity, Outcome::File(_)));
    let (encoding, file) = out.sidecar.expect("sidecar selected");
    assert_eq!(encoding, Encoding::Brotli);
    assert_eq!(file.len, 2); // the SIDECAR fd's fstat, not the identity's
}

#[test]
fn preference_order_falls_through_to_existing_encoding() {
    let (_dir, root) = root_with(&[("app.js", b"identity"), ("app.js.gz", b"GZ")]);
    let out = root.open_encoded("app.js", PREFER_BR_GZ);
    let (encoding, _) = out.sidecar.expect("gz selected");
    assert_eq!(encoding, Encoding::Gzip);
}

#[test]
fn empty_preference_serves_identity_only() {
    let (_dir, root) = root_with(&[("app.js", b"identity"), ("app.js.br", b"BR")]);
    let out = root.open_encoded("app.js", &[]);
    assert!(matches!(out.identity, Outcome::File(_)));
    assert!(out.sidecar.is_none());
}

#[test]
fn sidecar_without_uncompressed_original_is_never_served() {
    // A stray x.br must not shadow a deleted x (Caddy rule): identity resolution is
    // authoritative, and the miss propagates as the outcome.
    let (_dir, root) = root_with(&[("gone.js.br", b"BR")]);
    let out = root.open_encoded("gone.js", PREFER_BR_GZ);
    assert!(matches!(out.identity, Outcome::Miss(_)));
    assert!(out.sidecar.is_none());
}

#[test]
fn directory_outcome_gets_no_sidecar_probe() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("docs")).expect("mkdir");
    let root = Root::pin(dir.path(), SymlinkPolicy::Deny).expect("pin");
    let out = root.open_encoded("docs", PREFER_BR_GZ);
    assert!(matches!(out.identity, Outcome::Directory));
    assert!(out.sidecar.is_none());
    // The pinned-root rel ("") likewise: directory, no ".br" nonsense appended.
    let out = root.open_encoded("", PREFER_BR_GZ);
    assert!(matches!(out.identity, Outcome::Directory));
    assert!(out.sidecar.is_none());
}

#[test]
fn open_encoded_with_identity_matches_open_encoded_and_never_reresolves_identity() {
    // contract: threading a pre-resolved identity outcome through must be
    // indistinguishable from open_encoded — sidecars still probed on File, never on
    // Miss — because the serve loop's dispatch resolution is now REUSED instead of
    // discarded (the earlier double-resolution cost one openat2 per request).
    let (_dir, root) = root_with(&[("app.js", b"identity"), ("app.js.br", b"BR")]);

    let identity = root.open_rel("app.js");
    let threaded = root.open_encoded_with_identity("app.js", PREFER_BR_GZ, identity);
    assert!(matches!(threaded.identity, Outcome::File(_)));
    let (encoding, _) = threaded
        .sidecar
        .expect("sidecar probed for a File identity");
    assert_eq!(encoding, Encoding::Brotli);

    // A Miss identity threads through untouched and suppresses sidecar probing —
    // the Caddy rule survives the refactor.
    let miss = root.open_rel("gone.js");
    let threaded = root.open_encoded_with_identity("gone.js", PREFER_BR_GZ, miss);
    assert!(matches!(threaded.identity, Outcome::Miss(_)));
    assert!(threaded.sidecar.is_none());
}

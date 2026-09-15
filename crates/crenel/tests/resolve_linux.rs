//! Resolver behavior tests: openat2 containment, errno taxonomy, boot audit,
//! deploy-coupled re-pin, and the FIFO non-blocking guarantee. Linux-only.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::{Duration, Instant};

use crenel::resolve::{MissKind, Outcome, Root, RootError, SymlinkPolicy};
use tempfile::TempDir;

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn served_bytes(outcome: Outcome) -> (String, u64, u64) {
    match outcome {
        Outcome::File(served) => {
            let len = served.len;
            let generation = served.generation;
            let mut file = std::fs::File::from(served.fd);
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            (contents, len, generation)
        }
        other => panic!("expected File, got {other:?}"),
    }
}

#[test]
fn serves_regular_file_from_fd_with_snapshot() {
    let tmp = TempDir::new().unwrap();
    write(&tmp.path().join("assets/app.js"), "console.log(1);\n");
    let root = Root::pin(tmp.path(), SymlinkPolicy::Deny).unwrap();
    let (contents, len, generation) = served_bytes(root.open_rel("assets/app.js"));
    assert_eq!(contents, "console.log(1);\n");
    assert_eq!(len, 16);
    assert_eq!(generation, 0);
}

#[test]
fn errno_taxonomy_maps_to_misses() {
    let tmp = TempDir::new().unwrap();
    write(&tmp.path().join("file.txt"), "x");
    let root = Root::pin(tmp.path(), SymlinkPolicy::Deny).unwrap();

    assert!(matches!(
        root.open_rel("absent.txt"),
        Outcome::Miss(MissKind::NotFound)
    ));
    // Path THROUGH a regular file -> ENOTDIR.
    assert!(matches!(
        root.open_rel("file.txt/deeper"),
        Outcome::Miss(MissKind::NotDir)
    ));
    // Directories are a distinct outcome (index semantics live in ).
    assert!(matches!(root.open_rel(""), Outcome::Directory));
    fs::create_dir(tmp.path().join("dir")).unwrap();
    assert!(matches!(root.open_rel("dir"), Outcome::Directory));
}

#[test]
fn contract_violations_are_faults_not_opens() {
    let tmp = TempDir::new().unwrap();
    let root = Root::pin(tmp.path(), SymlinkPolicy::Deny).unwrap();
    for hostile in ["/etc/passwd", "a/../b", "a//b", ".", "a/./b", "a\0b"] {
        assert!(
            matches!(root.open_rel(hostile), Outcome::Fault(_)),
            "rel {hostile:?} must be rejected by the contract check"
        );
    }
}

#[test]
fn symlinks_created_after_pin_are_contained_at_request_time() {
    // The boot audit catches pre-existing links; these appear post-pin (deploy drift)
    // and must be contained by openat2 itself — the no-TOCTOU property.
    let tmp = TempDir::new().unwrap();
    write(&tmp.path().join("real.txt"), "real");

    let deny = Root::pin(tmp.path(), SymlinkPolicy::Deny).unwrap();
    symlink("real.txt", tmp.path().join("alias.txt")).unwrap();
    symlink("/etc/passwd", tmp.path().join("evil.txt")).unwrap();
    assert!(matches!(
        deny.open_rel("alias.txt"),
        Outcome::Miss(MissKind::SymlinkDenied)
    ));
    assert!(matches!(
        deny.open_rel("evil.txt"),
        Outcome::Miss(MissKind::SymlinkDenied)
    ));

    // AllowWithinRoot: in-tree links resolve, escapes are EXDEV.
    let tmp2 = TempDir::new().unwrap();
    write(&tmp2.path().join("real.txt"), "real");
    let allow = Root::pin(tmp2.path(), SymlinkPolicy::AllowWithinRoot).unwrap();
    symlink("real.txt", tmp2.path().join("alias.txt")).unwrap();
    symlink("/etc/passwd", tmp2.path().join("evil.txt")).unwrap();
    symlink("../../../etc/passwd", tmp2.path().join("climb.txt")).unwrap();
    let (contents, _, _) = served_bytes(allow.open_rel("alias.txt"));
    assert_eq!(contents, "real");
    assert!(matches!(
        allow.open_rel("evil.txt"),
        Outcome::Miss(MissKind::EscapesRoot)
    ));
    assert!(matches!(
        allow.open_rel("climb.txt"),
        Outcome::Miss(MissKind::EscapesRoot)
    ));
}

#[test]
fn boot_audit_fails_closed_on_policy_hostile_symlinks() {
    // the Capistrano linked_dirs failure mode must be a loud boot error,
    // not silent request-time 404s.
    let tmp = TempDir::new().unwrap();
    write(&tmp.path().join("sub/file.txt"), "x");
    symlink("/srv/shared/assets", tmp.path().join("sub/linked")).unwrap();

    match Root::pin(tmp.path(), SymlinkPolicy::AllowWithinRoot) {
        Err(RootError::HostileSymlinks { entries }) => {
            assert!(
                entries.iter().any(|e| e.contains("linked")),
                "entries: {entries:?}"
            );
        }
        other => panic!("expected HostileSymlinks, got {other:?}"),
    }
    // Under Deny, ANY symlink is hostile at boot — even an in-tree relative one.
    let tmp2 = TempDir::new().unwrap();
    write(&tmp2.path().join("real.txt"), "x");
    symlink("real.txt", tmp2.path().join("alias.txt")).unwrap();
    assert!(matches!(
        Root::pin(tmp2.path(), SymlinkPolicy::Deny),
        Err(RootError::HostileSymlinks { .. })
    ));
    // In-tree relative link is fine under AllowWithinRoot; dangling is fine too
    // (request-time ENOENT, not a boot failure).
    let tmp3 = TempDir::new().unwrap();
    write(&tmp3.path().join("real.txt"), "x");
    symlink("real.txt", tmp3.path().join("alias.txt")).unwrap();
    symlink("gone.txt", tmp3.path().join("dangling.txt")).unwrap();
    let root = Root::pin(tmp3.path(), SymlinkPolicy::AllowWithinRoot).unwrap();
    assert!(matches!(
        root.open_rel("dangling.txt"),
        Outcome::Miss(MissKind::NotFound)
    ));
}

#[test]
fn writerless_fifo_returns_immediately_as_not_regular() {
    // without O_NONBLOCK this test hangs forever and a production docroot
    // FIFO permanently eats blocking-pool threads. Bound: well under 2s.
    let tmp = TempDir::new().unwrap();
    let root = Root::pin(tmp.path(), SymlinkPolicy::Deny).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        tmp.path().join("trap.fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let start = Instant::now();
    let outcome = root.open_rel("trap.fifo");
    let elapsed = start.elapsed();
    assert!(
        matches!(outcome, Outcome::Miss(MissKind::NotRegular)),
        "got {outcome:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "FIFO open took {elapsed:?} — O_NONBLOCK regression"
    );
}

#[test]
fn deploy_flip_repins_with_generation_bump_and_old_fd_survival() {
    // the Capistrano current -> releases/N flip. Old in-flight fds must keep
    // working; the new pin must serve the new release; generation must bump for caches.
    let tmp = TempDir::new().unwrap();
    write(&tmp.path().join("releases/A/a.txt"), "release A");
    write(&tmp.path().join("releases/B/b.txt"), "release B");
    let current = tmp.path().join("current");
    symlink(tmp.path().join("releases/A"), &current).unwrap();

    let root = Root::pin(&current, SymlinkPolicy::Deny).unwrap();
    assert_eq!(root.generation(), 0);
    assert!(root.canonical().ends_with("releases/A"));

    // Hold an fd across the flip (an in-flight download).
    let inflight = match root.open_rel("a.txt") {
        Outcome::File(f) => f,
        other => panic!("expected File, got {other:?}"),
    };

    // No-op check first: nothing changed, no re-pin.
    assert!(!root.check_repin().unwrap());

    // Atomic flip exactly as Capistrano does it: new symlink + rename over.
    let staging = tmp.path().join("current.new");
    symlink(tmp.path().join("releases/B"), &staging).unwrap();
    fs::rename(&staging, &current).unwrap();

    assert!(root.check_repin().unwrap());
    assert_eq!(root.generation(), 1);
    assert!(root.canonical().ends_with("releases/B"));

    // New tree serves; old name is gone in the new tree.
    let (contents, _, generation) = served_bytes(root.open_rel("b.txt"));
    assert_eq!((contents.as_str(), generation), ("release B", 1));
    assert!(matches!(
        root.open_rel("a.txt"),
        Outcome::Miss(MissKind::NotFound)
    ));

    // The in-flight fd from release A still reads fine (ArcSwap handoff kept it alive).
    let mut old = std::fs::File::from(inflight.fd);
    let mut contents = String::new();
    old.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "release A");
}

#[test]
fn repin_fails_closed_if_new_tree_is_hostile() {
    // A deploy that introduces policy-hostile symlinks must fail the re-pin (and the
    // old pin keeps serving) rather than fail open.
    let tmp = TempDir::new().unwrap();
    write(&tmp.path().join("releases/A/a.txt"), "A");
    write(&tmp.path().join("releases/C/c.txt"), "C");
    symlink("/etc", tmp.path().join("releases/C/evil")).unwrap();
    let current = tmp.path().join("current");
    symlink(tmp.path().join("releases/A"), &current).unwrap();

    let root = Root::pin(&current, SymlinkPolicy::Deny).unwrap();
    let staging = tmp.path().join("current.new");
    symlink(tmp.path().join("releases/C"), &staging).unwrap();
    fs::rename(&staging, &current).unwrap();

    assert!(matches!(
        root.check_repin(),
        Err(RootError::HostileSymlinks { .. })
    ));
    // Old pin still serves release A.
    assert_eq!(root.generation(), 0);
    let (contents, _, _) = served_bytes(root.open_rel("a.txt"));
    assert_eq!(contents, "A");
}

#[test]
fn nonexistent_or_file_roots_fail_to_pin() {
    let tmp = TempDir::new().unwrap();
    assert!(matches!(
        Root::pin(&tmp.path().join("missing"), SymlinkPolicy::Deny),
        Err(RootError::Io(_))
    ));
    write(&tmp.path().join("file.txt"), "x");
    assert!(matches!(
        Root::pin(&tmp.path().join("file.txt"), SymlinkPolicy::Deny),
        Err(RootError::NotADirectory(_) | RootError::Io(_))
    ));
}

//! nginx golden-fixture harness (design S2 gate): the SAME docroot and request matrix is
//! answered by a real nginx (pinned conf, `tests/fixtures/nginx-golden.conf`) and by the
//! crenel engine (pipeline → resolver → sidecar → plan_response); every mismatch must be
//! either fixed or a cited entry in `docs/DIVERGENCES.md`.
//!
//! Manual-gated: runs only with `CRENEL_NGINX_FIXTURES=1` and
//! a real nginx binary (Linux/WSL: `apt install nginx`). Everything runs unprivileged in
//! a temp prefix on an ephemeral loopback port.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crenel::headers;
use crenel::pipeline::{classify, Classification, Mount, Mounts};
use crenel::resolve::{Outcome, Root, SymlinkPolicy};
use crenel::semantics::{
    directory_action, plan_response, DirectoryAction, FileFacts, RequestFacts, ResponsePolicy,
};
use crenel::sidecar::{negotiate, Encoding};

/// One observed response, from either implementation.
#[derive(Debug, Clone)]
struct Observed {
    status: u16,
    headers: HashMap<String, String>,
}

impl Observed {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// Per-side header values for conditional cases (each side must be probed with its OWN
/// validator — the ETag formats differ by design, ledger D1).
#[derive(Debug, Clone, Copy)]
enum Value {
    Lit(&'static str),
    OwnEtag,
    ForeignEtag,
    LastModified,
    OlderDate,
    NewerDate,
}

#[derive(Debug, Clone, Copy)]
struct Case {
    name: &'static str,
    method: &'static str,
    target: &'static str,
    headers: &'static [(&'static str, Value)],
    /// `None` = statuses must be equal; `Some((nginx, crenel, ledger))` = a documented
    /// divergence, asserted on BOTH sides so ledger drift is caught.
    diverges: Option<(u16, u16, &'static str)>,
}

const CASES: &[Case] = &[
    // ---- plain retrieval ----
    Case {
        name: "basic_txt_200",
        method: "GET",
        target: "/a.txt",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "head_txt_200",
        method: "HEAD",
        target: "/a.txt",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "css_content_type",
        method: "GET",
        target: "/style.css",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "no_ext_octet_stream",
        method: "GET",
        target: "/b.bin",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "missing_404",
        method: "GET",
        target: "/nope.txt",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "percent20_name",
        method: "GET",
        target: "/a%20b.txt",
        headers: &[],
        diverges: None,
    },
    // ---- conditionals (each side probed with its own validators) ----
    Case {
        name: "inm_match_304",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-none-match", Value::OwnEtag)],
        diverges: None,
    },
    Case {
        name: "inm_mismatch_200",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-none-match", Value::Lit("\"deadbeef-1\""))],
        diverges: None,
    },
    Case {
        name: "inm_foreign_etag_200",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-none-match", Value::ForeignEtag)],
        diverges: None,
    },
    Case {
        name: "ims_exact_304",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-modified-since", Value::LastModified)],
        diverges: None,
    },
    Case {
        name: "ims_newer_200_exact_semantics",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-modified-since", Value::NewerDate)],
        diverges: None,
    },
    Case {
        name: "ims_older_200",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-modified-since", Value::OlderDate)],
        diverges: None,
    },
    Case {
        name: "if_match_star_200",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-match", Value::Lit("*"))],
        diverges: None,
    },
    Case {
        name: "if_match_mismatch_412",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-match", Value::Lit("\"deadbeef-1\""))],
        diverges: None,
    },
    Case {
        name: "ius_older_412",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-unmodified-since", Value::OlderDate)],
        diverges: None,
    },
    Case {
        name: "ius_equal_200",
        method: "GET",
        target: "/a.txt",
        headers: &[("if-unmodified-since", Value::LastModified)],
        diverges: None,
    },
    // ---- range ----
    Case {
        name: "range_first_500",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=0-499"))],
        diverges: None,
    },
    Case {
        name: "range_open_end",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=500-"))],
        diverges: None,
    },
    Case {
        name: "range_suffix",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=-300"))],
        diverges: None,
    },
    Case {
        name: "range_suffix_longer_than_file",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=-5000"))],
        diverges: None,
    },
    Case {
        name: "range_clamp_end",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=900-99999"))],
        diverges: None,
    },
    Case {
        name: "range_past_eof_416",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=1000-"))],
        diverges: None,
    },
    Case {
        name: "range_inverted_416",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=500-100"))],
        diverges: None,
    },
    Case {
        name: "range_overflow_416_never_wraps",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=99999999999999999999-"))],
        diverges: None,
    },
    Case {
        name: "range_multi_single_range_only",
        method: "GET",
        target: "/a.txt",
        headers: &[("range", Value::Lit("bytes=0-1,5-9"))],
        diverges: Some((206, 200, "D3 single-range-only")),
    },
    Case {
        name: "if_range_own_etag_206",
        method: "GET",
        target: "/a.txt",
        headers: &[
            ("range", Value::Lit("bytes=0-9")),
            ("if-range", Value::OwnEtag),
        ],
        diverges: None,
    },
    Case {
        name: "if_range_mismatch_200",
        method: "GET",
        target: "/a.txt",
        headers: &[
            ("range", Value::Lit("bytes=0-9")),
            ("if-range", Value::Lit("\"deadbeef-1\"")),
        ],
        diverges: None,
    },
    Case {
        name: "if_range_exact_date_206",
        method: "GET",
        target: "/a.txt",
        headers: &[
            ("range", Value::Lit("bytes=0-9")),
            ("if-range", Value::LastModified),
        ],
        diverges: None,
    },
    // ---- precompressed sidecars ----
    Case {
        name: "gzip_sidecar_served",
        method: "GET",
        target: "/app.js",
        headers: &[("accept-encoding", Value::Lit("gzip"))],
        diverges: None,
    },
    Case {
        name: "identity_when_no_ae",
        method: "GET",
        target: "/app.js",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "gzip_refused_q0",
        method: "GET",
        target: "/app.js",
        headers: &[("accept-encoding", Value::Lit("gzip;q=0"))],
        diverges: None,
    },
    // nginx gzip_static serves an ORPHAN .gz (original absent); the Caddy
    // uncompressed-must-exist rule refuses the shadow file.
    Case {
        name: "orphan_sidecar_refused",
        method: "GET",
        target: "/gone.js",
        headers: &[("accept-encoding", Value::Lit("gzip"))],
        diverges: Some((200, 404, "D8 uncompressed-must-exist")),
    },
    // ---- directories ----
    Case {
        name: "dir_redirect_adds_slash",
        method: "GET",
        target: "/docs",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "dir_with_index_served",
        method: "GET",
        target: "/docs/",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "dir_without_index",
        method: "GET",
        target: "/sub/",
        headers: &[],
        diverges: Some((403, 404, "D6 dir-without-index-is-miss")),
    },
    // ---- hostility ----
    Case {
        name: "traversal_above_root_400",
        method: "GET",
        target: "/../etc/passwd",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "interior_dotdot_global_reject",
        method: "GET",
        target: "/docs/../a.txt",
        headers: &[],
        diverges: Some((200, 400, "D4 global-dotdot-reject")),
    },
    Case {
        name: "encoded_dotdot_400",
        method: "GET",
        target: "/%2e%2e/etc/passwd",
        headers: &[],
        diverges: None,
    },
    Case {
        name: "dotfile_denied",
        method: "GET",
        target: "/.hidden.txt",
        headers: &[],
        diverges: Some((200, 404, "D5 dotfile-deny-default")),
    },
    Case {
        name: "null_byte_400",
        method: "GET",
        target: "/a%00.txt",
        headers: &[],
        diverges: None,
    },
    // ---- empty file edges ----
    Case {
        name: "empty_file_200",
        method: "GET",
        target: "/empty.txt",
        headers: &[],
        diverges: None,
    },
    // Range filter bypassed on empty representations (both sides): plain 200.
    Case {
        name: "empty_file_range_bypassed_200",
        method: "GET",
        target: "/empty.txt",
        headers: &[("range", Value::Lit("bytes=0-"))],
        diverges: None,
    },
];

#[test]
fn nginx_golden_fixtures_match_or_cite_ledger() {
    if std::env::var("CRENEL_NGINX_FIXTURES").as_deref() != Ok("1") {
        eprintln!("skipped: set CRENEL_NGINX_FIXTURES=1 (needs nginx on PATH, Linux)");
        return;
    }

    let scratch = tempfile::tempdir().expect("scratch");
    let docroot = scratch.path().join("root");
    build_docroot(&docroot);
    let prefix = scratch.path().join("nginx");
    fs::create_dir_all(&prefix).expect("prefix");

    let port = free_port();
    let conf = render_conf(&prefix, &docroot, port);
    let nginx = NginxGuard::start(&prefix, &conf, port);

    // Per-side validator material for the shared fixture file.
    let nginx_probe = nginx_request(port, "GET", "/a.txt", &[]);
    let nginx_etag = nginx_probe.header("etag").expect("nginx etag").to_string();
    let meta = fs::metadata(docroot.join("a.txt")).expect("meta");
    let (mtime_sec, mtime_nsec) = mtimes(&meta);
    let crenel_etag = headers::etag(mtime_sec, mtime_nsec, meta.len(), Encoding::Identity);
    let lm = headers::last_modified(mtime_sec);
    let older = httpdate::fmt_http_date(headers::system_time_for(mtime_sec - 86_400));
    let newer = httpdate::fmt_http_date(headers::system_time_for(mtime_sec + 86_400));
    // Sanity: both implementations derive Last-Modified from the same inode.
    assert_eq!(nginx_probe.header("last-modified"), Some(lm.as_str()));
    // Ledger D1: deliberately different ETag formats (ns-granular vs second-granular).
    assert_ne!(
        nginx_etag, crenel_etag,
        "ledger D1 evaporated — update DIVERGENCES.md"
    );

    let engine = Engine::new(&docroot);
    let mut failures: Vec<String> = Vec::new();

    for case in CASES {
        let resolve = |value: Value, own: &str| -> String {
            match value {
                Value::Lit(v) => v.to_string(),
                Value::OwnEtag => own.to_string(),
                Value::ForeignEtag => {
                    if own == nginx_etag {
                        crenel_etag.clone()
                    } else {
                        nginx_etag.clone()
                    }
                }
                Value::LastModified => lm.clone(),
                Value::OlderDate => older.clone(),
                Value::NewerDate => newer.clone(),
            }
        };
        let nginx_headers: Vec<(String, String)> = case
            .headers
            .iter()
            .map(|(n, v)| (n.to_string(), resolve(*v, &nginx_etag)))
            .collect();
        let crenel_headers: Vec<(String, String)> = case
            .headers
            .iter()
            .map(|(n, v)| (n.to_string(), resolve(*v, &crenel_etag)))
            .collect();

        let from_nginx = nginx_request(port, case.method, case.target, &nginx_headers);
        let from_crenel = engine.answer(case.method, case.target, &crenel_headers);

        match case.diverges {
            None => {
                if from_nginx.status != from_crenel.status {
                    failures.push(format!(
                        "{}: status nginx={} crenel={} (undocumented divergence)",
                        case.name, from_nginx.status, from_crenel.status
                    ));
                    continue;
                }
                // Semantics-bearing headers must agree wherever both sides succeed.
                // content-type compares as MEDIA TYPE only: crenel's table bakes in
                // `; charset=utf-8` for text types (additive hardening, uncompared).
                for name in [
                    "last-modified",
                    "content-range",
                    "content-length",
                    "content-type",
                    "content-encoding",
                ] {
                    let strip = |v: Option<&str>| -> Option<String> {
                        v.map(|v| {
                            if name == "content-type" {
                                v.split(';').next().unwrap_or(v).trim().to_string()
                            } else {
                                v.to_string()
                            }
                        })
                    };
                    let (a, b) = (
                        strip(from_nginx.header(name)),
                        strip(from_crenel.header(name)),
                    );
                    if matches!(from_nginx.status, 200 | 206 | 304 | 416) && a != b {
                        // 304/416 header sets legitimately differ in breadth; only flag
                        // when BOTH sides emitted the header with different values.
                        if a.is_some() && b.is_some() {
                            failures.push(format!(
                                "{}: header {name} nginx={a:?} crenel={b:?}",
                                case.name
                            ));
                        }
                    }
                }
            }
            Some((expect_nginx, expect_crenel, ledger)) => {
                if from_nginx.status != expect_nginx || from_crenel.status != expect_crenel {
                    failures.push(format!(
                        "{}: ledger {ledger} drifted — expected nginx={expect_nginx} \
                         crenel={expect_crenel}, got nginx={} crenel={}",
                        case.name, from_nginx.status, from_crenel.status
                    ));
                }
            }
        }
    }

    drop(nginx);
    assert!(
        failures.is_empty(),
        "golden mismatches:\n{}",
        failures.join("\n")
    );
}

// ---- fixture docroot ----

fn build_docroot(root: &Path) {
    fs::create_dir_all(root).expect("docroot");
    let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    fs::write(root.join("a.txt"), &body).expect("a.txt");
    fs::write(root.join("a b.txt"), b"space name").expect("a b.txt");
    fs::write(root.join("style.css"), b"body{color:#333}").expect("css");
    fs::write(root.join("b.bin"), b"\x00\x01\x02").expect("bin");
    fs::write(
        root.join("app.js"),
        b"var x = 1; // identity representation",
    )
    .expect("js");
    fs::write(root.join("app.js.gz"), b"\x1f\x8b\x08\x00FAKEGZIPBYTES").expect("js.gz");
    fs::write(root.join("gone.js.gz"), b"\x1f\x8b\x08\x00ORPHAN").expect("orphan gz");
    fs::write(root.join(".hidden.txt"), b"secret").expect("dotfile");
    fs::write(root.join("empty.txt"), b"").expect("empty");
    fs::create_dir_all(root.join("docs")).expect("docs");
    fs::write(root.join("docs/index.html"), b"<h1>idx</h1>").expect("index");
    fs::create_dir_all(root.join("sub")).expect("sub");
}

fn mtimes(meta: &fs::Metadata) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (meta.mtime(), meta.mtime_nsec())
}

// ---- crenel side: pipeline -> resolver -> sidecar -> plan ----

struct Engine {
    mounts: Mounts,
    root: Root,
}

impl Engine {
    fn new(docroot: &Path) -> Engine {
        let mounts =
            Mounts::new(vec![Mount::new("/", false).expect("mount")]).expect("mount table");
        // AllowWithinRoot: the fixture tree has no symlinks; Deny would also work, but
        // this mirrors the preset the golden claim describes.
        let root = Root::pin(docroot, SymlinkPolicy::AllowWithinRoot).expect("pin");
        Engine { mounts, root }
    }

    fn answer(&self, method: &str, target: &str, request_headers: &[(String, String)]) -> Observed {
        let get = |name: &str| -> Option<&str> {
            request_headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let candidate = match classify(method, target, &self.mounts) {
            Classification::Candidate(c) => c,
            Classification::Reject(_) => return simple(400),
            Classification::Miss { .. } => return simple(404),
            Classification::NotStatic(_) => return simple(404), // no app behind the harness
        };

        // Directory dispatch first (index enabled for every fixture mount).
        let rel = match self.root.open_rel(&candidate.rel_path) {
            Outcome::Directory => match directory_action(candidate.trailing_slash, true) {
                DirectoryAction::Miss => return simple(404),
                DirectoryAction::RedirectAddSlash => {
                    let location = headers::redirect_location(
                        self.mounts.get(candidate.mount).prefix(),
                        &candidate.rel_path,
                        None,
                    );
                    let mut observed = simple(301);
                    observed.headers.insert("location".into(), location);
                    return observed;
                }
                DirectoryAction::ServeIndex => {
                    if candidate.rel_path.is_empty() {
                        "index.html".to_string()
                    } else {
                        format!("{}/index.html", candidate.rel_path)
                    }
                }
            },
            _ => candidate.rel_path.clone(),
        };

        let preference = negotiate(get("accept-encoding"));
        let encoded = self.root.open_encoded(&rel, &preference);
        let (encoding, file) = match encoded.identity {
            Outcome::File(identity_file) => match encoded.sidecar {
                Some((encoding, sidecar)) => (encoding, sidecar),
                None => (Encoding::Identity, identity_file),
            },
            Outcome::Miss(_) => return simple(404),
            Outcome::Directory => return simple(404), // index.html was itself a dir
            Outcome::Shed => return simple(503),
            Outcome::Fault(_) => return simple(500),
        };

        let facts = FileFacts {
            len: file.len,
            mtime_sec: file.mtime_sec,
            mtime_nsec: file.mtime_nsec,
            encoding,
            vary_applies: true, // gzip_static-equivalent negotiation is on for the mount
            content_type: headers::content_type_for(&rel),
        };
        let req = RequestFacts {
            head: method == "HEAD",
            if_match: get("if-match"),
            if_none_match: get("if-none-match"),
            if_modified_since: get("if-modified-since"),
            if_unmodified_since: get("if-unmodified-since"),
            if_range: get("if-range"),
            range: get("range"),
        };
        let plan = plan_response(&req, &facts, &ResponsePolicy::default());
        let mut observed = simple(plan.status);
        for (name, value) in plan.headers {
            observed.headers.insert(name.to_string(), value);
        }
        observed
    }
}

fn simple(status: u16) -> Observed {
    Observed {
        status,
        headers: HashMap::new(),
    }
}

// ---- nginx side: process control + raw HTTP/1.1 ----

struct NginxGuard {
    prefix: PathBuf,
    conf: PathBuf,
}

impl NginxGuard {
    fn start(prefix: &Path, conf: &Path, port: u16) -> NginxGuard {
        // nginx probes <prefix>/logs/error.log before reading the error_log directive.
        fs::create_dir_all(prefix.join("logs")).expect("logs dir");
        let out = Command::new("nginx")
            .args(["-p"])
            .arg(prefix)
            .args(["-c"])
            .arg(conf)
            .output()
            .expect("nginx binary present (apt install nginx)");
        assert!(
            out.status.success(),
            "nginx failed to start: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "nginx never came up on {port}");
            std::thread::sleep(Duration::from_millis(50));
        }
        NginxGuard {
            prefix: prefix.to_path_buf(),
            conf: conf.to_path_buf(),
        }
    }
}

impl Drop for NginxGuard {
    fn drop(&mut self) {
        let _ = Command::new("nginx")
            .args(["-p"])
            .arg(&self.prefix)
            .args(["-c"])
            .arg(&self.conf)
            .args(["-s", "stop"])
            .output();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn render_conf(prefix: &Path, docroot: &Path, port: u16) -> PathBuf {
    let template = include_str!("fixtures/nginx-golden.conf");
    let rendered = template
        .replace("{{PREFIX}}", &prefix.display().to_string())
        .replace("{{ROOT}}", &docroot.display().to_string())
        .replace("{{PORT}}", &port.to_string());
    let path = prefix.join("nginx-golden.conf");
    fs::write(&path, rendered).expect("write conf");
    path
}

fn nginx_request(
    port: u16,
    method: &str,
    target: &str,
    request_headers: &[(String, String)],
) -> Observed {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request =
        format!("{method} {target} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n");
    for (name, value) in request_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).expect("send");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Observed {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut response_headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            response_headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Observed {
        status,
        headers: response_headers,
    }
}

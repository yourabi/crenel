//! End-to-end tests: spawn the real `crenel-serve` binary (pingora server, real TCP) on
//! an ephemeral port over a temp docroot, drive it with a raw HTTP/1.1 client.
//! Framing-aware client (Content-Length reads) so keepalive reuse is provable.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ---- fixture server ----

struct TestServer {
    child: Child,
    port: u16,
    _docroot: tempfile::TempDir,
}

impl TestServer {
    fn start(extra_args: &[&str], mounts: &[String], docroot: tempfile::TempDir) -> TestServer {
        let port = free_port();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_crenel-serve"));
        cmd.arg("--bind").arg(format!("127.0.0.1:{port}"));
        for mount in mounts {
            cmd.arg("--mount").arg(mount);
        }
        cmd.args(extra_args);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn crenel-serve");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "crenel-serve never came up");
            std::thread::sleep(Duration::from_millis(50));
        }
        TestServer {
            child,
            port,
            _docroot: docroot,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Standard docroot with small/large/sidecar/dir/hostile fixtures. Returns the large
/// file's bytes for integrity comparison.
fn build_docroot() -> (tempfile::TempDir, Vec<u8>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fs::write(root.join("small.txt"), b"hello crenel").unwrap();
    fs::write(root.join("app.js"), b"var x = 1; // identity bytes here").unwrap();
    fs::write(root.join("app.js.gz"), b"\x1f\x8b\x08\x00FAKEGZ").unwrap();
    fs::create_dir(root.join("docs")).unwrap();
    fs::write(root.join("docs/index.html"), b"<h1>idx</h1>").unwrap();
    fs::create_dir(root.join("assets")).unwrap();
    fs::write(root.join("assets/app-abc.css"), b"body{}").unwrap();
    // 8 MiB deterministic pattern: exercises the reader-task (streamed) path.
    let large: Vec<u8> = (0..8 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
    fs::write(root.join("large.bin"), &large).unwrap();
    (dir, large)
}

fn default_server() -> (TestServer, Vec<u8>) {
    let (docroot, large) = build_docroot();
    let root = docroot.path().display().to_string();
    let mounts = vec![
        format!("/={root},index,fallthrough"),
        format!(
            "/assets={}/assets,cache-control=public%2Cmax-age=31536000",
            root
        ),
    ];
    (TestServer::start(&[], &mounts, docroot), large)
}

// ---- framing-aware raw client ----

#[derive(Debug)]
struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
}

fn send_request(stream: &mut TcpStream, method: &str, target: &str, headers: &[(&str, &str)]) {
    let mut request = format!("{method} {target} HTTP/1.1\r\nhost: localhost\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).expect("send");
}

/// Read exactly one framed response (status line + headers + Content-Length body).
fn read_response(stream: &mut TcpStream, head_only: bool) -> Response {
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => buf.push(byte[0]),
            other => panic!("header read failed: {other:?} after {} bytes", buf.len()),
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("status line");
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let mut body = Vec::new();
    if !head_only {
        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        body.resize(content_length, 0);
        stream.read_exact(&mut body).expect("body read");
    }
    Response {
        status,
        headers,
        body,
    }
}

fn get(port: u16, target: &str, headers: &[(&str, &str)]) -> Response {
    let mut stream = connect(port);
    send_request(&mut stream, "GET", target, headers);
    read_response(&mut stream, false)
}

// ---- tests ----

#[test]
fn small_file_200_with_full_header_contract() {
    let (server, _) = default_server();
    let r = get(server.port, "/small.txt", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"hello crenel");
    assert_eq!(
        r.header("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(r.header("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(r.header("accept-ranges").unwrap(), "bytes");
    assert!(r.header("etag").unwrap().starts_with('"'));
    assert!(r.header("last-modified").is_some());
    assert_eq!(r.header("vary").unwrap(), "Accept-Encoding");
}

#[test]
fn large_file_streams_intact_through_reader_task() {
    let (server, large) = default_server();
    let r = get(server.port, "/large.bin", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), large.len());
    assert!(r.body == large, "streamed bytes differ from source");
}

#[test]
fn head_reports_length_without_body() {
    let (server, large) = default_server();
    let mut stream = connect(server.port);
    send_request(&mut stream, "HEAD", "/large.bin", &[]);
    let r = read_response(&mut stream, true);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-length").unwrap(), large.len().to_string());
}

#[test]
fn conditional_304_and_range_206_and_416() {
    let (server, _) = default_server();
    let first = get(server.port, "/small.txt", &[]);
    let etag = first.header("etag").unwrap().to_string();
    let r = get(server.port, "/small.txt", &[("if-none-match", &etag)]);
    assert_eq!(r.status, 304);
    assert_eq!(r.header("vary").unwrap(), "Accept-Encoding");

    let r = get(server.port, "/small.txt", &[("range", "bytes=0-4")]);
    assert_eq!(r.status, 206);
    assert_eq!(r.body, b"hello");
    assert_eq!(r.header("content-range").unwrap(), "bytes 0-4/12");

    let r = get(server.port, "/small.txt", &[("range", "bytes=999-")]);
    assert_eq!(r.status, 416);
    assert_eq!(r.header("content-range").unwrap(), "bytes */12");
}

#[test]
fn gzip_sidecar_negotiated_with_sidecar_snapshot() {
    let (server, _) = default_server();
    let r = get(server.port, "/app.js", &[("accept-encoding", "gzip")]);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-encoding").unwrap(), "gzip");
    assert!(r.header("etag").unwrap().ends_with("-gz\""));
    assert_eq!(r.body, b"\x1f\x8b\x08\x00FAKEGZ");
    // Identity when the client refuses gzip.
    let r = get(server.port, "/app.js", &[("accept-encoding", "gzip;q=0")]);
    assert!(r.header("content-encoding").is_none());
    assert_eq!(r.header("vary").unwrap(), "Accept-Encoding");
}

#[test]
fn directory_redirect_then_index() {
    let (server, _) = default_server();
    let r = get(server.port, "/docs", &[]);
    assert_eq!(r.status, 301);
    assert_eq!(r.header("location").unwrap(), "/docs/");
    let r = get(server.port, "/docs/", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"<h1>idx</h1>");
}

#[test]
fn miss_policies_fallthrough_vs_strict() {
    let (server, _) = default_server();
    // "/" mount is fallthrough: the example app marks NotStatic 404s.
    let r = get(server.port, "/nope.txt", &[]);
    assert_eq!(r.status, 404);
    assert_eq!(r.header("x-crenel-fallthrough").unwrap(), "1");
    // "/assets" is strict: engine-owned 404, no fallthrough marker.
    let r = get(server.port, "/assets/nope.css", &[]);
    assert_eq!(r.status, 404);
    assert!(r.header("x-crenel-fallthrough").is_none());
    // Strict mount hit still works + policy header applied.
    let r = get(server.port, "/assets/app-abc.css", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("cache-control").unwrap(),
        "public,max-age=31536000"
    );
}

#[test]
fn hostile_paths_are_fixed_400s() {
    let (server, _) = default_server();
    for target in ["/../etc/passwd", "/%2e%2e/etc/passwd", "/a%00.txt", "/a%zz"] {
        let r = get(server.port, target, &[]);
        assert_eq!(r.status, 400, "target {target:?}");
        assert!(
            r.header("x-crenel-fallthrough").is_none(),
            "{target:?} fell through"
        );
    }
}

#[test]
fn h1_keepalive_serves_two_requests_on_one_connection() {
    let (server, _) = default_server();
    let mut stream = connect(server.port);
    send_request(&mut stream, "GET", "/small.txt", &[]);
    let first = read_response(&mut stream, false);
    assert_eq!(
        (first.status, first.body.as_slice()),
        (200, b"hello crenel".as_slice())
    );
    send_request(&mut stream, "GET", "/docs/", &[]);
    let second = read_response(&mut stream, false);
    assert_eq!(
        (second.status, second.body.as_slice()),
        (200, b"<h1>idx</h1>".as_slice())
    );
}

#[test]
fn slow_reader_is_disconnected_by_response_deadline() {
    // min-throughput huge + floor tiny -> budget collapses to ~2s; write timeout kept
    // above it so the whole-response deadline is what fires.
    let (docroot, _large) = build_docroot();
    let root = docroot.path().display().to_string();
    let server = TestServer::start(
        &[
            "--min-throughput",
            "1000000000",
            "--deadline-floor-secs",
            "2",
            "--write-timeout-secs",
            "30",
        ],
        &[format!("/={root}")],
        docroot,
    );
    let mut stream = connect(server.port);
    send_request(&mut stream, "GET", "/large.bin", &[]);
    // Read a token amount, then stall without draining. 8 MiB >> kernel buffers, so the
    // server-side writer must block and the deadline must kill the connection.
    let mut tiny = [0u8; 1024];
    stream.read_exact(&mut tiny).expect("first KiB");
    let started = Instant::now();
    std::thread::sleep(Duration::from_secs(4)); // sit past the 2s budget
                                                // Drain whatever is buffered; the stream must reach EOF/reset well before the
                                                // 8 MiB body could ever complete at zero drain rate.
    let mut sink = [0u8; 64 * 1024];
    let mut drained = 1024u64;
    let closed = loop {
        match stream.read(&mut sink) {
            Ok(0) => break true, // clean FIN
            Ok(n) => drained += n as u64,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break true,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                break false
            }
            Err(_) => break true,
        }
        if started.elapsed() > Duration::from_secs(30) {
            break false;
        }
    };
    assert!(
        closed,
        "connection still open after deadline (drained {drained} bytes)"
    );
    assert!(
        drained < 8 * 1024 * 1024,
        "entire body was delivered; deadline never fired"
    );
}

/// Regression guard for the repo layout assumption in [`build_docroot`].
#[test]
fn fixture_paths_exist() {
    let (docroot, _) = build_docroot();
    assert!(Path::new(&docroot.path().join("docs/index.html")).exists());
}

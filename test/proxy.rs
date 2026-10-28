//! End-to-end proxy tests. Each test runs `proxy::serve` in-process with a real
//! `Store` and TAP CA in its own temp dir, in-process upstreams (hyper h1/h2,
//! plain or TLS with a test CA, or raw TCP where the exact bytes matter) and
//! curl subprocesses or raw TCP clients. Everything binds 127.0.0.1:0.

use bytes::Bytes;
use http::{HeaderMap, Request, Response, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tap::capture::redact::default_redact;
use tap::capture::Store;
use tap::filter::FilterSet;
use tap::hooks::{HookConfig, HookMode, HookSpec, Hooks};
use tap::proxy::{self, Runtime};
use tap::record::{header, Event, Exchange, Mode};
use tap::tls::Ca;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

const WAIT: Duration = Duration::from_secs(15);

// ---- harness: a TAP proxy in this process ----

#[derive(Default)]
struct Options {
    filters: Vec<&'static str>,
    hooks: HookConfig,
    no_intercept: bool,
    tunnel: Vec<&'static str>,
    upstream: Option<String>,
    max_body: Option<u64>,
    response_timeout: Option<Duration>,
    /// Holds `serve` back until this fires (the listener already accepts).
    gate: Option<oneshot::Receiver<()>>,
    /// Stops the proxy (`serve_until`) when this fires.
    stop: Option<oneshot::Receiver<()>>,
}

struct Tap {
    addr: SocketAddr,
    home: PathBuf,
    session_dir: PathBuf,
    store: Arc<Store>,
    /// TAP's CA, which clients must trust for interception.
    ca_pem: PathBuf,
    /// The test CA upstream TLS servers use (TAP trusts it via `upstream_ca`).
    pki: Pki,
    task: JoinHandle<()>,
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn temp_home(name: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "tap-proxy-{name}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

impl Tap {
    async fn start(name: &str, options: Options) -> Tap {
        let home = temp_home(name);
        let session_dir = home.join("session");
        let ca_dir = home.join("ca");
        let ca = Ca::load_or_create(&ca_dir).unwrap();
        let pki = Pki::create(&home, "TAP test upstream CA");
        let store = Store::open(&session_dir, "test-session").unwrap();
        let specs: Vec<String> = options
            .filters
            .iter()
            .map(|spec| spec.to_string())
            .collect();
        let runtime = Arc::new(Runtime {
            session_id: "test-session".into(),
            session_dir: session_dir.clone(),
            filters: FilterSet::parse(&specs).unwrap(),
            hooks: Hooks::new(options.hooks),
            store: store.clone(),
            ca: (!options.no_intercept).then(|| Arc::new(ca)),
            tunnel_hosts: options
                .tunnel
                .iter()
                .map(|p| regex::Regex::new(p).unwrap())
                .collect(),
            upstream: options.upstream.map(|url| url.parse().unwrap()),
            upstream_ca: Some(pki.ca_pem.clone()),
            redact: default_redact(),
            max_body: options.max_body.unwrap_or(8 << 20),
            connect_timeout: Duration::from_secs(5),
            response_timeout: options.response_timeout.unwrap_or(Duration::from_secs(30)),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let gated = options.gate.is_some();
        let gate = options.gate;
        let stop = options.stop;
        let task = tokio::spawn(async move {
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            match stop {
                Some(stop) => proxy::serve_until(listener, runtime, async {
                    let _ = stop.await;
                })
                .await
                .unwrap(),
                None => proxy::serve(listener, runtime).await.unwrap(),
            }
        });
        if !gated {
            wait_until_serving(addr).await;
        }
        Tap {
            addr,
            home,
            session_dir,
            store,
            ca_pem: Ca::cert_path(&ca_dir),
            pki,
            task,
        }
    }

    fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every exchange recorded so far (each line of events.jsonl must be valid).
    fn exchanges(&self) -> Vec<Exchange> {
        self.store.flush();
        let text = std::fs::read_to_string(self.session_dir.join("events.jsonl")).unwrap();
        text.lines()
            .map(|line| {
                serde_json::from_str::<Event>(line)
                    .unwrap_or_else(|e| panic!("bad line {line}: {e}"))
            })
            .filter_map(|event| match event {
                Event::Exchange(exchange) => Some(exchange),
                Event::SessionStart(_) => None,
            })
            .collect()
    }

    /// Waits until at least `count` exchanges are recorded.
    async fn wait_for(&self, count: usize) -> Vec<Exchange> {
        let deadline = Instant::now() + WAIT;
        loop {
            let found = self.exchanges();
            if found.len() >= count {
                return found;
            }
            assert!(
                Instant::now() < deadline,
                "expected {count} exchanges, found {}: {found:#?}",
                found.len()
            );
            sleep(Duration::from_millis(20)).await;
        }
    }

    async fn only(&self) -> Exchange {
        let mut found = self.wait_for(1).await;
        sleep(Duration::from_millis(100)).await;
        assert_eq!(self.exchanges().len(), 1, "{:#?}", self.exchanges());
        found.remove(0)
    }

    fn body(&self, file: &Option<String>) -> Vec<u8> {
        let file = file.as_ref().expect("a body file");
        std::fs::read(self.session_dir.join(file)).unwrap()
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.home.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

/// Waits until `serve` answers HTTP (it loads the platform's roots first, which
/// takes a while when many tests start at once), so no test races its startup.
/// A CONNECT without a target gets TAP's 400 and is not recorded.
async fn wait_until_serving(addr: SocketAddr) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT / HTTP/1.1\r\nHost: tap\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("TAP started serving")
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

/// A test CA and one leaf for `localhost` / `127.0.0.1`, for upstream TLS servers.
struct Pki {
    ca_pem: PathBuf,
    leaf: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Pki {
    fn create(dir: &Path, name: &str) -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, name);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let leaf = params.signed_by(&key, &ca, &ca_key).unwrap();
        let ca_pem = dir.join("upstream-ca.pem");
        std::fs::write(&ca_pem, ca.pem()).unwrap();
        Pki {
            ca_pem,
            leaf: leaf.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn server_config(&self, alpn: &[&[u8]]) -> Arc<ServerConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()));
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![self.leaf.clone()], key)
                .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

// ---- upstreams ----

#[derive(Clone, Debug)]
struct Received {
    method: String,
    uri: String,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
}

/// A hyper upstream (HTTP/1.1 and HTTP/2, TLS when `tls` is set) that records what it receives.
struct Upstream {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    task: JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Upstream {
    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    fn url(&self, scheme: &str, path: &str) -> String {
        format!("{scheme}://{}{path}", self.addr)
    }
}

async fn upstream<F>(tls: Option<Arc<ServerConfig>>, handler: F) -> Upstream
where
    F: Fn(&Received) -> Response<Full<Bytes>> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);
    let log = received.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (handler, log, tls) = (handler.clone(), log.clone(), tls.clone());
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let (handler, log) = (handler.clone(), log.clone());
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let got = Received {
                            method: parts.method.to_string(),
                            uri: parts.uri.to_string(),
                            version: parts.version,
                            headers: parts.headers,
                            body,
                        };
                        let response = handler(&got);
                        log.lock().unwrap().push(got);
                        Ok::<_, Infallible>(response)
                    }
                });
                let builder = auto::Builder::new(TokioExecutor::new());
                match tls {
                    Some(config) => {
                        if let Ok(stream) = TlsAcceptor::from(config).accept(stream).await {
                            let _ = builder
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        }
                    }
                    None => {
                        let _ = builder
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                }
            });
        }
    });
    Upstream {
        addr,
        received,
        task,
    }
}

fn ok(body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::new(Full::new(body.into()))
}

fn echo(received: &Received) -> Response<Full<Bytes>> {
    ok(received.body.clone())
}

/// Accepts one connection, reads one request (head plus Content-Length body) and
/// hands the stream and the raw request bytes to `script`. Resolves to the request bytes.
async fn raw_upstream<F, Fut>(script: F) -> (SocketAddr, JoinHandle<Vec<u8>>)
where
    F: FnOnce(TcpStream, Vec<u8>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_message(&mut stream).await;
        script(stream, request.clone()).await;
        request
    });
    (addr, task)
}

/// Reads one HTTP/1 message head and its Content-Length body.
async fn read_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = find(&data, b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(
            read > 0,
            "connection closed mid-head: {}",
            String::from_utf8_lossy(&data)
        );
        data.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&data[..head_end]).to_ascii_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().unwrap());
    while data.len() < head_end + length {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0);
        data.extend_from_slice(&chunk[..read]);
    }
    data
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    find(haystack, needle.as_bytes()).is_some()
}

/// Sends raw bytes to `addr` and reads until the server closes (send `Connection: close`).
async fn raw_client(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut out = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    out
}

/// Reads from `stream` until `needle` has arrived.
async fn read_until(stream: &mut TcpStream, data: &mut Vec<u8>, needle: &str) {
    let mut chunk = [0u8; 4096];
    timeout(WAIT, async {
        while !contains(data, needle) {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(
                read > 0,
                "closed before {needle:?}: {}",
                String::from_utf8_lossy(data)
            );
            data.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{needle:?} did not arrive; got {}",
            String::from_utf8_lossy(data)
        )
    });
}

/// A port nothing listens on.
fn refused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn curl(args: &[&str]) -> Output {
    let output = tokio::process::Command::new("curl")
        .arg("-q")
        .args(["-s", "-S", "--max-time", "20"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .output();
    timeout(Duration::from_secs(30), output)
        .await
        .unwrap()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "curl failed ({}): {}\nstdout: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        stdout(output)
    );
}

fn sync_hook(command: &[&str]) -> HookSpec {
    HookSpec {
        mode: HookMode::Sync,
        command: command.iter().map(|part| part.to_string()).collect(),
        timeout_ms: 20_000,
    }
}

fn binary(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

// ---- forward mode: bodies, headers, framing ----

#[tokio::test(flavor = "multi_thread")]
async fn binary_bodies_are_byte_identical_everywhere() {
    let tap = Tap::start("binary", Options::default()).await;
    let response_bytes = binary(70_000, 7);
    let reply = response_bytes.clone();
    let server = upstream(None, move |_| {
        Response::builder()
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::from(reply.clone())))
            .unwrap()
    })
    .await;
    let request_bytes = binary(100_000, 3);
    let upload = tap.file("upload.bin", &request_bytes);
    let download = tap.home.join("download.bin");
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        &format!("@{}", upload.display()),
        "-H",
        "content-type: application/octet-stream",
        "-o",
        download.to_str().unwrap(),
        &server.url("http", "/upload?kind=bin"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(
        std::fs::read(&download).unwrap(),
        response_bytes,
        "client got the exact bytes"
    );
    let received = &server.received()[0];
    assert_eq!(
        (received.method.as_str(), received.uri.as_str()),
        ("POST", "/upload?kind=bin")
    );
    assert_eq!(received.body, request_bytes, "upstream got the exact bytes");

    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Forward);
    assert_eq!(exchange.seq, 1);
    assert_eq!(exchange.request.url, server.url("http", "/upload?kind=bin"));
    assert_eq!(exchange.request.path, "/upload?kind=bin");
    assert_eq!(exchange.request.method, "POST");
    assert_eq!(exchange.request.body.size, request_bytes.len() as u64);
    assert!(exchange.request.body.complete);
    assert_eq!(tap.body(&exchange.request.body.file), request_bytes);
    let response = exchange.response.as_ref().unwrap();
    assert_eq!(response.status, 200);
    assert!(response.body.complete);
    assert_eq!(tap.body(&response.body.file), response_bytes);
    assert!(exchange.ttfb_ms.is_some() && exchange.duration_ms.is_some());
    assert!(exchange.notes.is_empty(), "{:?}", exchange.notes);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_response_head_is_preserved() {
    let tap = Tap::start("raw-head", Options::default()).await;
    let (addr, upstream_task) = raw_upstream(|mut stream, _| async move {
        stream
            .write_all(
                b"HTTP/1.1 299 Totally Custom\r\nContent-Length: 5\r\nSet-Cookie: a=1\r\n\
                  X-Mixed-Case: Yes\r\nSet-Cookie: b=2\r\n\r\nhello",
            )
            .await
            .unwrap();
    })
    .await;
    let request = format!(
        "GET http://{addr}/x HTTP/1.1\r\nHost: {addr}\r\nX-Client-Case: kept\r\n\
         Proxy-Connection: keep-alive\r\nConnection: close\r\n\r\n"
    );
    let response = raw_client(tap.addr, request.as_bytes()).await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 299 Totally Custom\r\n"),
        "{text}"
    );
    assert_eq!(text.matches("Set-Cookie: ").count(), 2, "{text}");
    assert!(
        text.contains("Set-Cookie: a=1\r\n") && text.contains("Set-Cookie: b=2\r\n"),
        "{text}"
    );
    assert!(
        text.contains("X-Mixed-Case: Yes\r\n"),
        "header case kept: {text}"
    );
    assert_eq!(
        text.to_ascii_lowercase().matches("content-length:").count(),
        1,
        "{text}"
    );
    assert!(
        !text.to_ascii_lowercase().contains("transfer-encoding"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\nhello"), "{text}");

    let sent = String::from_utf8(upstream_task.await.unwrap()).unwrap();
    assert!(
        sent.starts_with("GET /x HTTP/1.1\r\n"),
        "origin-form upstream: {sent}"
    );
    assert!(
        sent.contains("X-Client-Case: kept\r\n"),
        "request header case kept: {sent}"
    );
    assert!(
        !sent.to_ascii_lowercase().contains("proxy-connection"),
        "{sent}"
    );
    assert!(
        sent.to_ascii_lowercase()
            .contains(&format!("host: {addr}\r\n")),
        "{sent}"
    );

    let exchange = tap.only().await;
    let response = exchange.response.unwrap();
    assert_eq!(
        (response.status, response.reason.as_str()),
        (299, "Totally Custom")
    );
    let cookies: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .collect();
    assert_eq!(cookies.len(), 2, "both cookies recorded");
    assert!(cookies
        .iter()
        .all(|(_, value)| value.starts_with("[REDACTED len=3 sha256=")));
    assert_eq!(header(&response.headers, "x-mixed-case"), Some("Yes"));
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(exchange.request.version, "HTTP/1.1");
    assert_eq!(
        header(&exchange.request.headers, "proxy-connection"),
        Some("keep-alive"),
        "recorded as sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn chunked_request_body_streams_through() {
    let tap = Tap::start("chunked", Options::default()).await;
    let server = upstream(None, echo).await;
    let payload = binary(50_000, 11);
    let upload = tap.file("chunked.bin", &payload);
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "-H",
        "Transfer-Encoding: chunked",
        "--data-binary",
        &format!("@{}", upload.display()),
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        &server.url("http", "/chunked"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "200");
    let received = &server.received()[0];
    assert_eq!(received.body, payload);
    assert!(!received.headers.contains_key("content-length"));
    assert_eq!(
        received.headers["transfer-encoding"], "chunked",
        "re-framed by hyper"
    );
    let exchange = tap.only().await;
    assert_eq!(
        header(&exchange.request.headers, "transfer-encoding"),
        Some("chunked")
    );
    assert_eq!(exchange.request.body.size, payload.len() as u64);
    assert_eq!(tap.body(&exchange.request.body.file), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn expect_100_continue_completes_quickly() {
    let tap = Tap::start("expect", Options::default()).await;
    let server = upstream(None, echo).await;
    let started = Instant::now();
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "-H",
        "Expect: 100-continue",
        "--expect100-timeout",
        "5",
        "--data-binary",
        "expected body",
        &server.url("http", "/expect"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "expected body");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "took {:?}",
        started.elapsed()
    );
    assert!(!server.received()[0].headers.contains_key("expect"));
    let exchange = tap.only().await;
    assert_eq!(
        header(&exchange.request.headers, "expect"),
        Some("100-continue")
    );
    assert_eq!(tap.body(&exchange.request.body.file), b"expected body");
}

#[tokio::test(flavor = "multi_thread")]
async fn head_keeps_content_length_without_body() {
    let tap = Tap::start("head", Options::default()).await;
    let (addr, _upstream) = raw_upstream(|mut stream, _| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let request =
        format!("HEAD http://{addr}/h HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let text = String::from_utf8(raw_client(tap.addr, request.as_bytes()).await).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("content-length: 1234\r\n"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\n"), "no body: {text}");
    let exchange = tap.only().await;
    let response = exchange.response.unwrap();
    assert_eq!(response.body.size, 0);
    assert!(response.body.complete);
}

#[tokio::test(flavor = "multi_thread")]
async fn http10_client_and_close_delimited_upstream() {
    let tap = Tap::start("http10", Options::default()).await;
    let (addr, upstream_task) = raw_upstream(|mut stream, _| async move {
        // No Content-Length and no chunking: the body ends when the connection does.
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil close")
            .await
            .unwrap();
    })
    .await;
    let request = format!("GET http://{addr}/old HTTP/1.0\r\n\r\n");
    let text = String::from_utf8(raw_client(tap.addr, request.as_bytes()).await).unwrap();
    assert!(text.starts_with("HTTP/1."), "{text}");
    assert!(text.contains(" 200 OK\r\n"), "{text}");
    assert!(
        text.ends_with("\r\n\r\nuntil close"),
        "close-delimited for an HTTP/1.0 client: {text}"
    );
    let sent = String::from_utf8(upstream_task.await.unwrap()).unwrap();
    assert!(sent.starts_with("GET /old HTTP/1.1\r\n"), "{sent}");
    let exchange = tap.only().await;
    assert_eq!(exchange.request.version, "HTTP/1.0");
    let response = exchange.response.unwrap();
    assert_eq!(response.version, "HTTP/1.0");
    assert!(response.body.complete);
    assert_eq!(tap.body(&response.body.file), b"until close");
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_streams_in_real_time_and_records_everything() {
    let tap = Tap::start("sse", Options::default()).await;
    let (go, wait_go) = oneshot::channel::<()>();
    let (addr, _upstream) = raw_upstream(move |mut stream, _| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        stream.write_all(b"c\r\nevent: one\n\n\r\n").await.unwrap();
        // The rest is only sent once the client has seen the first event.
        let _ = wait_go.await;
        stream.write_all(b"c\r\nevent: two\n\n\r\n0\r\n\r\n").await.unwrap();
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!("GET http://{addr}/stream HTTP/1.1\r\nHost: {addr}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "event: one").await;
    assert!(!contains(&data, "event: two"));
    go.send(()).unwrap();
    timeout(WAIT, client.read_to_end(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert!(
        contains(&data, "event: two"),
        "{}",
        String::from_utf8_lossy(&data)
    );

    let exchange = tap.only().await;
    let response = exchange.response.unwrap();
    assert!(response.body.complete);
    assert_eq!(
        tap.body(&response.body.file),
        b"event: one\n\nevent: two\n\n"
    );
    assert_eq!(
        header(&response.headers, "transfer-encoding"),
        Some("chunked")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_mid_stream_records_incomplete_response() {
    let tap = Tap::start("disconnect", Options::default()).await;
    let (addr, upstream_task) = raw_upstream(|mut stream, _| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        // Streams until TAP hangs up on this connection.
        while stream.write_all(b"5\r\ntick\n\r\n").await.is_ok() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!("GET http://{addr}/forever HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "tick").await;
    drop(client);

    let exchange = tap.only().await;
    let response = exchange.response.as_ref().unwrap();
    assert!(!response.body.complete, "{exchange:#?}");
    assert!(response.body.size >= 5);
    assert!(
        exchange
            .notes
            .iter()
            .any(|note| note.contains("response body incomplete")),
        "{:?}",
        exchange.notes
    );
    timeout(WAIT, upstream_task)
        .await
        .expect("TAP closed the upstream connection")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn client_giving_up_before_the_response_is_recorded_and_cancels_upstream() {
    let tap = Tap::start("give-up", Options::default()).await;
    let (arrived, wait_arrived) = oneshot::channel::<()>();
    let (addr, upstream_task) = raw_upstream(|mut stream, _| async move {
        arrived.send(()).unwrap();
        // Never answers; returns once TAP drops the connection.
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!(
        "POST http://{addr}/slow HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 4\r\n\r\nwait"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    timeout(WAIT, wait_arrived).await.unwrap().unwrap();
    drop(client);

    let exchange = tap.only().await;
    let error = exchange.error.as_deref().unwrap();
    assert!(
        error.contains("the client went away (closed the connection or cancelled the request) before it got a response"),
        "{error}"
    );
    assert!(exchange.response.is_none());
    assert_eq!(tap.body(&exchange.request.body.file), b"wait");
    timeout(WAIT, upstream_task)
        .await
        .expect("the upstream request was cancelled")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn max_body_truncates_the_capture_not_the_traffic() {
    let tap = Tap::start(
        "truncate",
        Options {
            max_body: Some(4),
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        "0123456789",
        &server.url("http", "/t"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "0123456789");
    assert_eq!(server.received()[0].body, "0123456789");
    let exchange = tap.only().await;
    assert_eq!(tap.body(&exchange.request.body.file), b"0123");
    let body = &exchange.request.body;
    assert_eq!((body.size, body.captured, body.truncated), (10, 4, true));
    assert!(
        exchange
            .notes
            .iter()
            .any(|note| note.contains("request body truncated")),
        "{:?}",
        exchange.notes
    );
}

// ---- failures ----

#[tokio::test(flavor = "multi_thread")]
async fn upstream_refused_gives_502_and_error_exchange() {
    let tap = Tap::start("refused", Options::default()).await;
    let port = refused_port();
    let url = format!("http://127.0.0.1:{port}/nothing");
    let output = curl(&["-x", &tap.proxy_url(), "-i", &url]).await;
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "{text}");
    assert!(
        text.to_ascii_lowercase().contains("x-tap-error: "),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "tap: upstream request to {url} failed: cannot connect to 127.0.0.1:{port}"
        )),
        "{text}"
    );
    assert!(text.contains("Connection refused"), "{text}");
    let exchange = tap.only().await;
    let error = exchange.error.unwrap();
    assert!(
        error.contains("Connection refused") && error.contains("tcp connect error"),
        "{error}"
    );
    assert!(exchange.response.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_failure_names_the_cause() {
    let tap = Tap::start("tls-fail", Options::default()).await;
    // A certificate from a CA TAP does not trust.
    let other = Pki::create(&tap.home.join("ca"), "Some other CA");
    let server = upstream(Some(other.server_config(&[b"http/1.1"])), echo).await;
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.ca_pem.to_str().unwrap(),
        "-i",
        &server.url("https", "/x"),
    ])
    .await;
    let text = stdout(&output);
    assert!(text.contains("HTTP/2 502"), "{text}");
    assert!(text.contains("UnknownIssuer"), "{text}");
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Mitm);
    let error = exchange.error.unwrap();
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_to_tap_itself_are_refused_not_looped() {
    let tap = Tap::start("loop", Options::default()).await;
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "-i",
        &format!("http://{}/again", tap.addr),
    ])
    .await;
    let text = stdout(&output);
    assert!(text.starts_with("HTTP/1.1 502"), "{text}");
    assert!(text.contains("would loop"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn origin_form_without_upstream_explains_how_to_use_tap() {
    let tap = Tap::start("origin", Options::default()).await;
    let output = curl(&["-i", &format!("http://{}/v1/messages", tap.addr)]).await;
    let text = stdout(&output);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert!(
        text.contains("HTTPS_PROXY") && text.contains("--upstream"),
        "{text}"
    );
    let exchange = tap.only().await;
    assert!(exchange.error.unwrap().contains("--upstream"));
    assert_eq!(exchange.request.path, "/v1/messages");
}

// ---- scope ----

#[tokio::test(flavor = "multi_thread")]
async fn out_of_scope_traffic_is_forwarded_but_not_recorded() {
    let tap = Tap::start(
        "scope",
        Options {
            filters: vec!["path=/in"],
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let out = curl(&[
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        "outside",
        &server.url("http", "/out"),
    ])
    .await;
    assert_eq!(stdout(&out), "outside");
    let inside = curl(&[
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        "inside",
        &server.url("http", "/in"),
    ])
    .await;
    assert_eq!(stdout(&inside), "inside");
    assert_eq!(server.received().len(), 2);
    let exchange = tap.only().await;
    assert_eq!(exchange.request.path, "/in");
    assert_eq!(exchange.seq, 1, "out-of-scope requests take no number");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_filter_records_only_failures() {
    let tap = Tap::start(
        "status",
        Options {
            filters: vec!["status=5xx"],
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, |received| {
        let status = if received.uri.contains("fail") {
            503
        } else {
            200
        };
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from("x")))
            .unwrap()
    })
    .await;
    for path in ["/ok", "/fail", "/ok2"] {
        assert_success(&curl(&["-x", &tap.proxy_url(), &server.url("http", path)]).await);
    }
    let refused = format!("http://127.0.0.1:{}/down", refused_port());
    curl(&["-x", &tap.proxy_url(), &refused]).await;
    let found = tap.wait_for(2).await;
    sleep(Duration::from_millis(200)).await;
    let found_later = tap.exchanges();
    assert_eq!(found_later.len(), 2, "{found_later:#?}");
    assert_eq!(found[0].request.path, "/fail");
    assert_eq!(found[0].status(), Some(503));
    assert_eq!(found[1].request.url, refused);
    assert!(found[1].error.is_some());
}

// ---- concurrency ----

#[tokio::test(flavor = "multi_thread")]
async fn fifty_concurrent_requests_make_fifty_valid_records() {
    let tap = Tap::start("concurrent", Options::default()).await;
    let server = upstream(None, echo).await;
    let addr = server.addr;
    let clients: Vec<_> = (0..50)
        .map(|i| {
            let proxy = tap.addr;
            tokio::spawn(async move {
                let body = format!("body-{i}-{}", "x".repeat(i * 100));
                let request = format!(
                    "POST http://{addr}/item/{i} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let response = raw_client(proxy, request.as_bytes()).await;
                assert!(response.ends_with(body.as_bytes()), "{i}: {}", String::from_utf8_lossy(&response));
            })
        })
        .collect();
    for client in clients {
        client.await.unwrap();
    }
    let found = tap.wait_for(50).await;
    assert_eq!(found.len(), 50);
    let mut seqs: Vec<u64> = found.iter().map(|exchange| exchange.seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=50).collect::<Vec<u64>>());
    for exchange in &found {
        let i: usize = exchange
            .request
            .path
            .strip_prefix("/item/")
            .unwrap()
            .parse()
            .unwrap();
        let body = format!("body-{i}-{}", "x".repeat(i * 100));
        assert_eq!(tap.body(&exchange.request.body.file), body.as_bytes());
        assert_eq!(
            tap.body(&exchange.response.as_ref().unwrap().body.file),
            body.as_bytes()
        );
    }
}

// ---- CONNECT: MITM, tunnel, plain HTTP inside ----

#[tokio::test(flavor = "multi_thread")]
async fn mitm_over_http1_upstream() {
    let tap = Tap::start("mitm-h1", Options::default()).await;
    let server = upstream(Some(tap.pki.server_config(&[b"http/1.1"])), |_| {
        Response::builder()
            .status(201)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(br#"{"ok":true}"#)))
            .unwrap()
    })
    .await;
    let url = server.url("https", "/v1/messages?beta=1");
    let output = curl(&[
        "--http1.1",
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.ca_pem.to_str().unwrap(),
        "-H",
        "x-api-key: sk-test-secret-1",
        "-H",
        "content-type: application/json",
        "--data-binary",
        r#"{"model":"m"}"#,
        &url,
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), r#"{"ok":true}"#);
    let received = &server.received()[0];
    assert_eq!(
        received.headers["x-api-key"], "sk-test-secret-1",
        "upstream gets the real key"
    );
    assert_eq!(received.version, Version::HTTP_11);
    assert_eq!(received.body, r#"{"model":"m"}"#);

    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Mitm);
    assert_eq!(exchange.request.url, url);
    assert_eq!(exchange.request.scheme, "https");
    assert_eq!(exchange.request.path, "/v1/messages?beta=1");
    assert_eq!(exchange.request.version, "HTTP/1.1");
    let key = header(&exchange.request.headers, "x-api-key").unwrap();
    assert!(key.starts_with("[REDACTED len=16 sha256="), "{key}");
    assert_eq!(tap.body(&exchange.request.body.file), br#"{"model":"m"}"#);
    let response = exchange.response.as_ref().unwrap();
    assert_eq!(
        (response.status, response.reason.as_str()),
        (201, "Created")
    );
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(tap.body(&response.body.file), br#"{"ok":true}"#);
    let raw = std::fs::read_to_string(tap.session_dir.join("events.jsonl")).unwrap();
    assert!(
        !raw.contains("sk-test-secret-1"),
        "the secret never reaches the record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mitm_over_http2_upstream() {
    let tap = Tap::start("mitm-h2", Options::default()).await;
    let server = upstream(Some(tap.pki.server_config(&[b"h2"])), |received| {
        Response::builder()
            .header("x-upstream-version", format!("{:?}", received.version))
            .body(Full::new(received.body.clone()))
            .unwrap()
    })
    .await;
    let url = server.url("https", "/h2/path?q=1");
    let output = curl(&[
        "--http2",
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.ca_pem.to_str().unwrap(),
        "-H",
        "x-api-key: sk-test-secret-2",
        "--data-binary",
        "over h2",
        "-i",
        &url,
    ])
    .await;
    assert_success(&output);
    let text = stdout(&output);
    assert!(
        text.contains("HTTP/2 200"),
        "client spoke h2 to TAP: {text}"
    );
    assert!(text.ends_with("over h2"), "{text}");
    let received = &server.received()[0];
    assert_eq!(
        received.version,
        Version::HTTP_2,
        "TAP negotiated h2 upstream"
    );
    assert_eq!(received.headers["x-api-key"], "sk-test-secret-2");
    assert_eq!(received.uri, url);

    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Mitm);
    assert_eq!(exchange.request.url, url);
    assert_eq!(exchange.request.version, "HTTP/2");
    assert!(header(&exchange.request.headers, "x-api-key")
        .unwrap()
        .starts_with("[REDACTED"));
    assert_eq!(tap.body(&exchange.request.body.file), b"over h2");
    let response = exchange.response.as_ref().unwrap();
    assert_eq!(response.version, "HTTP/2");
    assert_eq!(response.status, 200);
    assert_eq!(tap.body(&response.body.file), b"over h2");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_not_trusting_the_ca_is_recorded_with_advice() {
    let tap = Tap::start("untrusted", Options::default()).await;
    let server = upstream(Some(tap.pki.server_config(&[b"http/1.1"])), echo).await;
    let output = curl(&["-x", &tap.proxy_url(), &server.url("https", "/x")]).await;
    assert!(
        !output.status.success(),
        "curl must reject TAP's certificate"
    );
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Mitm);
    assert_eq!(exchange.request.method, "CONNECT");
    assert_eq!(exchange.request.url, server.addr.to_string());
    let error = exchange.error.unwrap();
    assert!(
        error.contains("does not trust TAP's CA") && error.contains("tap ca"),
        "{error}"
    );
    assert!(server.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_hosts_are_relayed_opaquely() {
    let tap = Tap::start(
        "tunnel",
        Options {
            tunnel: vec![r"^127\.0\.0\.1$"],
            ..Default::default()
        },
    )
    .await;
    let server = upstream(Some(tap.pki.server_config(&[b"http/1.1"])), echo).await;
    // The client talks TLS with the upstream itself, so it trusts the upstream's CA.
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.pki.ca_pem.to_str().unwrap(),
        "--data-binary",
        "through the tunnel",
        &server.url("https", "/t"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "through the tunnel");
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Tunnel);
    assert_eq!(exchange.request.method, "CONNECT");
    assert_eq!(exchange.request.url, server.addr.to_string());
    assert_eq!(exchange.request.scheme, "tcp");
    assert_eq!(exchange.request.path, "");
    assert!(header(&exchange.request.headers, "host").is_some());
    let stats = exchange.tunnel.unwrap();
    assert!(stats.bytes_up > 100 && stats.bytes_down > 100, "{stats:?}");
    assert!(exchange.response.is_none() && exchange.error.is_none());
    assert!(exchange.duration_ms.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_to_refused_port_without_interception_is_502() {
    let tap = Tap::start(
        "tunnel-refused",
        Options {
            no_intercept: true,
            ..Default::default()
        },
    )
    .await;
    let port = refused_port();
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "refused").await;
    let text = String::from_utf8(data).unwrap();
    assert!(text.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{text}");
    assert!(
        text.contains(&format!("tap: cannot open a tunnel to 127.0.0.1:{port}")),
        "{text}"
    );
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Tunnel);
    assert!(exchange.error.unwrap().contains("refused"));
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_inside_connect_is_intercepted() {
    let tap = Tap::start("plain-connect", Options::default()).await;
    let server = upstream(None, echo).await;
    let url = server.url("http", "/plain");
    let output = curl(&[
        "--proxytunnel",
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        "plain inside",
        &url,
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "plain inside");
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Mitm);
    assert_eq!(exchange.request.scheme, "http");
    assert_eq!(exchange.request.url, url);
    assert_eq!(tap.body(&exchange.request.body.file), b"plain inside");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_protocol_inside_connect_is_relayed_opaquely() {
    let tap = Tap::start("opaque", Options::default()).await;
    let (addr, _upstream) = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });
        (addr, task)
    };
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    client
        .write_all(format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "\r\n\r\n").await;
    assert!(data.starts_with(b"HTTP/1.1 200"));
    client.write_all(b"\x00\x01bin!").await.unwrap();
    let mut echoed = [0u8; 6];
    timeout(WAIT, client.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"\x00\x01bin!");
    drop(client);
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Tunnel);
    let stats = exchange.tunnel.unwrap();
    assert_eq!((stats.bytes_up, stats.bytes_down), (6, 6));
    assert!(
        exchange.notes[0].contains("opaque tunnel"),
        "{:?}",
        exchange.notes
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_101_relays_bytes_both_ways() {
    let tap = Tap::start("upgrade", Options::default()).await;
    let (addr, upstream_task) = raw_upstream(|mut stream, _| async move {
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf.to_ascii_uppercase()).await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!(
        "GET http://{addr}/ws HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "\r\n\r\n").await;
    let head = String::from_utf8_lossy(&data).to_ascii_lowercase();
    assert!(
        head.starts_with("http/1.1 101 switching protocols\r\n"),
        "{head}"
    );
    assert!(
        head.contains("upgrade: echo\r\n") && head.contains("connection: upgrade\r\n"),
        "{head}"
    );
    client.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    timeout(WAIT, client.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"PING");
    drop(client);

    let sent = String::from_utf8(upstream_task.await.unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        sent.contains("connection: upgrade\r\n") && sent.contains("upgrade: echo\r\n"),
        "{sent}"
    );
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Forward);
    assert_eq!(exchange.status(), Some(101));
    let stats = exchange.tunnel.unwrap();
    assert_eq!((stats.bytes_up, stats.bytes_down), (4, 4));
}

// ---- reverse mode ----

#[tokio::test(flavor = "multi_thread")]
async fn reverse_mode_joins_base_path_and_rewrites_host() {
    let server = upstream(None, echo).await;
    let base = format!("http://{}/base/", server.addr);
    let tap = Tap::start(
        "reverse",
        Options {
            upstream: Some(base),
            ..Default::default()
        },
    )
    .await;
    let output = curl(&[
        "--data-binary",
        "rev",
        &format!("http://{}/v1/messages?x=1", tap.addr),
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "rev");
    let received = &server.received()[0];
    assert_eq!(received.uri, "/base/v1/messages?x=1");
    assert_eq!(
        received.headers["host"],
        server.addr.to_string(),
        "Host rewritten to the upstream"
    );
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Reverse);
    assert_eq!(
        exchange.request.url,
        format!("http://{}/base/v1/messages?x=1", server.addr)
    );
    assert_eq!(
        header(&exchange.request.headers, "host"),
        Some(tap.addr.to_string().as_str())
    );
}

// ---- hooks ----

#[tokio::test(flavor = "multi_thread")]
async fn sync_request_hook_changing_body_length_fixes_content_length() {
    let hooks = HookConfig {
        on_request: vec![sync_hook(&[
            "sed",
            r#"s/"body":"hello"/"body":"hello, longer world"/"#,
        ])],
        ..Default::default()
    };
    let tap = Tap::start(
        "hook-body",
        Options {
            hooks,
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        "hello",
        &server.url("http", "/hook"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(stdout(&output), "hello, longer world");
    let received = &server.received()[0];
    assert_eq!(received.body, "hello, longer world");
    let lengths: Vec<_> = received.headers.get_all("content-length").iter().collect();
    assert_eq!(lengths, ["19"]);

    let exchange = tap.only().await;
    assert_eq!(
        tap.body(&exchange.request.body.file),
        b"hello",
        "the record keeps what the client sent"
    );
    assert_eq!(
        header(&exchange.request.headers, "content-length"),
        Some("5")
    );
    assert!(
        exchange
            .notes
            .iter()
            .any(|note| note.starts_with("on_request hook `sed") && note.contains("changed body")),
        "{:?}",
        exchange.notes
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_mib_through_cat_hooks_does_not_stall() {
    let hooks = HookConfig {
        on_request: vec![sync_hook(&["cat"])],
        on_response: vec![sync_hook(&["cat"])],
        ..Default::default()
    };
    let tap = Tap::start(
        "hook-big",
        Options {
            hooks,
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let payload: Vec<u8> = (0..(1 << 20)).map(|i| b'a' + (i % 26) as u8).collect();
    let upload = tap.file("big.txt", &payload);
    let download = tap.home.join("big-back.txt");
    let started = Instant::now();
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--data-binary",
        &format!("@{}", upload.display()),
        "-o",
        download.to_str().unwrap(),
        &server.url("http", "/big"),
    ])
    .await;
    assert_success(&output);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(server.received()[0].body.len(), payload.len());
    assert_eq!(std::fs::read(&download).unwrap(), payload);
    let exchange = tap.only().await;
    assert!(
        exchange.notes.is_empty(),
        "echoing hooks change nothing: {:?}",
        exchange.notes
    );
    assert_eq!(exchange.response.unwrap().body.size, payload.len() as u64);
}

// ---- framing, timeouts, protocol choice ----

/// The 101 test's raw upstream has no TLS; this one serves TLS from the test CA
/// and hands the decrypted stream to `script` after reading one request head.
async fn raw_tls_upstream<F, Fut>(pki: &Pki, alpn: &[&[u8]], script: F) -> SocketAddr
where
    F: FnOnce(tokio_rustls::server::TlsStream<TcpStream>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let tls = pki.server_config(alpn);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // TAP may first open a connection only to learn the upstream's ALPN.
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = TlsAcceptor::from(tls.clone()).accept(stream).await else {
                continue;
            };
            let mut head = Vec::new();
            let mut chunk = [0u8; 4096];
            while find(&head, b"\r\n\r\n").is_none() {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => head.extend_from_slice(&chunk[..read]),
                }
            }
            if find(&head, b"\r\n\r\n").is_some() {
                script(stream).await;
                return;
            }
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn content_length_beside_chunked_is_not_forwarded() {
    let tap = Tap::start("cl-te", Options::default()).await;
    let (addr, _upstream) = raw_upstream(|mut stream, _| async move {
        // Transfer-Encoding wins (RFC 9112 6.3); the length is wrong.
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n\
                  5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
    })
    .await;
    let request =
        format!("GET http://{addr}/x HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let text = String::from_utf8(raw_client(tap.addr, request.as_bytes()).await).unwrap();
    assert!(
        !text.to_ascii_lowercase().contains("content-length"),
        "{text}"
    );
    assert!(
        text.ends_with("\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
        "the whole body, chunked: {text}"
    );
    let exchange = tap.only().await;
    let response = exchange.response.unwrap();
    assert_eq!(tap.body(&response.body.file), b"hello world");
    assert_eq!(
        header(&response.headers, "content-length"),
        Some("3"),
        "recorded as received"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn h2c_upgrade_requests_are_forwarded_as_plain_http1() {
    let server = upstream(None, echo).await;
    let tap = Tap::start(
        "h2c",
        Options {
            upstream: Some(format!("http://{}", server.addr)),
            ..Default::default()
        },
    )
    .await;
    // curl --http2 on an http:// URL asks to upgrade to h2c.
    let output = curl(&[
        "--http2",
        "-i",
        "--data-binary",
        "h2c?",
        &format!("http://{}/v1/x", tap.addr),
    ])
    .await;
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("h2c?"), "{text}");
    let received = &server.received()[0];
    for name in ["upgrade", "connection", "http2-settings"] {
        assert!(
            !received.headers.contains_key(name),
            "{name}: {:?}",
            received.headers
        );
    }
    let exchange = tap.only().await;
    assert_eq!(exchange.status(), Some(200));
    assert!(exchange.tunnel.is_none());
    assert_eq!(header(&exchange.request.headers, "upgrade"), Some("h2c"));
}

#[tokio::test(flavor = "multi_thread")]
async fn response_timeout_counts_only_time_without_progress() {
    let tap = Tap::start(
        "timeouts",
        Options {
            response_timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        },
    )
    .await;
    // An upload slower than the timeout that keeps going is not a stall.
    let server = upstream(None, echo).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{addr}/slow-upload HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    for _ in 0..8 {
        sleep(Duration::from_millis(200)).await;
        client.write_all(b"x").await.unwrap();
    }
    let mut out = Vec::new();
    timeout(WAIT, client.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("xxxxxxxx"), "{text}");

    // An upstream that takes the request and never answers is one.
    let (stalled, _upstream) = raw_upstream(|mut stream, _| async move {
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    })
    .await;
    let started = Instant::now();
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "-i",
        &format!("http://{stalled}/never"),
    ])
    .await;
    let text = stdout(&output);
    assert!(text.starts_with("HTTP/1.1 502"), "{text}");
    assert!(
        text.contains(&format!(
            "no response from {stalled} within 0.5s (the response timeout)"
        )),
        "{text}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let found = tap.wait_for(2).await;
    let failed = found
        .iter()
        .find(|exchange| exchange.request.path == "/never")
        .unwrap();
    assert!(failed
        .error
        .as_deref()
        .unwrap()
        .contains("the response timeout"));
}

#[tokio::test(flavor = "multi_thread")]
async fn intercepted_clients_speak_to_upstream_as_they_would_without_tap() {
    let tap = Tap::start("alpn", Options::default()).await;
    // An HTTP/1.1-only upstream: curl (which offers h2) must get HTTP/1.1 and its reason phrase.
    let h1_only = raw_tls_upstream(&tap.pki, &[b"http/1.1"], |mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 299 Very Custom\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )
            .await
            .unwrap();
        let _ = stream.shutdown().await;
    })
    .await;
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.ca_pem.to_str().unwrap(),
        "-i",
        &format!("https://localhost:{}/h1", h1_only.port()),
    ])
    .await;
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("HTTP/1.1 299 Very Custom\r\n"), "{text}");

    // An upstream offering both: a client that chose HTTP/1.1 keeps it upstream.
    let both = upstream(Some(tap.pki.server_config(&[b"h2", b"http/1.1"])), echo).await;
    let output = curl(&[
        "--http1.1",
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.ca_pem.to_str().unwrap(),
        "--data-binary",
        "one",
        &both.url("https", "/one"),
    ])
    .await;
    assert_success(&output);
    assert_eq!(both.received()[0].version, Version::HTTP_11);
    // ... and one that offers h2 gets it on both sides.
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "--cacert",
        tap.ca_pem.to_str().unwrap(),
        "-i",
        "--data-binary",
        "two",
        &both.url("https", "/two"),
    ])
    .await;
    assert_success(&output);
    assert!(
        stdout(&output).contains("\r\nHTTP/2 200"),
        "{}",
        stdout(&output)
    );
    assert_eq!(both.received()[1].version, Version::HTTP_2);

    let found = tap.wait_for(3).await;
    let versions: Vec<(String, String, String)> = found
        .iter()
        .map(|exchange| {
            (
                exchange.request.path.clone(),
                exchange.request.version.clone(),
                exchange.response.as_ref().unwrap().version.clone(),
            )
        })
        .collect();
    for expected in [
        ("/h1", "HTTP/1.1", "HTTP/1.1"),
        ("/one", "HTTP/1.1", "HTTP/1.1"),
        ("/two", "HTTP/2", "HTTP/2"),
    ] {
        let expected = (
            expected.0.to_string(),
            expected.1.to_string(),
            expected.2.to_string(),
        );
        assert!(versions.contains(&expected), "{expected:?} in {versions:?}");
    }
    let h1 = found.iter().find(|e| e.request.path == "/h1").unwrap();
    assert_eq!(h1.response.as_ref().unwrap().reason, "Very Custom");
}

// ---- HTTP/2, upgrades and keep-alive inside intercepted tunnels ----

/// Opens a CONNECT tunnel through TAP to `authority` and completes TLS with TAP
/// (trusting TAP's CA), offering `alpn`.
async fn mitm_tls(
    tap: &Tap,
    authority: &str,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut stream = TcpStream::connect(tap.addr).await.unwrap();
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    read_until(&mut stream, &mut head, "\r\n\r\n").await;
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&tap.ca_pem).unwrap();
    for cert in rustls::pki_types::pem::PemObject::pem_slice_iter(&pem) {
        let cert: CertificateDer<'static> = cert.unwrap();
        roots.add(cert).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let host = authority.rsplit_once(':').unwrap().0.to_string();
    let name = rustls::pki_types::ServerName::try_from(host).unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .unwrap()
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;
type Handler = dyn Fn(Request<Incoming>) -> std::pin::Pin<Box<dyn Future<Output = Response<TestBody>> + Send>>
    + Send
    + Sync;

/// A body fed frame by frame from a channel; ends when the sender is dropped.
struct ChannelBody(tokio::sync::mpsc::Receiver<Result<hyper::body::Frame<Bytes>, BoxError>>);

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx)
    }
}

/// An h2 TLS upstream whose handler builds responses with any body.
async fn h2_upstream(pki: &Pki, handler: Arc<Handler>) -> SocketAddr {
    let tls = pki.server_config(&[b"h2"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (handler, tls) = (handler.clone(), tls.clone());
            tokio::spawn(async move {
                let Ok(stream) = TlsAcceptor::from(tls).accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Incoming>| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(request).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_inside_mitm_multiplexes_keeps_trailers_and_isolates_resets() {
    let tap = Tap::start("h2-streams", Options::default()).await;
    let handler: Arc<Handler> = Arc::new(|request: Request<Incoming>| {
        Box::pin(async move {
            let path = request.uri().path().to_string();
            if path == "/grpc" {
                // gRPC needs `te: trailers` upstream and the trailers back.
                let te = request.headers().get("te").cloned();
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                let body = Full::new(Bytes::from(format!("te={te:?}")))
                    .map_err(|never| match never {})
                    .with_trailers(async move { Some(Ok(trailers)) })
                    .boxed();
                return Response::new(body);
            }
            if path == "/broken" {
                let (sender, receiver) = tokio::sync::mpsc::channel(2);
                tokio::spawn(async move {
                    let part = hyper::body::Frame::data(Bytes::from_static(b"part"));
                    sender.send(Ok(part)).await.unwrap();
                    sleep(Duration::from_millis(50)).await;
                    let _ = sender.send(Err("upstream broke".into())).await;
                });
                return Response::new(ChannelBody(receiver).boxed());
            }
            sleep(Duration::from_millis(300)).await;
            let body = request.into_body().collect().await.unwrap().to_bytes();
            Response::new(Full::new(body).map_err(|never| match never {}).boxed())
        })
    });
    let addr = h2_upstream(&tap.pki, handler).await;
    let authority = format!("localhost:{}", addr.port());
    let tls = mitm_tls(&tap, &authority, &[b"h2"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    let request = |path: &str, body: &'static str| {
        Request::builder()
            .method("POST")
            .uri(format!("https://{authority}{path}"))
            .header("te", "trailers")
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap()
    };

    // 20 streams on one connection, each waiting 300ms upstream: concurrent, not queued.
    let started = Instant::now();
    let streams: Vec<_> = (0..20)
        .map(|i| {
            let mut sender = sender.clone();
            let request = request(&format!("/echo/{i}"), "same body");
            tokio::spawn(async move {
                let response = sender.send_request(request).await.unwrap();
                response.into_body().collect().await.unwrap().to_bytes()
            })
        })
        .collect();
    for stream in streams {
        assert_eq!(stream.await.unwrap(), "same body");
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );

    let mut sender = sender.clone();
    let response = sender.send_request(request("/grpc", "")).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().expect("trailers forwarded");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(collected.to_bytes(), r#"te=Some("trailers")"#);

    let response = sender.send_request(request("/broken", "")).await.unwrap();
    assert!(
        response.into_body().collect().await.is_err(),
        "the client sees the abort"
    );
    let response = sender
        .send_request(request("/after", "still fine"))
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "still fine",
        "one broken stream does not break the connection"
    );

    let found = tap.wait_for(23).await;
    let broken = found.iter().find(|e| e.request.path == "/broken").unwrap();
    let body = &broken.response.as_ref().unwrap().body;
    assert!(!body.complete && body.size == 4, "{body:?}");
    assert!(broken
        .notes
        .iter()
        .any(|note| note.contains("response body incomplete")));
    let grpc = found.iter().find(|e| e.request.path == "/grpc").unwrap();
    assert!(grpc.response.as_ref().unwrap().body.complete);
    assert!(found
        .iter()
        .all(|e| e.request.version == "HTTP/2" && e.mode == Mode::Mitm));
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrade_inside_mitm_relays_bytes() {
    let tap = Tap::start("wss", Options::default()).await;
    let addr = raw_tls_upstream(&tap.pki, &[b"http/1.1"], |mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        stream.write_all(&ping.to_ascii_uppercase()).await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    })
    .await;
    let authority = format!("localhost:{}", addr.port());
    let mut tls = mitm_tls(&tap, &authority, &[b"http/1.1"]).await;
    tls.write_all(
        format!(
            "GET /ws HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while find(&head, b"\r\n\r\n").is_none() {
        let read = timeout(WAIT, tls.read(&mut chunk)).await.unwrap().unwrap();
        assert!(read > 0);
        head.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
    assert!(
        head.starts_with("http/1.1 101 switching protocols\r\n"),
        "{head}"
    );
    tls.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    timeout(WAIT, tls.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"PING");
    drop(tls);
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Mitm);
    assert_eq!(exchange.request.url, format!("https://{authority}/ws"));
    assert_eq!(exchange.status(), Some(101));
    let stats = exchange.tunnel.unwrap();
    assert_eq!((stats.bytes_up, stats.bytes_down), (4, 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_keep_alive_inside_connect_records_each_request() {
    let tap = Tap::start("keep-alive", Options::default()).await;
    let server = upstream(None, echo).await;
    let addr = server.addr;
    let mut stream = TcpStream::connect(tap.addr).await.unwrap();
    stream
        .write_all(format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut data = Vec::new();
    read_until(&mut stream, &mut data, "\r\n\r\n").await;
    for body in ["first", "second"] {
        data.clear();
        let request = format!(
            "POST /{body} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        read_until(&mut stream, &mut data, body).await;
    }
    let found = tap.wait_for(2).await;
    let mut urls: Vec<String> = found.iter().map(|e| e.request.url.clone()).collect();
    urls.sort();
    assert_eq!(
        urls,
        [
            format!("http://{addr}/first"),
            format!("http://{addr}/second")
        ]
    );
}

// ---- hooks: buffering, hang-ups, what event hooks see ----

#[tokio::test(flavor = "multi_thread")]
async fn sync_hooks_reframe_chunked_bodies_with_one_content_length() {
    let hooks = HookConfig {
        on_request: vec![sync_hook(&["cat"])],
        on_response: vec![sync_hook(&["cat"])],
        ..Default::default()
    };
    let tap = Tap::start(
        "hook-chunked",
        Options {
            hooks,
            ..Default::default()
        },
    )
    .await;
    let (addr, upstream_task) = raw_upstream(|mut stream, _| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
    })
    .await;
    let request = format!(
        "POST http://{addr}/x HTTP/1.1\r\nHost: {addr}\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    );
    let text = String::from_utf8(raw_client(tap.addr, request.as_bytes()).await).unwrap();
    let lower = text.to_ascii_lowercase();
    assert_eq!(lower.matches("content-length: 5\r\n").count(), 1, "{text}");
    assert!(!lower.contains("transfer-encoding"), "{text}");
    assert!(text.ends_with("\r\n\r\nhello"), "{text}");
    let sent = String::from_utf8(upstream_task.await.unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert_eq!(sent.matches("content-length: 3\r\n").count(), 1, "{sent}");
    assert!(!sent.contains("transfer-encoding"), "{sent}");
    assert!(sent.ends_with("\r\n\r\nabc"), "{sent}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_hanging_up_during_a_sync_hook_keeps_what_it_sent() {
    let hooks = HookConfig {
        on_request: vec![sync_hook(&["sh", "-c", "cat >/dev/null; sleep 10"])],
        ..Default::default()
    };
    let tap = Tap::start(
        "hook-hangup",
        Options {
            hooks,
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{addr}/hang HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 4\r\n\r\nbody"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    let hung_up = Instant::now();
    drop(client);
    let exchange = tap.only().await;
    assert!(
        hung_up.elapsed() < Duration::from_secs(5),
        "the hook was stopped, not waited for"
    );
    assert!(exchange
        .error
        .as_deref()
        .unwrap()
        .contains("before it got a response"));
    assert_eq!(tap.body(&exchange.request.body.file), b"body");
    assert!(server.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn event_hooks_see_the_redacted_record_as_written() {
    let home = temp_home("event-input");
    let seen = home.join("event.json");
    let hooks = HookConfig {
        on_event: vec![sync_hook(&[
            "sh",
            "-c",
            &format!("cat > '{}'", seen.display()),
        ])],
        ..Default::default()
    };
    let tap = Tap::start(
        "event-hook",
        Options {
            hooks,
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let output = curl(&[
        "-x",
        &tap.proxy_url(),
        "-H",
        "x-api-key: sk-event-secret",
        "--data-binary",
        "payload",
        &server.url("http", "/event"),
    ])
    .await;
    assert_success(&output);
    let written = tap.only().await;
    let input: Exchange = serde_json::from_slice(&std::fs::read(&seen).unwrap()).unwrap();
    assert_eq!(input, written, "the hook saw exactly what was recorded");
    assert_eq!(input.request.body.file.as_deref(), Some("bodies/1.req"));
    assert!(header(&input.request.headers, "x-api-key")
        .unwrap()
        .starts_with("[REDACTED"));
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_sent_with_the_end_of_stream_are_forwarded_and_recorded() {
    let (go, gate) = oneshot::channel();
    let tap = Tap::start(
        "fire-and-forget",
        Options {
            gate: Some(gate),
            ..Default::default()
        },
    )
    .await;
    let server = upstream(None, echo).await;
    let addr = server.addr;
    // The request and the end of the client's stream are both waiting when TAP
    // first reads, so hyper drops the request before it is ever polled.
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    client
        .write_all(
            format!("POST http://{addr}/beacon HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 4\r\n\r\nping")
                .as_bytes(),
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    sleep(Duration::from_millis(100)).await;
    go.send(()).unwrap();
    let exchange = tap.only().await;
    assert_eq!(server.received()[0].body, "ping", "upstream got it");
    assert_eq!(exchange.request.path, "/beacon");
    assert_eq!(tap.body(&exchange.request.body.file), b"ping");
    let response = exchange.response.as_ref().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(tap.body(&response.body.file), b"ping");
    assert!(
        exchange
            .notes
            .iter()
            .any(|note| note.contains("never reached the client")),
        "{:?}",
        exchange.notes
    );
}

// ---- stopping ----

/// Stops `tap` and waits for `serve_until` to return, as `tap stop` does.
async fn stop(tap: &mut Tap, stop: oneshot::Sender<()>) {
    stop.send(()).unwrap();
    timeout(Duration::from_secs(5), &mut tap.task)
        .await
        .expect("serve_until returned after the drain")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_records_a_stream_in_progress_as_incomplete() {
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut tap = Tap::start(
        "stop-stream",
        Options {
            stop: Some(stop_rx),
            ..Default::default()
        },
    )
    .await;
    let (addr, _upstream) = raw_upstream(|mut stream, _| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        while stream.write_all(b"5\r\ntick\n\r\n").await.is_ok() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!("GET http://{addr}/forever HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "tick").await;

    let started = Instant::now();
    stop(&mut tap, stop_tx).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    let exchange = tap.only().await;
    let response = exchange.response.as_ref().unwrap();
    assert_eq!(response.status, 200);
    assert!(!response.body.complete, "{exchange:#?}");
    assert!(response.body.size >= 5);
    assert!(
        exchange
            .notes
            .iter()
            .any(|note| note == "TAP was stopped while this exchange was in progress"),
        "{:?}",
        exchange.notes
    );
    // The client's connection was closed.
    let mut rest = Vec::new();
    timeout(WAIT, client.read_to_end(&mut rest))
        .await
        .unwrap()
        .ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_while_waiting_for_a_response_records_why() {
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut tap = Tap::start(
        "stop-wait",
        Options {
            stop: Some(stop_rx),
            ..Default::default()
        },
    )
    .await;
    let (arrived, wait_arrived) = oneshot::channel::<()>();
    let (addr, _upstream) = raw_upstream(|mut stream, _| async move {
        arrived.send(()).unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!(
        "POST http://{addr}/slow HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 4\r\n\r\nwait"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    timeout(WAIT, wait_arrived).await.unwrap().unwrap();

    stop(&mut tap, stop_tx).await;
    let exchange = tap.only().await;
    assert_eq!(
        exchange.error.as_deref(),
        Some("TAP was stopped before the response arrived")
    );
    assert_eq!(tap.body(&exchange.request.body.file), b"wait");
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_records_open_tunnels_with_their_byte_counts() {
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut tap = Tap::start(
        "stop-tunnel",
        Options {
            no_intercept: true,
            stop: Some(stop_rx),
            ..Default::default()
        },
    )
    .await;
    let (addr, _upstream) = raw_upstream(|mut stream, _| async move {
        stream.write_all(b"hello from upstream").await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    })
    .await;
    let mut client = TcpStream::connect(tap.addr).await.unwrap();
    let request = format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    read_until(&mut client, &mut data, "\r\n\r\n").await;
    assert!(data.starts_with(b"HTTP/1.1 200"));
    // The upstream answers once it has read a message head.
    let ping = b"PING / HTTP/1.1\r\n\r\n";
    client.write_all(ping).await.unwrap();
    read_until(&mut client, &mut data, "hello from upstream").await;

    stop(&mut tap, stop_tx).await;
    let exchange = tap.only().await;
    assert_eq!(exchange.mode, Mode::Tunnel);
    let stats = exchange.tunnel.unwrap();
    assert_eq!(
        (stats.bytes_up, stats.bytes_down),
        (ping.len() as u64, 19),
        "{stats:?}"
    );
    assert!(
        exchange
            .notes
            .iter()
            .any(|note| note.contains("TAP was stopped while the tunnel was open")),
        "{:?}",
        exchange.notes
    );
    assert!(exchange
        .notes
        .iter()
        .any(|note| note == "TAP was stopped while this exchange was in progress"));
}

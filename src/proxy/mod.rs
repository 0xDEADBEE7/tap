//! The proxy engine. Each client connection speaks HTTP/1.1 to TAP; every request is
//! routed by its form:
//!
//! - `CONNECT host:port`: an opaque tunnel, or interception of the TLS (or plain
//!   HTTP) the client sends inside it (`connect`);
//! - absolute-form `http(s)://host/path`: forward-proxy mode;
//! - origin-form `/path` with the session's `upstream` set: reverse (base-URL) mode.
//!
//! All three end in one forwarding core (`forward`) that streams bodies through,
//! captures a bounded copy, runs hooks and writes one exchange record.

mod connect;
mod forward;
mod headers;
mod io;
mod upstream;

use crate::capture::{self, ProxyBody, Store};
use crate::filter::FilterSet;
use crate::hooks::Hooks;
use crate::record::{BodyRecord, Mode, RequestRecord};
use crate::tls::Ca;
use http::header::{HeaderValue, CONTENT_TYPE, HOST};
use http::uri::Authority;
use http::{Method, Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use regex::Regex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Everything a running session's proxy needs. Built by `session::run` from
/// metadata.json, or directly by tests.
pub struct Runtime {
    pub session_id: String,
    pub session_dir: PathBuf,
    /// Capture scope (never blocks traffic).
    pub filters: FilterSet,
    pub hooks: Hooks,
    pub store: Arc<Store>,
    /// None disables HTTPS interception: every CONNECT is relayed as an opaque tunnel.
    pub ca: Option<Arc<Ca>>,
    /// CONNECT hosts matching any of these are tunneled, never intercepted.
    pub tunnel_hosts: Vec<Regex>,
    /// Base URL for origin-form requests (reverse / base-URL mode), e.g. `https://api.anthropic.com`.
    pub upstream: Option<http::Uri>,
    /// Extra PEM roots trusted for upstream TLS (corporate CAs, tests).
    pub upstream_ca: Option<PathBuf>,
    /// Lowercase header names to redact in records.
    pub redact: Vec<String>,
    /// Per-body capture limit in bytes.
    pub max_body: u64,
    pub connect_timeout: Duration,
    /// Limit on waiting for the upstream response head.
    pub response_timeout: Duration,
}

/// How long a client may take to send a request head.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest an intercepted client's TLS handshake waits to learn whether its
/// upstream speaks HTTP/2 (clients time out handshakes, then never see TAP's 502).
const ALPN_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long an upstream that could not be probed is not probed again.
const ALPN_RETRY: Duration = Duration::from_secs(30);
/// How long a stopping proxy waits for the exchanges it cut off to be recorded
/// (`tap stop` allows the process 5s before it kills it).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// State shared by every connection of one [`serve`] call.
struct Proxy {
    runtime: Arc<Runtime>,
    clients: upstream::Clients,
    /// The listening address, to refuse requests that would loop back into TAP.
    local: SocketAddr,
    /// `host:port` of intercepted upstreams → whether they negotiate HTTP/2
    /// (None: could not be told, retried after [`ALPN_RETRY`]) and when that was learned.
    upstream_h2: Mutex<HashMap<String, (Option<bool>, Instant)>>,
    drain: Drain,
}

/// How a stop reaches the connections, and which exchanges it must wait for.
struct Drain {
    /// Becomes true when the proxy stops: client connections and tunnels are cut.
    stopping: watch::Sender<bool>,
    /// Exchanges started but not yet handed to the store.
    recording: watch::Sender<usize>,
}

/// Counts one exchange as being recorded until it is dropped.
pub(super) struct Recording(Arc<Proxy>);

impl Drop for Recording {
    fn drop(&mut self) {
        self.0.drain.recording.send_modify(|count| *count -= 1);
    }
}

impl Proxy {
    /// Call before an exchange starts; keep it until the exchange is recorded or dropped.
    pub(super) fn recording(self: &Arc<Proxy>) -> Recording {
        self.drain.recording.send_modify(|count| *count += 1);
        Recording(self.clone())
    }

    pub(super) fn is_stopping(&self) -> bool {
        *self.drain.stopping.borrow()
    }

    /// Resolves when the proxy stops.
    pub(super) fn stopped(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut stopping = self.drain.stopping.subscribe();
        async move {
            let _ = stopping.wait_for(|stopping| *stopping).await;
        }
    }
}

/// Serves proxy connections from `listener` until the process exits.
pub async fn serve(listener: TcpListener, runtime: Arc<Runtime>) -> std::io::Result<()> {
    serve_until(listener, runtime, std::future::pending()).await
}

/// Serves proxy connections from `listener` until `stop` resolves. Then it stops
/// accepting, cuts the connections still open (a stream in progress is recorded
/// as incomplete) and waits briefly for those exchanges to be recorded.
pub async fn serve_until(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    stop: impl Future<Output = ()>,
) -> std::io::Result<()> {
    // Loading the platform's roots blocks (tens of milliseconds, more under load).
    let clients = {
        let runtime = runtime.clone();
        tokio::task::spawn_blocking(move || upstream::Clients::new(&runtime))
            .await
            .map_err(std::io::Error::other)??
    };
    let local = listener.local_addr()?;
    let proxy = Arc::new(Proxy {
        runtime,
        clients,
        local,
        upstream_h2: Mutex::new(HashMap::new()),
        drain: Drain {
            stopping: watch::Sender::new(false),
            recording: watch::Sender::new(0),
        },
    });
    tokio::select! {
        result = accept(&proxy, listener) => result,
        () = stop => {
            proxy.drain.stopping.send_replace(true);
            let mut recording = proxy.drain.recording.subscribe();
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, recording.wait_for(|count| *count == 0)).await;
            Ok(())
        }
    }
}

async fn accept(proxy: &Arc<Proxy>, listener: TcpListener) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(serve_client(proxy.clone(), stream, peer));
            }
            Err(error) => {
                // Usually EMFILE: wait for connections to close instead of spinning.
                log(format_args!(
                    "cannot accept a connection: {error}; retrying"
                ));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn serve_client(proxy: Arc<Proxy>, stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_nodelay(true);
    let client: Arc<str> = peer.to_string().into();
    let stopped = proxy.stopped();
    let service = {
        let client = client.clone();
        service_fn(move |request| {
            let (proxy, client) = (proxy.clone(), client.clone());
            let response = forward::detachable(request, |request| route(proxy, client, request));
            async move { Ok::<_, Infallible>(response.await) }
        })
    };
    let connection = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::select! {
        served = connection => {
            if let Err(error) = served {
                log_connection_error(&client, &error);
            }
        }
        // Dropping the connection ends its bodies, so their exchanges are recorded as cut off.
        () = stopped => {}
    }
}

async fn route(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    if request.method() == Method::CONNECT {
        return connect::connect(proxy, client, request).await;
    }
    if request.uri().scheme().is_some() {
        return match Target::absolute(request.uri()) {
            Ok(target) => forward::forward(proxy, client, Mode::Forward, target, request).await,
            Err(problem) => {
                let record = unroutable_record(&proxy, &request);
                reject(
                    proxy,
                    client,
                    Mode::Forward,
                    record,
                    StatusCode::BAD_REQUEST,
                    problem,
                )
            }
        };
    }
    match proxy.runtime.upstream.as_ref() {
        Some(upstream) => {
            let target = Target::reverse(upstream, request.uri());
            forward::forward(proxy, client, Mode::Reverse, target, request).await
        }
        None => {
            let record = unroutable_record(&proxy, &request);
            let port = proxy.local.port();
            let problem = format!(
                "this is a TAP proxy port, and {} {} is not a proxy request. Send requests through \
                 TAP as a proxy (HTTP_PROXY / HTTPS_PROXY=http://127.0.0.1:{port}, or run the client \
                 with `tap exec`), or create the session with --upstream URL to forward plain \
                 requests to that base URL",
                record.method, record.path
            );
            reject(
                proxy,
                client,
                Mode::Reverse,
                record,
                StatusCode::BAD_REQUEST,
                problem,
            )
        }
    }
}

/// Answers a request TAP cannot route with `status` and `problem`, and records it as failed.
fn reject(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    mode: Mode,
    record: RequestRecord,
    status: StatusCode,
    problem: String,
) -> Response<ProxyBody> {
    let start = forward::Start::now();
    let response = text_response(status, &format!("tap: {problem}"));
    let recording = proxy.recording();
    tokio::spawn(async move {
        forward::record_failure(&proxy, start, mode, &client, record, problem).await;
        drop(recording);
    });
    response
}

/// Where a request goes upstream. `host` is as in a URI (IPv6 in brackets).
#[derive(Clone, Debug)]
struct Target {
    scheme: &'static str,
    host: String,
    port: u16,
    /// Path plus query, starting with `/`.
    path: String,
}

impl Target {
    fn absolute(uri: &Uri) -> Result<Target, String> {
        let scheme = match uri.scheme_str() {
            Some(scheme) if scheme.eq_ignore_ascii_case("http") => "http",
            Some(scheme) if scheme.eq_ignore_ascii_case("https") => "https",
            other => {
                return Err(format!(
                    "cannot forward {uri}: the scheme {:?} is not supported (only http:// and https://)",
                    other.unwrap_or_default()
                ))
            }
        };
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| format!("cannot forward {uri}: the URL has no host"))?;
        Ok(Target {
            scheme,
            host: host.to_string(),
            port: uri.port_u16().unwrap_or(default_port(scheme)),
            path: path_of(uri),
        })
    }

    /// The session's upstream base URL joined with an origin-form request target.
    fn reverse(upstream: &Uri, request: &Uri) -> Target {
        let scheme = if upstream.scheme_str() == Some("https") {
            "https"
        } else {
            "http"
        };
        let base = upstream.path().trim_end_matches('/');
        Target {
            scheme,
            host: upstream.host().unwrap_or_default().to_string(),
            port: upstream.port_u16().unwrap_or(default_port(scheme)),
            path: format!("{base}{}", path_of(request)),
        }
    }

    /// `host` or `host:port` when the port is not the scheme's default.
    fn authority(&self) -> String {
        if self.port == default_port(self.scheme) {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}://{}{path}", self.scheme, self.authority())
    }

    fn uri(&self, path: &str) -> Result<Uri, http::Error> {
        Uri::builder()
            .scheme(self.scheme)
            .authority(self.authority())
            .path_and_query(path)
            .build()
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

/// Path plus query of a request target, always starting with `/`.
fn path_of(uri: &Uri) -> String {
    match uri.path_and_query().map(|path| path.as_str()) {
        Some(path) if path.starts_with('/') => path.to_string(),
        Some(path) if !path.is_empty() && path != "*" => format!("/{path}"),
        _ => "/".to_string(),
    }
}

/// A record for a request TAP could not route, addressed as well as it can tell.
fn unroutable_record(proxy: &Proxy, request: &Request<Incoming>) -> RequestRecord {
    let uri = request.uri();
    let host_header = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Authority>().ok());
    let (host, port) = match uri.authority().or(host_header.as_ref()) {
        Some(authority) => (
            authority.host().to_string(),
            authority.port_u16().unwrap_or(80),
        ),
        None => (proxy.local.ip().to_string(), proxy.local.port()),
    };
    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    let path = path_of(uri);
    let url = if uri.scheme().is_some() {
        uri.to_string()
    } else {
        let target = Target {
            scheme: "http",
            host: host.clone(),
            port,
            path: path.clone(),
        };
        target.url(&path)
    };
    RequestRecord {
        method: request.method().as_str().to_string(),
        url,
        scheme,
        host,
        port,
        path,
        version: headers::version_name(request.version()).to_string(),
        headers: headers::record(request.headers()),
        body: BodyRecord {
            complete: true,
            ..Default::default()
        },
    }
}

impl Proxy {
    /// Whether the TLS server at `host:port` negotiates HTTP/2, so an intercepted
    /// client is offered the protocol it would have got without TAP. Learned once
    /// per upstream; None when it cannot be told (unreachable, TLS failure).
    async fn upstream_h2(&self, host: &str, port: u16) -> Option<bool> {
        if self.is_self(host, port) {
            return None;
        }
        let key = format!("{}:{port}", host.to_ascii_lowercase());
        let known = self.upstream_h2_cache().get(&key).copied();
        match known {
            Some((Some(h2), _)) => return Some(h2),
            Some((None, at)) if at.elapsed() < ALPN_RETRY => return None,
            _ => {}
        }
        let timeout = self.runtime.connect_timeout.min(ALPN_PROBE_TIMEOUT);
        let h2 = self.clients.speaks_h2(host, port, timeout).await;
        self.upstream_h2_cache().insert(key, (h2, Instant::now()));
        h2
    }

    fn upstream_h2_cache(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, (Option<bool>, Instant)>> {
        self.upstream_h2
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `host:port` is TAP's own listening address (a request there would loop).
    fn is_self(&self, host: &str, port: u16) -> bool {
        if port != self.local.port() {
            return false;
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match bare.parse::<IpAddr>() {
            Ok(ip) => ip == self.local.ip() || ip.is_unspecified(),
            Err(_) => {
                let name = bare.trim_end_matches('.');
                name.eq_ignore_ascii_case("localhost") && self.local.ip().is_loopback()
            }
        }
    }
}

/// A plain-text response from TAP itself. `x-tap-error` repeats the message on one line.
fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(capture::full(format!("{message}\n")));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let one_line: String = message
        .chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c
            } else {
                '?'
            }
        })
        .take(1000)
        .collect();
    if let Ok(value) = HeaderValue::from_str(&one_line) {
        headers.insert("x-tap-error", value);
    }
    response
}

/// Prints `tap: <message>` on stderr (the session log), ignoring write failures.
fn log(message: std::fmt::Arguments) {
    let _ = writeln!(std::io::stderr(), "tap: {message}");
}

/// Logs a client connection error unless it is the routine end of a connection
/// (client gone, reset, idle timeout).
fn log_connection_error(client: &str, error: &(dyn Error + 'static)) {
    if is_routine(error) {
        return;
    }
    let parse = error
        .downcast_ref::<hyper::Error>()
        .is_some_and(hyper::Error::is_parse);
    let hint = if parse {
        " (the client does not speak HTTP to the proxy port; if it sent TLS, its proxy URL \
         must start with http://, not https://)"
    } else {
        ""
    };
    log(format_args!(
        "connection from {client}: {}{hint}",
        upstream::chain(error)
    ));
}

fn is_routine(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<hyper::Error>() {
            if error.is_incomplete_message()
                || error.is_canceled()
                || error.is_closed()
                || error.is_timeout()
            {
                return true;
            }
        }
        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            if matches!(
                error.kind(),
                ConnectionReset
                    | ConnectionAborted
                    | BrokenPipe
                    | UnexpectedEof
                    | NotConnected
                    | TimedOut
            ) {
                return true;
            }
        }
        current = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_urls() {
        let target = Target::absolute(&"http://Example.com:80/a?b=1".parse().unwrap()).unwrap();
        assert_eq!(target.url(&target.path), "http://Example.com/a?b=1");
        let target = Target::absolute(&"https://[::1]:8443".parse().unwrap()).unwrap();
        assert_eq!((target.host.as_str(), target.port), ("[::1]", 8443));
        assert_eq!(target.url(&target.path), "https://[::1]:8443/");
        assert_eq!(
            target.uri(&target.path).unwrap().to_string(),
            "https://[::1]:8443/"
        );
        assert!(Target::absolute(&"ftp://example.com/x".parse().unwrap()).is_err());
    }

    #[test]
    fn reverse_joins_base_path() {
        let upstream: Uri = "https://api.example.com/base/".parse().unwrap();
        let target = Target::reverse(&upstream, &"/v1/messages?beta=1".parse().unwrap());
        assert_eq!(
            target.url(&target.path),
            "https://api.example.com/base/v1/messages?beta=1"
        );
        let upstream: Uri = "http://127.0.0.1:9000".parse().unwrap();
        let target = Target::reverse(&upstream, &"/x".parse().unwrap());
        assert_eq!(target.url(&target.path), "http://127.0.0.1:9000/x");
    }
}

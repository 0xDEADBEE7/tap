//! `CONNECT host:port`: an opaque tunnel, or interception of what the client sends
//! inside it: TLS (decrypted with a leaf certificate from the TAP CA) or plain HTTP.

use super::forward::{self, Start};
use super::io::{relay, Prefixed};
use super::{headers, log_connection_error, text_response, Proxy, Target, HEADER_READ_TIMEOUT};
use crate::capture::{self, ProxyBody};
use crate::filter::Facts;
use crate::record::{BodyRecord, Mode, RequestRecord};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::server::{Acceptor, ClientHello};
use rustls::ServerConfig;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::LazyConfigAcceptor;

/// Clients that speak first (TLS, HTTP) do so at once. One that stays silent this
/// long is waiting for the server (SSH, SMTP, ...) and gets an opaque tunnel.
const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE: u8 = 0x16;

pub(super) async fn connect(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    let start = Start::now();
    let Some(authority) = request.uri().authority().cloned() else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "tap: CONNECT needs a host:port target, e.g. CONNECT api.example.com:443",
        );
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    let record = connect_record(&request, &host, port);
    let runtime = &proxy.runtime;
    let tunneled = runtime.ca.is_none() || {
        let name = host.to_ascii_lowercase();
        runtime
            .tunnel_hosts
            .iter()
            .any(|pattern| pattern.is_match(&name))
    };
    if tunneled {
        return tunnel(proxy, client, start, record, request).await;
    }
    let on_upgrade = hyper::upgrade::on(request);
    tokio::spawn(async move {
        // An error here means the client went away before the tunnel opened.
        if let Ok(upgraded) = on_upgrade.await {
            intercept(proxy, client, start, record, TokioIo::new(upgraded)).await;
        }
    });
    Response::new(capture::empty())
}

/// Connects upstream first, so a failure can still be answered with a `502`.
async fn tunnel(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    start: Start,
    record: RequestRecord,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    let in_scope = proxy
        .runtime
        .filters
        .matches(&Facts::request(&record, Mode::Tunnel.as_str()));
    let upstream = match dial(&proxy, &record.host, record.port).await {
        Ok(upstream) => upstream,
        Err(problem) => {
            let response = text_response(StatusCode::BAD_GATEWAY, &format!("tap: {problem}"));
            if in_scope {
                let recording = proxy.recording();
                tokio::spawn(async move {
                    forward::record_failure(&proxy, start, Mode::Tunnel, &client, record, problem)
                        .await;
                    drop(recording);
                });
            }
            return response;
        }
    };
    let exchange =
        in_scope.then(|| forward::new_exchange(&proxy, start, Mode::Tunnel, &client, record));
    let recording = exchange.as_ref().map(|_| proxy.recording());
    let on_upgrade = hyper::upgrade::on(request);
    tokio::spawn(async move {
        let (stats, error) = match on_upgrade.await {
            Ok(upgraded) => relay(TokioIo::new(upgraded), upstream, proxy.stopped()).await,
            Err(_) => {
                let gone = "the client went away before it used the tunnel";
                (Default::default(), Some(io::Error::other(gone)))
            }
        };
        if let Some(exchange) = exchange {
            forward::record_tunnel(&proxy, start, exchange, stats, error).await;
        }
        drop(recording);
    });
    Response::new(capture::empty())
}

/// Looks at the client's first bytes to decide how to serve the tunnel.
async fn intercept(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    start: Start,
    record: RequestRecord,
    mut io: TokioIo<Upgraded>,
) {
    let mut first = vec![0u8; 4096];
    let reason = match tokio::time::timeout(FIRST_BYTES_TIMEOUT, io.read(&mut first)).await {
        Ok(Ok(0)) | Ok(Err(_)) => return,
        Ok(Ok(read)) => {
            first.truncate(read);
            let kind = first[0];
            let io = Prefixed::new(Bytes::from(first), io);
            if kind == TLS_HANDSHAKE {
                return intercept_tls(proxy, client, start, record, io).await;
            }
            if kind.is_ascii_uppercase() {
                // An HTTP method: plain HTTP inside the tunnel (Node's fetch does this for http:// URLs).
                return serve_inner(proxy, client, "http", record.host, record.port, io, None)
                    .await;
            }
            return opaque(
                proxy,
                client,
                start,
                record,
                io,
                "the client's first bytes were neither TLS nor HTTP",
            )
            .await;
        }
        Err(_) => "the client sent nothing at first (a protocol where the server speaks first)",
    };
    opaque(
        proxy,
        client,
        start,
        record,
        Prefixed::new(Bytes::new(), io),
        reason,
    )
    .await;
}

async fn intercept_tls(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    start: Start,
    mut record: RequestRecord,
    io: Prefixed<TokioIo<Upgraded>>,
) {
    record.scheme = "https".into();
    let Some(ca) = proxy.runtime.ca.clone() else {
        return;
    };
    let (host, port) = (record.host.clone(), record.port);
    let failed = |problem: String| async {
        forward::record_failure(&proxy, start, Mode::Mitm, &client, record, problem).await;
    };
    let config = match ca.server_config(&host) {
        Ok(config) => config,
        Err(error) => return failed(format!("cannot intercept {host}:{port}: {error}")).await,
    };
    let handshake = async {
        let hello = LazyConfigAcceptor::new(Acceptor::default(), io).await?;
        let config = match offered(&hello.client_hello()) {
            // Offer HTTP/2 only if upstream speaks it, so the client speaks what it would without TAP.
            Offered {
                h2: true,
                http1: true,
            } if proxy.upstream_h2(&host, port).await == Some(false) => http1_only(&config),
            _ => config,
        };
        hello.into_stream(config).await
    };
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => return failed(untrusted(&host, port, &error)).await,
        Err(_) => {
            let seconds = HANDSHAKE_TIMEOUT.as_secs();
            return failed(format!(
                "the client did not finish the TLS handshake for {host}:{port} within {seconds}s"
            ))
            .await;
        }
    };
    let h2 = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| protocol == b"h2");
    serve_inner(proxy.clone(), client.clone(), "https", host, port, tls, h2).await;
}

/// The application protocols a client offers (ALPN).
struct Offered {
    h2: bool,
    http1: bool,
}

fn offered(hello: &ClientHello) -> Offered {
    let mut offered = Offered {
        h2: false,
        http1: false,
    };
    for protocol in hello.alpn().into_iter().flatten() {
        offered.h2 |= protocol == b"h2";
        offered.http1 |= protocol == b"http/1.1";
    }
    offered
}

/// `config` advertising only HTTP/1.1.
fn http1_only(config: &ServerConfig) -> Arc<ServerConfig> {
    let mut config = config.clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn untrusted(host: &str, port: u16, error: &io::Error) -> String {
    format!(
        "TLS handshake with the client for {host}:{port} failed ({error}). The client probably does \
         not trust TAP's CA: it then reports an unknown issuer (UnknownIssuer / unknown CA), or a bad \
         signature (BadSignature) when it trusts a different TAP CA. Run `tap ca` to see how to trust \
         it, or start the client with `tap exec` so it trusts TAP's CA"
    )
}

/// Serves the HTTP requests inside an intercepted tunnel; each one goes to the
/// CONNECT target. `h2` is the ALPN choice (None: detect from the first bytes).
async fn serve_inner<I>(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    scheme: &'static str,
    host: String,
    port: u16,
    io: I,
    h2: Option<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stopped = proxy.stopped();
    let service = {
        let client = client.clone();
        service_fn(move |request: Request<Incoming>| {
            let (proxy, client) = (proxy.clone(), client.clone());
            let target = Target {
                scheme,
                host: host.clone(),
                port,
                path: super::path_of(request.uri()),
            };
            let connect = request.method() == Method::CONNECT;
            let response = forward::detachable(request, |request| {
                forward::forward(proxy, client, Mode::Mitm, target, request)
            });
            async move {
                if connect {
                    return Ok::<_, Infallible>(text_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "tap: CONNECT inside an intercepted tunnel is not supported",
                    ));
                }
                Ok(response.await)
            }
        })
    };
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder.http2().timer(TokioTimer::new());
    let builder = match h2 {
        Some(true) => builder.http2_only(),
        Some(false) => builder.http1_only(),
        None => builder,
    };
    tokio::select! {
        served = builder.serve_connection_with_upgrades(TokioIo::new(io), service) => {
            if let Err(error) = served {
                log_connection_error(&client, &*error);
            }
        }
        () = stopped => {}
    }
}

/// Relays a tunnel TAP meant to intercept but cannot understand, recording it as a tunnel.
async fn opaque<I>(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    start: Start,
    record: RequestRecord,
    io: I,
    reason: &str,
) where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let in_scope = proxy
        .runtime
        .filters
        .matches(&Facts::request(&record, Mode::Tunnel.as_str()));
    let upstream = match dial(&proxy, &record.host, record.port).await {
        Ok(upstream) => upstream,
        Err(problem) => {
            if in_scope {
                forward::record_failure(&proxy, start, Mode::Tunnel, &client, record, problem)
                    .await;
            }
            return;
        }
    };
    let mut exchange =
        in_scope.then(|| forward::new_exchange(&proxy, start, Mode::Tunnel, &client, record));
    let _recording = exchange.as_ref().map(|_| proxy.recording());
    if let Some(exchange) = exchange.as_mut() {
        exchange.notes.push(format!(
            "relayed as an opaque tunnel without interception: {reason}"
        ));
    }
    let (stats, error) = relay(io, upstream, proxy.stopped()).await;
    if let Some(exchange) = exchange {
        forward::record_tunnel(&proxy, start, exchange, stats, error).await;
    }
}

/// Connects to `host:port`, trying each resolved address in turn. Each attempt
/// gets an equal share of the time left, so an unreachable first address (a
/// broken IPv6 route) does not use up the whole connect timeout.
async fn dial(proxy: &Proxy, host: &str, port: u16) -> Result<TcpStream, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let timeout = proxy.runtime.connect_timeout;
    let deadline = tokio::time::Instant::now() + timeout;
    let failed = |reason: String| format!("cannot open a tunnel to {host}:{port}: {reason}");
    let timed_out = || {
        failed(format!(
            "no connection within {}s (the connect timeout)",
            timeout.as_secs_f64()
        ))
    };
    let addresses: Vec<SocketAddr> =
        match tokio::time::timeout_at(deadline, lookup_host((bare, port))).await {
            Ok(Ok(addresses)) => addresses.collect(),
            Ok(Err(error)) => return Err(failed(error.to_string())),
            Err(_) => return Err(timed_out()),
        };
    let mut last_error = None;
    for (index, address) in addresses.iter().enumerate() {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let share = left / u32::try_from(addresses.len() - index).unwrap_or(u32::MAX);
        match tokio::time::timeout(share, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("{address} did not answer")),
        }
    }
    match last_error {
        Some(reason) if addresses.len() > 1 => Err(failed(format!(
            "{reason} (tried {} addresses)",
            addresses.len()
        ))),
        Some(reason) => Err(failed(reason)),
        None => Err(failed("the host name resolved to no addresses".into())),
    }
}

/// The record of a CONNECT request: `host:port`, scheme `tcp`, no path.
fn connect_record(request: &Request<Incoming>, host: &str, port: u16) -> RequestRecord {
    RequestRecord {
        method: Method::CONNECT.to_string(),
        url: format!("{host}:{port}"),
        scheme: "tcp".into(),
        host: host.to_string(),
        port,
        path: String::new(),
        version: headers::version_name(request.version()).to_string(),
        headers: headers::record(request.headers()),
        body: BodyRecord {
            complete: true,
            ..Default::default()
        },
    }
}

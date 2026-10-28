//! The HTTP(S) client TAP forwards requests with, and how its failures are described.

use super::Runtime;
use crate::capture::ProxyBody;
use crate::tls;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::pki_types::ServerName;
use std::error::Error;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub(super) type HttpClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

pub(super) struct Clients {
    /// HTTP/1.1 or HTTP/2, whichever the upstream picks via ALPN.
    pub(super) any: HttpClient,
    /// HTTP/1.1 only: upgrades (WebSocket) do not exist in HTTP/2, and a
    /// client that speaks HTTP/1.1 to TAP gets it upstream too.
    pub(super) http1: HttpClient,
    /// Offers `h2` and `http/1.1`, to learn what an upstream negotiates.
    probe: Arc<rustls::ClientConfig>,
}

impl Clients {
    /// Loads the trusted roots once (it takes tens of milliseconds).
    pub(super) fn new(runtime: &Runtime) -> io::Result<Clients> {
        let config = tls::upstream_client_config(runtime.upstream_ca.as_deref())?;
        let mut probe = config.clone();
        probe.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let any = HttpsConnectorBuilder::new()
            .with_tls_config(config.clone())
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector(runtime));
        let http1 = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector(runtime));
        Ok(Clients {
            any: client(any),
            http1: client(http1),
            probe: Arc::new(probe),
        })
    }

    /// Whether `host:port` negotiates HTTP/2 over TLS, found with a TLS
    /// handshake that is closed right away. None when it cannot be told
    /// (unreachable, TLS failure, `timeout`).
    pub(super) async fn speaks_h2(&self, host: &str, port: u16, timeout: Duration) -> Option<bool> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let name = ServerName::try_from(bare.to_string()).ok()?;
        let probe = async {
            let tcp = TcpStream::connect((bare, port)).await.ok()?;
            let _ = tcp.set_nodelay(true);
            let tls = TlsConnector::from(self.probe.clone())
                .connect(name, tcp)
                .await
                .ok()?;
            Some(tls.get_ref().1.alpn_protocol() == Some(b"h2"))
        };
        tokio::time::timeout(timeout, probe).await.ok().flatten()
    }
}

fn connector(runtime: &Runtime) -> HttpConnector {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(runtime.connect_timeout));
    http
}

fn client(connector: HttpsConnector<HttpConnector>) -> HttpClient {
    Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .pool_timer(TokioTimer::new())
        .http1_preserve_header_case(true)
        .build(connector)
}

/// Describes a failed upstream request with its whole cause chain, e.g.
/// `cannot connect to api.example.com: tcp connect error: Connection refused (os error 61)`.
/// The client's own top-level message (`client error (Connect)`) says nothing and is left out.
pub(super) fn describe(error: &hyper_util::client::legacy::Error, authority: &str) -> String {
    let causes = error.source().map(chain).unwrap_or_default();
    let causes = if causes.is_empty() {
        error.to_string()
    } else {
        causes
    };
    if error.is_connect() {
        format!("cannot connect to {authority}: {causes}")
    } else {
        causes
    }
}

/// `error` and its sources joined with `: `, skipping messages that repeat the previous one.
pub(super) fn chain(error: &(dyn Error + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut current = Some(error);
    while let Some(error) = current {
        let text = error.to_string();
        let repeated = parts.last().is_some_and(|last| last.contains(&text));
        if !text.is_empty() && !repeated {
            parts.push(text);
        }
        current = error.source();
    }
    parts.join(": ")
}

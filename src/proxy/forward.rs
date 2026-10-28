//! The forwarding core shared by forward, MITM and reverse mode: one request sent
//! upstream and its response streamed back, with capture, hooks and the record.

use super::io::{relay, Activity};
use super::{headers, text_response, upstream, Proxy, Recording, Target};
use crate::capture::{self, redact, Captured, ProxyBody};
use crate::filter::Facts;
use crate::hooks::{HookContext, HookMessage};
use crate::record::{self, BodyRecord, Exchange, Mode, RequestRecord, ResponseRecord, TunnelStats};
use bytes::Bytes;
use http::request::Parts;
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::ext::ReasonPhrase;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// How long a detached request's response is read for its record.
const DETACHED_DRAIN: Duration = Duration::from_secs(30);
const DETACHED_NOTE: &str = "the client ended its side of the connection together with this request \
     (it closed or half-closed it), so TAP forwarded the request but could not answer; the response \
     recorded here never reached the client";

/// Set on a request whose handler was detached (see [`detachable`]).
#[derive(Clone, Default)]
struct Detached(Arc<AtomicBool>);

impl Detached {
    fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// `handler(request)`, which still runs when hyper drops it before its first
/// poll. Hyper does that when the client's end of stream arrives along with
/// the request: it sent the request and closed (fire and forget), or
/// half-closed to wait for the answer. The handler then runs in the background,
/// so the request reaches upstream and the record as it would without TAP, and
/// the response is read for the record. Only HTTP/1 requests are detached: an
/// HTTP/2 client cancels a stream explicitly, and a CONNECT tunnel needs its client.
pub(super) fn detachable<F>(
    mut request: Request<Incoming>,
    handler: impl FnOnce(Request<Incoming>) -> F,
) -> Detachable<F>
where
    F: Future<Output = Response<ProxyBody>> + Send + 'static,
{
    let http1 = request.version() < Version::HTTP_2;
    let detached = (http1 && request.method() != Method::CONNECT).then(|| {
        let detached = Detached::default();
        request.extensions_mut().insert(detached.clone());
        detached
    });
    Detachable {
        future: Some(Box::pin(handler(request))),
        detached,
    }
}

pub(super) struct Detachable<F: Future<Output = Response<ProxyBody>> + Send + 'static> {
    future: Option<Pin<Box<F>>>,
    /// None once polled (from then on, hyper dropping it means the client went away).
    detached: Option<Detached>,
}

impl<F: Future<Output = Response<ProxyBody>> + Send + 'static> Future for Detachable<F> {
    type Output = Response<ProxyBody>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.detached = None;
        let Some(future) = this.future.as_mut() else {
            return Poll::Pending;
        };
        let poll = future.as_mut().poll(cx);
        if poll.is_ready() {
            this.future = None;
        }
        poll
    }
}

impl<F: Future<Output = Response<ProxyBody>> + Send + 'static> Drop for Detachable<F> {
    fn drop(&mut self) {
        let (Some(detached), Some(future)) = (self.detached.take(), self.future.take()) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        detached.0.store(true, Ordering::Relaxed);
        runtime.spawn(async move {
            let body = future.await.into_body();
            let _ = tokio::time::timeout(DETACHED_DRAIN, body.collect()).await;
        });
    }
}

/// When an exchange started, for `started_at`, `ttfb_ms` and `duration_ms`.
#[derive(Clone, Copy)]
pub(super) struct Start {
    instant: Instant,
    unix_ms: u64,
}

impl Start {
    pub(super) fn now() -> Start {
        Start {
            instant: Instant::now(),
            unix_ms: record::unix_ms_now(),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.instant.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Forwards one request to `target` and returns the response for the client.
/// In-scope exchanges are captured and recorded once both bodies have finished.
pub(super) async fn forward(
    proxy: Arc<Proxy>,
    client: Arc<str>,
    mode: Mode,
    target: Target,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    let start = Start::now();
    let record = RequestRecord {
        method: request.method().as_str().to_string(),
        url: target.url(&target.path),
        scheme: target.scheme.to_string(),
        host: target.host.clone(),
        port: target.port,
        path: target.path.clone(),
        version: headers::version_name(request.version()).to_string(),
        headers: headers::record(request.headers()),
        body: BodyRecord::default(),
    };
    if proxy
        .runtime
        .filters
        .matches(&Facts::request(&record, mode.as_str()))
    {
        let mut exchange = new_exchange(&proxy, start, mode, &client, record);
        if request
            .extensions()
            .get::<Detached>()
            .is_some_and(Detached::is_set)
        {
            exchange.notes.push(DETACHED_NOTE.into());
        }
        recorded(proxy, start, exchange, target, request).await
    } else {
        unrecorded(proxy, mode, target, request).await
    }
}

/// Whether to forward with the HTTP/1.1-only client: for upgrades, and for an
/// intercepted client that chose HTTP/1 (offered no `h2`, or upstream lacks it),
/// so upstream sees the protocol it would without TAP. Elsewhere the client
/// cannot express a choice and HTTP/2 is used when upstream offers it.
fn http1_upstream(mode: Mode, version: Version, upgrade: bool) -> bool {
    upgrade || (mode == Mode::Mitm && version != Version::HTTP_2)
}

/// Out of scope: forwarded exactly like recorded traffic, but nothing is captured or run.
async fn unrecorded(
    proxy: Arc<Proxy>,
    mode: Mode,
    target: Target,
    mut request: Request<Incoming>,
) -> Response<ProxyBody> {
    let upgrade = headers::is_upgrade(request.headers());
    let http1 = http1_upstream(mode, request.version(), upgrade);
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let url = target.url(&target.path);
    let outgoing = upstream_request(
        parts,
        capture::boxed(body),
        &target,
        &target.path,
        upgrade,
        None,
    );
    let sent = match outgoing {
        Ok(outgoing) => send(&proxy, outgoing, &target, http1).await,
        Err(problem) => Err(problem),
    };
    let mut response = match sent {
        Ok(response) => response,
        Err(problem) => return bad_gateway(&url, &problem),
    };
    let switched = take_upgrade(&mut response, client_upgrade);
    let (mut parts, body) = response.into_parts();
    headers::to_client(&mut parts.headers, switched.is_some());
    parts.version = Version::HTTP_11;
    if let Some(sides) = switched {
        tokio::spawn(splice(sides, proxy.stopped()));
        return Response::from_parts(parts, capture::empty());
    }
    Response::from_parts(parts, capture::boxed(body))
}

async fn recorded(
    proxy: Arc<Proxy>,
    start: Start,
    exchange: Exchange,
    target: Target,
    mut request: Request<Incoming>,
) -> Response<ProxyBody> {
    let runtime = &proxy.runtime;
    let hooks = &runtime.hooks;
    let context = HookContext {
        session_id: runtime.session_id.clone(),
        seq: exchange.seq,
        method: exchange.request.method.clone(),
        url: exchange.request.url.clone(),
    };
    let mut finish = Pending(Some(Completion::new(&proxy, start, exchange, context)));
    let upgrade = headers::is_upgrade(request.headers());
    let http1 = http1_upstream(finish.exchange.mode, request.version(), upgrade);
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let (mut parts, body) = request.into_parts();
    let mut path = target.path.clone();
    // The length of a body a sync hook rewrote, and whether the client framed one.
    let mut buffered = None;

    let sync_request = hooks.has_sync_request();
    finish.request_hooks_done = sync_request;
    let body = if sync_request {
        let framed = headers::has_framing(&parts.headers);
        let original = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                let problem = format!(
                    "reading the request body from the client failed: {}",
                    upstream::chain(&error)
                );
                finish.exchange.error = Some(problem.clone());
                finish.spawn();
                return text_response(StatusCode::BAD_REQUEST, &format!("tap: {problem}"));
            }
        };
        // Kept before the hook runs, in case the client goes away meanwhile.
        finish.request = Some(ready(captured(&original, runtime.max_body)));
        let recorded = &finish.exchange.request;
        let message = HookMessage {
            method: Some(recorded.method.clone()),
            path: Some(path.clone()),
            status: None,
            headers: recorded.headers.clone(),
            body: original.clone(),
        };
        let (changed, notes) = hooks.on_request(&finish.context, message).await;
        finish.exchange.notes.extend(notes);
        let recorded = &finish.exchange.request;
        if let Some(method) = changed.method.filter(|method| *method != recorded.method) {
            if let Ok(method) = Method::from_bytes(method.as_bytes()) {
                parts.method = method;
            }
        }
        if let Some(changed_path) = changed.path {
            path = changed_path;
        }
        if changed.headers != recorded.headers {
            parts.headers = headers::from_pairs(&changed.headers);
        }
        buffered = Some((changed.body.len(), framed));
        capture::full(changed.body)
    } else {
        let (body, captured) = capture::tee(body, runtime.max_body);
        finish.request = Some(captured);
        body
    };

    let method = parts.method.clone();
    let url = target.url(&path);
    let sent = match upstream_request(parts, body, &target, &path, upgrade, buffered) {
        Ok(outgoing) => send(&proxy, outgoing, &target, http1).await,
        Err(problem) => Err(problem),
    };
    let mut response = match sent {
        Ok(response) => response,
        Err(problem) => {
            finish.exchange.error = Some(problem.clone());
            finish.spawn();
            return bad_gateway(&url, &problem);
        }
    };
    finish.exchange.ttfb_ms = Some(start.elapsed_ms());

    let switched = take_upgrade(&mut response, client_upgrade);
    let (mut parts, body) = response.into_parts();
    let status = parts.status;
    let response_record = ResponseRecord {
        status: status.as_u16(),
        reason: reason(&parts),
        version: headers::version_name(parts.version).to_string(),
        headers: headers::record(&parts.headers),
        body: BodyRecord::default(),
    };
    let framed = headers::has_framing(&parts.headers);
    finish.exchange.response = Some(response_record);
    headers::to_client(&mut parts.headers, switched.is_some());
    parts.version = Version::HTTP_11;

    if let Some(sides) = switched {
        // Only the bytes relayed after the switch follow; there is no response body.
        finish.response_hooks_done = true;
        finish.response = Some(ready(Captured {
            bytes: Bytes::new(),
            record: BodyRecord {
                complete: true,
                ..Default::default()
            },
        }));
        let completion = finish.take();
        let stopped = proxy.stopped();
        tokio::spawn(async move {
            let (stats, error) = splice(sides, stopped).await;
            if let Some(mut completion) = completion {
                completion.exchange.tunnel = Some(stats);
                if let Some(error) = error {
                    completion.exchange.notes.push(tunnel_error_note(&error));
                }
                completion.run().await;
            }
        });
        return Response::from_parts(parts, capture::empty());
    }

    let body = if hooks.has_sync_response() {
        finish.response_hooks_done = true;
        let original = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                let problem = format!(
                    "reading the response body from upstream failed: {}",
                    upstream::chain(&error)
                );
                finish.exchange.error = Some(problem.clone());
                finish.spawn();
                return bad_gateway(&url, &problem);
            }
        };
        finish.response = Some(ready(captured(&original, runtime.max_body)));
        let recorded_headers = finish.recorded_response_headers();
        let message = HookMessage {
            method: None,
            path: None,
            status: Some(status.as_u16()),
            headers: recorded_headers.clone(),
            body: original.clone(),
        };
        let (changed, notes) = hooks.on_response(&finish.context, message).await;
        finish.exchange.notes.extend(notes);
        if let Some(code) = changed.status.filter(|code| *code != status.as_u16()) {
            if let Ok(code) = StatusCode::from_u16(code) {
                parts.status = code;
                // The upstream's reason phrase described the old status.
                parts.extensions.remove::<ReasonPhrase>();
            }
        }
        if changed.headers != recorded_headers {
            parts.headers = headers::from_pairs(&changed.headers);
            headers::to_client(&mut parts.headers, false);
        }
        if !headers::body_forbidden(&method, parts.status) {
            headers::set_content_length(&mut parts.headers, changed.body.len(), framed);
        }
        capture::full(changed.body)
    } else {
        let (body, captured) = capture::tee(body, runtime.max_body);
        finish.response = Some(captured);
        body
    };
    finish.spawn();
    Response::from_parts(parts, body)
}

/// The client request turned into the upstream request: absolute URI, HTTP/1.1
/// (the connector negotiates HTTP/2 via ALPN), hop-by-hop headers removed.
/// Extensions are kept, so HTTP/1 header case survives. `buffered` is the
/// length of a body read whole (and whether the client announced one), which
/// then gets exactly one matching `content-length`.
fn upstream_request(
    mut parts: Parts,
    body: ProxyBody,
    target: &Target,
    path: &str,
    upgrade: bool,
    buffered: Option<(usize, bool)>,
) -> Result<Request<ProxyBody>, String> {
    parts.uri = target.uri(path).map_err(|error| {
        format!(
            "cannot build the upstream URL for {}: {error}",
            target.url(path)
        )
    })?;
    headers::to_upstream(&mut parts.headers, parts.version, upgrade);
    if let Some((len, framed)) = buffered {
        headers::set_content_length(&mut parts.headers, len, framed);
    }
    parts.version = Version::HTTP_11;
    Ok(Request::from_parts(parts, body))
}

/// Sends `request` upstream and waits for the response head. It fails after
/// `response_timeout` without progress: no connection, no request body taken
/// (an upload that keeps going is fine), or no response head once the whole
/// request was sent.
async fn send(
    proxy: &Proxy,
    request: Request<ProxyBody>,
    target: &Target,
    http1: bool,
) -> Result<Response<Incoming>, String> {
    if proxy.is_self(&target.host, target.port) {
        return Err(format!(
            "{} is TAP's own address, so forwarding there would loop; request the real server's URL",
            target.authority()
        ));
    }
    let client = if http1 {
        &proxy.clients.http1
    } else {
        &proxy.clients.any
    };
    let timeout = proxy.runtime.response_timeout;
    let activity = Activity::new();
    let request = request.map(|body| activity.watch(body));
    tokio::select! {
        sent = client.request(request) => {
            sent.map_err(|error| upstream::describe(&error, &target.authority()))
        }
        () = activity.idle_for(timeout) => {
            let seconds = timeout.as_secs_f64();
            let authority = target.authority();
            Err(if activity.uploading() {
                format!("{authority} stopped taking the request body for {seconds}s (the response timeout)")
            } else {
                format!("no response from {authority} within {seconds}s (the response timeout)")
            })
        }
    }
}

/// `502` for a failed upstream request; `problem` is the cause chain.
fn bad_gateway(url: &str, problem: &str) -> Response<ProxyBody> {
    text_response(
        StatusCode::BAD_GATEWAY,
        &format!("tap: upstream request to {url} failed: {problem}"),
    )
}

/// The canonical reason, unless upstream sent its own (HTTP/1 only), which is
/// also what the client gets.
fn reason(parts: &http::response::Parts) -> String {
    match parts.extensions.get::<ReasonPhrase>() {
        Some(phrase) => String::from_utf8_lossy(phrase.as_bytes()).into_owned(),
        None => parts
            .status
            .canonical_reason()
            .unwrap_or_default()
            .to_string(),
    }
}

type Sides = (OnUpgrade, OnUpgrade);

/// Both connections' upgrade handles when upstream switched protocols on an upgrade request.
fn take_upgrade(response: &mut Response<Incoming>, client: Option<OnUpgrade>) -> Option<Sides> {
    let client = client?;
    (response.status() == StatusCode::SWITCHING_PROTOCOLS)
        .then(|| (client, hyper::upgrade::on(response)))
}

/// Relays the upgraded connections (once the client has its `101`) until both sides close.
async fn splice(
    (client, upstream): Sides,
    stop: impl Future<Output = ()>,
) -> (TunnelStats, Option<io::Error>) {
    match tokio::try_join!(client, upstream) {
        Ok((client, upstream)) => relay(TokioIo::new(client), TokioIo::new(upstream), stop).await,
        Err(error) => (TunnelStats::default(), Some(io::Error::other(error))),
    }
}

pub(super) fn tunnel_error_note(error: &io::Error) -> String {
    format!("the tunnel ended with an error: {error}")
}

fn ready(captured: Captured) -> oneshot::Receiver<Captured> {
    let (sender, receiver) = oneshot::channel();
    let _ = sender.send(captured);
    receiver
}

/// The capture of a body that was read whole.
fn captured(bytes: &Bytes, limit: u64) -> Captured {
    let size = bytes.len() as u64;
    let kept = usize::try_from(limit).map_or(bytes.len(), |limit| limit.min(bytes.len()));
    Captured {
        bytes: bytes.slice(..kept),
        record: BodyRecord {
            size,
            captured: kept as u64,
            truncated: (kept as u64) < size,
            complete: true,
            file: None,
        },
    }
}

/// A new in-scope exchange with the next `seq`.
pub(super) fn new_exchange(
    proxy: &Proxy,
    start: Start,
    mode: Mode,
    client: &str,
    request: RequestRecord,
) -> Exchange {
    Exchange {
        seq: proxy.runtime.store.next_seq(),
        ..unnumbered(proxy, start, mode, client, request)
    }
}

fn unnumbered(
    proxy: &Proxy,
    start: Start,
    mode: Mode,
    client: &str,
    request: RequestRecord,
) -> Exchange {
    Exchange {
        seq: 0,
        session_id: proxy.runtime.session_id.clone(),
        started_at: record::rfc3339(start.unix_ms),
        started_unix_ms: start.unix_ms,
        mode,
        client_addr: client.to_string(),
        request,
        ..Default::default()
    }
}

/// What is left to do once an exchange's bodies have finished.
struct Completion {
    proxy: Arc<Proxy>,
    start: Start,
    exchange: Exchange,
    context: HookContext,
    /// Body captures; a missing one counts as an aborted, empty body.
    request: Option<oneshot::Receiver<Captured>>,
    response: Option<oneshot::Receiver<Captured>>,
    /// Message hooks that already ran (sync ones, with the whole body) or must not run.
    request_hooks_done: bool,
    response_hooks_done: bool,
    /// Keeps a stopping proxy waiting until this exchange is recorded.
    _recording: Recording,
}

impl Completion {
    fn new(
        proxy: &Arc<Proxy>,
        start: Start,
        exchange: Exchange,
        context: HookContext,
    ) -> Completion {
        Completion {
            proxy: proxy.clone(),
            start,
            exchange,
            context,
            request: None,
            response: None,
            request_hooks_done: false,
            response_hooks_done: false,
            _recording: proxy.recording(),
        }
    }

    fn recorded_response_headers(&self) -> crate::record::Headers {
        self.exchange
            .response
            .as_ref()
            .map(|response| response.headers.clone())
            .unwrap_or_default()
    }

    /// Waits for both bodies, then makes the final scope decision, runs the
    /// async-only message hooks and records the exchange.
    async fn run(self) {
        let request = settle(self.request).await;
        let response = settle(self.response).await;
        let mut exchange = self.exchange;
        exchange.request.body = request.record;
        if let Some(record) = exchange.response.as_mut() {
            record.body = response.record;
        }
        exchange.duration_ms = Some(self.start.elapsed_ms());
        let proxy = &self.proxy;
        if !in_final_scope(proxy, &exchange) {
            return;
        }
        let hooks = &proxy.runtime.hooks;
        if !self.request_hooks_done && hooks.has_request() {
            let message = HookMessage {
                method: Some(exchange.request.method.clone()),
                path: Some(exchange.request.path.clone()),
                status: None,
                headers: exchange.request.headers.clone(),
                body: request.bytes.clone(),
            };
            let (_, notes) = hooks.on_request(&self.context, message).await;
            exchange.notes.extend(notes);
        }
        if let Some(record) = exchange.response.as_ref() {
            if !self.response_hooks_done && hooks.has_response() {
                let message = HookMessage {
                    method: None,
                    path: None,
                    status: Some(record.status),
                    headers: record.headers.clone(),
                    body: response.bytes.clone(),
                };
                let (_, notes) = hooks.on_response(&self.context, message).await;
                exchange.notes.extend(notes);
            }
        }
        commit(proxy, exchange, request.bytes, response.bytes).await;
    }
}

async fn settle(capture: Option<oneshot::Receiver<Captured>>) -> Captured {
    match capture {
        Some(receiver) => receiver.await.unwrap_or_default(),
        None => Captured::default(),
    }
}

/// Holds an exchange's [`Completion`] until it is handed to a task. When hyper
/// drops the request future first (the client went away before it got its
/// response), the upstream request is cancelled with it and Drop records the
/// exchange as failed.
struct Pending(Option<Completion>);

impl Pending {
    fn spawn(mut self) {
        if let Some(completion) = self.0.take() {
            tokio::spawn(completion.run());
        }
    }

    fn take(mut self) -> Option<Completion> {
        self.0.take()
    }
}

impl std::ops::Deref for Pending {
    type Target = Completion;

    fn deref(&self) -> &Completion {
        self.0
            .as_ref()
            .expect("only the consuming methods empty a Pending")
    }
}

impl std::ops::DerefMut for Pending {
    fn deref_mut(&mut self) -> &mut Completion {
        self.0
            .as_mut()
            .expect("only the consuming methods empty a Pending")
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let Some(mut completion) = self.0.take() else {
            return;
        };
        let stopping = completion.proxy.is_stopping();
        completion.exchange.error.get_or_insert_with(|| {
            if stopping {
                "TAP was stopped before the response arrived".into()
            } else {
                "the client went away (closed the connection or cancelled the request) before it got a response"
                    .into()
            }
        });
        // No runtime means the process is shutting down; there is nothing left to record with.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(completion.run());
        }
    }
}

/// The final scope decision, made once the status is known.
fn in_final_scope(proxy: &Proxy, exchange: &Exchange) -> bool {
    proxy.runtime.filters.matches(&Facts::exchange(exchange))
}

/// Records an exchange that failed before anything was forwarded, if it is in scope.
pub(super) async fn record_failure(
    proxy: &Proxy,
    start: Start,
    mode: Mode,
    client: &str,
    request: RequestRecord,
    error: String,
) {
    let mut exchange = unnumbered(proxy, start, mode, client, request);
    exchange.error = Some(error);
    exchange.duration_ms = Some(start.elapsed_ms());
    if !in_final_scope(proxy, &exchange) {
        return;
    }
    exchange.seq = proxy.runtime.store.next_seq();
    commit(proxy, exchange, Bytes::new(), Bytes::new()).await;
}

/// Records a finished tunnel (numbered when it started), if it is still in scope.
pub(super) async fn record_tunnel(
    proxy: &Proxy,
    start: Start,
    mut exchange: Exchange,
    stats: TunnelStats,
    error: Option<io::Error>,
) {
    exchange.tunnel = Some(stats);
    exchange.duration_ms = Some(start.elapsed_ms());
    if let Some(error) = error {
        exchange.notes.push(tunnel_error_note(&error));
    }
    if in_final_scope(proxy, &exchange) {
        commit(proxy, exchange, Bytes::new(), Bytes::new()).await;
    }
}

/// Body notes, redaction, `on_event` hooks, then the store.
async fn commit(proxy: &Proxy, mut exchange: Exchange, request: Bytes, response: Bytes) {
    body_notes(&mut exchange);
    if proxy.is_stopping() && cut_off(&exchange) {
        exchange
            .notes
            .push("TAP was stopped while this exchange was in progress".into());
    }
    let runtime = &proxy.runtime;
    redact::redact_exchange(&mut exchange, &runtime.redact);
    let seq = exchange.seq;
    // The store sets these itself; event hooks should see the record as it will be written.
    if exchange.request.body.captured > 0 {
        exchange.request.body.file = Some(format!("bodies/{seq}.req"));
    }
    if let Some(response) = exchange
        .response
        .as_mut()
        .filter(|response| response.body.captured > 0)
    {
        response.body.file = Some(format!("bodies/{seq}.res"));
    }
    if runtime.hooks.has_event() {
        let (changed, notes) = runtime.hooks.on_event(exchange).await;
        exchange = changed;
        exchange.notes.extend(notes);
        // A hook may have added headers; secrets never reach the record.
        redact::redact_exchange(&mut exchange, &runtime.redact);
    }
    runtime.store.record(exchange, request, response);
}

/// Whether an exchange ended early: an error, an aborted body or a broken tunnel.
fn cut_off(exchange: &Exchange) -> bool {
    exchange.error.is_some()
        || !exchange.request.body.complete
        || exchange
            .response
            .as_ref()
            .is_some_and(|response| !response.body.complete)
        || exchange
            .notes
            .iter()
            .any(|note| note.starts_with("the tunnel ended with an error"))
}

fn body_notes(exchange: &mut Exchange) {
    let failed = exchange.error.is_some();
    let sides = [
        ("request", Some(&exchange.request.body)),
        (
            "response",
            exchange.response.as_ref().map(|response| &response.body),
        ),
    ];
    let mut notes = Vec::new();
    for (side, body) in sides {
        let Some(body) = body else { continue };
        if body.truncated {
            notes.push(format!(
                "{side} body truncated: captured {} of {} bytes (the session's max_body)",
                body.captured, body.size
            ));
        }
        if !body.complete && !failed {
            notes.push(format!(
                "{side} body incomplete: the stream was aborted after {} bytes",
                body.size
            ));
        }
    }
    exchange.notes.extend(notes);
}

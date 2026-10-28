//! Small IO adapters: replaying bytes read ahead of time, relaying opaque
//! bytes between two connections while counting them, and noticing when a
//! request body makes progress.

use crate::capture::{BoxError, ProxyBody};
use crate::record::TunnelStats;
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// A stream whose first reads return `prefix` (bytes already read from `inner`
/// to look at them), then continue with `inner`.
pub(super) struct Prefixed<T> {
    prefix: Bytes,
    inner: T,
}

impl<T> Prefixed<T> {
    pub(super) fn new(prefix: Bytes, inner: T) -> Prefixed<T> {
        Prefixed { prefix, inner }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.prefix.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let take = this.prefix.len().min(buf.remaining());
        buf.put_slice(&this.prefix[..take]);
        this.prefix.advance(take);
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Counts the bytes read from and written to `inner`.
struct Counted<T> {
    inner: T,
    read: u64,
    written: u64,
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.read += (buf.filled().len() - before) as u64;
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            this.written += written as u64;
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Copies bytes both ways until both directions have ended, or `stop` resolves.
/// Returns the byte counts (also when an error ended the relay) and that error, if any.
pub(super) async fn relay<A, B>(
    client: A,
    mut upstream: B,
    stop: impl Future<Output = ()>,
) -> (TunnelStats, Option<io::Error>)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = Counted {
        inner: client,
        read: 0,
        written: 0,
    };
    let error = tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut upstream) => result.err(),
        () = stop => Some(io::Error::other("TAP was stopped while the tunnel was open")),
    };
    let stats = TunnelStats {
        bytes_up: client.read,
        bytes_down: client.written,
    };
    (stats, error)
}

/// When a body last made progress, so a timeout can count only the time
/// nothing happened (a slow upload that keeps going is not a stall).
#[derive(Clone)]
pub(super) struct Activity(Arc<ActivityState>);

struct ActivityState {
    base: Instant,
    /// Nanoseconds after `base` of the last progress.
    last: AtomicU64,
    finished: AtomicBool,
}

impl Activity {
    pub(super) fn new() -> Activity {
        Activity(Arc::new(ActivityState {
            base: Instant::now(),
            last: AtomicU64::new(0),
            finished: AtomicBool::new(false),
        }))
    }

    /// `body`, noting each frame (and its end) as progress.
    pub(super) fn watch(&self, body: ProxyBody) -> ProxyBody {
        Watched {
            inner: body,
            activity: self.clone(),
        }
        .boxed_unsync()
    }

    /// Whether the watched body was sent to its end.
    pub(super) fn finished(&self) -> bool {
        self.0.finished.load(Ordering::Relaxed)
    }

    /// Whether the body has started but not finished being sent.
    pub(super) fn uploading(&self) -> bool {
        self.0.last.load(Ordering::Relaxed) > 0 && !self.finished()
    }

    /// Resolves once `limit` has passed without progress.
    pub(super) async fn idle_for(&self, limit: Duration) {
        loop {
            let last = Duration::from_nanos(self.0.last.load(Ordering::Relaxed));
            let Some(due) = last
                .checked_add(limit)
                .and_then(|after| self.0.base.checked_add(after))
            else {
                // A limit beyond what time can express never runs out.
                return std::future::pending().await;
            };
            if Instant::now() >= due {
                return;
            }
            tokio::time::sleep_until(due).await;
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.0.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.0.last.fetch_max(elapsed, Ordering::Relaxed);
    }
}

struct Watched {
    inner: ProxyBody,
    activity: Activity,
}

impl Body for Watched {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(frame) = &poll {
            this.activity.touch();
            if frame.is_none() || this.inner.is_end_stream() {
                this.activity.0.finished.store(true, Ordering::Relaxed);
            }
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Item = Result<Frame<Bytes>, BoxError>;

    /// A body fed frame by frame from a channel; ends when the sender is dropped.
    struct ChannelBody(tokio::sync::mpsc::Receiver<Item>);

    impl Body for ChannelBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Item>> {
            self.0.poll_recv(cx)
        }
    }

    #[tokio::test]
    async fn activity_counts_only_idle_time() {
        let activity = Activity::new();
        let (sender, receiver) = tokio::sync::mpsc::channel::<Item>(4);
        let mut body = activity.watch(crate::capture::boxed(ChannelBody(receiver)));
        let limit = Duration::from_millis(300);
        let idle = tokio::spawn({
            let activity = activity.clone();
            async move {
                let started = Instant::now();
                activity.idle_for(limit).await;
                started.elapsed()
            }
        });
        // Progress every 200ms keeps a 300ms idle limit from firing.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            sender
                .send(Ok(Frame::data(Bytes::from_static(b"x"))))
                .await
                .unwrap();
            body.frame().await.unwrap().unwrap();
        }
        assert!(!activity.finished());
        drop(sender);
        assert!(body.frame().await.is_none());
        assert!(activity.finished());
        let waited = idle.await.unwrap();
        assert!(
            waited >= Duration::from_millis(900) && waited < Duration::from_millis(1500),
            "fires 300ms after the last progress at ~600ms: {waited:?}"
        );
    }

    #[tokio::test]
    async fn an_unrepresentable_idle_limit_never_fires() {
        let activity = Activity::new();
        let waited =
            tokio::time::timeout(Duration::from_millis(50), activity.idle_for(Duration::MAX)).await;
        assert!(waited.is_err(), "still waiting, no overflow panic");
    }

    #[tokio::test]
    async fn prefixed_replays_then_continues() {
        let (mut near, far) = tokio::io::duplex(64);
        near.write_all(b" world").await.unwrap();
        drop(near);
        let mut stream = Prefixed::new(Bytes::from_static(b"hello"), far);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn relay_counts_both_directions() {
        let (client, mut client_peer) = tokio::io::duplex(64);
        let (upstream, mut upstream_peer) = tokio::io::duplex(64);
        let relayed = tokio::spawn(relay(client, upstream, std::future::pending()));
        client_peer.write_all(b"ping!").await.unwrap();
        let mut got = [0u8; 5];
        upstream_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping!");
        upstream_peer.write_all(b"pong").await.unwrap();
        let mut back = [0u8; 4];
        client_peer.read_exact(&mut back).await.unwrap();
        drop(client_peer);
        drop(upstream_peer);
        let (stats, _) = relayed.await.unwrap();
        assert_eq!((stats.bytes_up, stats.bytes_down), (5, 4));
    }
}

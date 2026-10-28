//! Streaming body capture: frames pass through untouched while a bounded copy is kept aside.

use crate::record::BodyRecord;
use bytes::{Bytes, BytesMut};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body type used for everything TAP sends (to clients and upstreams).
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// What a [`tee`] saw once its stream finished (or was dropped).
#[derive(Debug, Default)]
pub struct Captured {
    /// The first `limit` bytes of body data.
    pub bytes: Bytes,
    /// `size`, `captured`, `truncated`, `complete` filled in; `file` is left None (the store sets it).
    pub record: BodyRecord,
}

/// Wraps `body` so every frame (data and trailers) passes through unchanged
/// and in real time, while the first `limit` data bytes are copied aside.
///
/// The receiver resolves exactly once: when the stream ends cleanly
/// (`complete = true`), when it yields an error, or when the wrapper is
/// dropped before the end (`complete = false`, e.g. the client disconnected).
pub fn tee<B>(body: B, limit: u64) -> (ProxyBody, oneshot::Receiver<Captured>)
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let (sender, receiver) = oneshot::channel();
    let tee = Tee {
        inner: Box::pin(body),
        limit,
        size: 0,
        bytes: BytesMut::new(),
        sender: Some(sender),
    };
    (UnsyncBoxBody::new(tee), receiver)
}

/// Boxes `body` without capturing anything (used for out-of-scope traffic).
pub fn boxed<B>(body: B) -> ProxyBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

pub fn full(bytes: impl Into<Bytes>) -> ProxyBody {
    boxed(Full::new(bytes.into()))
}

pub fn empty() -> ProxyBody {
    boxed(Empty::<Bytes>::new())
}

struct Tee<B: Body> {
    // Boxed so `Tee` is `Unpin` whatever `B` is.
    inner: Pin<Box<B>>,
    limit: u64,
    size: u64,
    bytes: BytesMut,
    sender: Option<oneshot::Sender<Captured>>,
}

impl<B: Body> Tee<B> {
    fn keep(&mut self, data: &Bytes) {
        self.size += data.len() as u64;
        let room = self.limit.saturating_sub(self.bytes.len() as u64);
        let take = usize::try_from(room).map_or(data.len(), |room| room.min(data.len()));
        self.bytes.extend_from_slice(&data[..take]);
    }

    fn finish(&mut self, complete: bool) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let bytes = std::mem::take(&mut self.bytes).freeze();
        let captured = bytes.len() as u64;
        let record = BodyRecord {
            size: self.size,
            captured,
            truncated: captured < self.size,
            complete,
            file: None,
        };
        let _ = sender.send(Captured { bytes, record });
    }
}

impl<B> Body for Tee<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.keep(data);
                }
                // Hyper stops polling (and drops the body) after trailers or once the
                // body reports its end; hyper's chunked h1 body never reports it.
                if frame.is_trailers() || this.inner.is_end_stream() {
                    this.finish(true);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.finish(false);
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                this.finish(true);
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B: Body> Drop for Tee<B> {
    fn drop(&mut self) {
        // A body that already reports its end was consumed fully even if nobody polled `None`.
        let complete = self.inner.is_end_stream();
        self.finish(complete);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    type Item = Result<Frame<Bytes>, BoxError>;

    /// A body fed frame by frame from a channel; ends when the sender is dropped.
    struct ChannelBody(mpsc::Receiver<Item>);

    impl Body for ChannelBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Item>> {
            self.0.poll_recv(cx)
        }
    }

    fn channel() -> (mpsc::Sender<Item>, ChannelBody) {
        let (sender, receiver) = mpsc::channel(16);
        (sender, ChannelBody(receiver))
    }

    fn data(bytes: &'static [u8]) -> Item {
        Ok(Frame::data(Bytes::from_static(bytes)))
    }

    async fn next(body: &mut ProxyBody) -> Option<Item> {
        timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("frame should arrive")
    }

    fn trailers() -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert("x-checksum", "abc".parse().unwrap());
        map
    }

    #[tokio::test]
    async fn passes_frames_and_trailers_through_in_order() {
        let (sender, inner) = channel();
        sender.send(data(b"hello ")).await.unwrap();
        sender.send(data(b"world")).await.unwrap();
        sender.send(Ok(Frame::trailers(trailers()))).await.unwrap();
        drop(sender);
        let (mut body, captured) = tee(inner, 1024);

        let first = next(&mut body).await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), "hello ");
        let second = next(&mut body).await.unwrap().unwrap();
        assert_eq!(second.into_data().unwrap(), "world");
        let third = next(&mut body).await.unwrap().unwrap();
        assert_eq!(third.into_trailers().unwrap(), trailers());
        assert!(next(&mut body).await.is_none());

        let captured = captured.await.unwrap();
        assert_eq!(captured.bytes, "hello world");
        assert_eq!(
            captured.record,
            BodyRecord {
                size: 11,
                captured: 11,
                truncated: false,
                complete: true,
                file: None
            }
        );
    }

    #[tokio::test]
    async fn truncates_the_copy_but_not_the_stream() {
        let (sender, inner) = channel();
        sender.send(data(b"abcd")).await.unwrap();
        sender.send(data(b"efgh")).await.unwrap();
        sender.send(data(b"ijkl")).await.unwrap();
        drop(sender);
        let (body, captured) = tee(inner, 6);

        let streamed = body.collect().await.unwrap().to_bytes();
        assert_eq!(streamed, "abcdefghijkl");
        let captured = captured.await.unwrap();
        assert_eq!(captured.bytes, "abcdef");
        assert_eq!(captured.record.size, 12);
        assert_eq!(captured.record.captured, 6);
        assert!(captured.record.truncated);
        assert!(captured.record.complete);
    }

    #[tokio::test]
    async fn zero_limit_captures_nothing() {
        let (body, captured) = tee(Full::new(Bytes::from_static(b"xyz")), 0);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "xyz");
        let captured = captured.await.unwrap();
        assert!(captured.bytes.is_empty());
        assert_eq!(captured.record.size, 3);
        assert_eq!(captured.record.captured, 0);
        assert!(captured.record.truncated);
        assert!(captured.record.complete);
    }

    #[tokio::test]
    async fn drop_mid_stream_reports_incomplete_with_partial_bytes() {
        let (sender, inner) = channel();
        sender.send(data(b"partial")).await.unwrap();
        let (mut body, captured) = tee(inner, 1024);
        assert_eq!(
            next(&mut body).await.unwrap().unwrap().into_data().unwrap(),
            "partial"
        );
        drop(body);

        let captured = captured.await.unwrap();
        assert_eq!(captured.bytes, "partial");
        assert_eq!(captured.record.size, 7);
        assert!(!captured.record.complete);
        assert!(!captured.record.truncated);
        drop(sender);
    }

    #[tokio::test]
    async fn drop_before_any_poll_reports_incomplete() {
        let (_sender, inner) = channel();
        let (body, captured) = tee(inner, 1024);
        drop(body);
        let captured = captured.await.unwrap();
        assert_eq!(captured.record.size, 0);
        assert!(!captured.record.complete);
    }

    #[tokio::test]
    async fn error_passes_through_and_reports_incomplete() {
        let (sender, inner) = channel();
        sender.send(data(b"ok")).await.unwrap();
        sender.send(Err("connection reset".into())).await.unwrap();
        let (mut body, mut captured) = tee(inner, 1024);

        assert!(next(&mut body).await.unwrap().is_ok());
        assert!(
            captured.try_recv().is_err(),
            "nothing is reported before the end"
        );
        let error = next(&mut body).await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "connection reset");

        let captured = captured.await.unwrap();
        assert_eq!(captured.bytes, "ok");
        assert_eq!(captured.record.size, 2);
        assert!(!captured.record.complete);
        drop(body);
        drop(sender);
    }

    #[tokio::test]
    async fn zero_length_body() {
        let (body, captured) = tee(Empty::<Bytes>::new(), 1024);
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.collect().await.unwrap().to_bytes().is_empty());
        let captured = captured.await.unwrap();
        assert!(captured.bytes.is_empty());
        assert_eq!(
            captured.record,
            BodyRecord {
                complete: true,
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn finished_body_dropped_without_final_poll_is_complete() {
        // Hyper drops an end-of-stream body without polling it again; that is a clean end.
        let (body, captured) = tee(Empty::<Bytes>::new(), 1024);
        drop(body);
        assert!(captured.await.unwrap().record.complete);

        let (mut body, mut captured) = tee(Full::new(Bytes::from_static(b"all")), 1024);
        assert_eq!(body.size_hint().exact(), Some(3));
        assert_eq!(
            next(&mut body).await.unwrap().unwrap().into_data().unwrap(),
            "all"
        );
        assert!(body.is_end_stream());
        let early = captured
            .try_recv()
            .expect("reported as soon as the body ends");
        assert!(early.record.complete);
        assert_eq!(early.bytes, "all");
        drop(body);
    }

    #[tokio::test]
    async fn streams_frame_by_frame_with_a_slow_producer() {
        let (sender, inner) = channel();
        let (mut body, captured) = tee(inner, 1024);
        let (first_seen, wait_first_seen) = tokio::sync::oneshot::channel::<()>();

        let producer = tokio::spawn(async move {
            sender.send(data(b"event: one\n\n")).await.unwrap();
            // The second frame is only produced after the consumer saw the first one.
            wait_first_seen.await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            sender.send(data(b"event: two\n\n")).await.unwrap();
        });

        let first = next(&mut body).await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), "event: one\n\n");
        assert!(
            timeout(Duration::from_millis(20), body.frame())
                .await
                .is_err(),
            "no frame may appear before the producer sends it"
        );
        first_seen.send(()).unwrap();
        let second = next(&mut body).await.unwrap().unwrap();
        assert_eq!(second.into_data().unwrap(), "event: two\n\n");
        producer.await.unwrap();
        assert!(next(&mut body).await.is_none());

        let captured = captured.await.unwrap();
        assert_eq!(captured.bytes, "event: one\n\nevent: two\n\n");
        assert!(captured.record.complete);
    }

    #[tokio::test]
    async fn trailers_end_the_capture_even_if_the_body_never_reports_its_end() {
        // ChannelBody never says is_end_stream, like hyper's chunked h1 Incoming after trailers.
        let (sender, inner) = channel();
        sender.send(data(b"x")).await.unwrap();
        sender.send(Ok(Frame::trailers(trailers()))).await.unwrap();
        let (mut body, mut captured) = tee(inner, 1024);
        assert!(next(&mut body).await.unwrap().unwrap().is_data());
        assert!(next(&mut body).await.unwrap().unwrap().is_trailers());
        drop(body);
        let captured = captured
            .try_recv()
            .expect("reported once the trailers passed");
        assert!(captured.record.complete);
        assert_eq!(captured.bytes, "x");
        drop(sender);
    }

    /// Serves one raw HTTP/1.1 request through hyper's own dispatcher, echoing the
    /// tee'd request body as the response, and returns the response bytes and capture.
    /// Unless `hang_up`, the capture must arrive while the client connection is still open.
    async fn echo_through_hyper(request: &'static [u8], hang_up: bool) -> (Vec<u8>, Captured) {
        use hyper::body::Incoming;
        use hyper_util::rt::TokioIo;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (report, mut reports) = mpsc::unbounded_channel();
        let service = hyper::service::service_fn(move |request: http::Request<Incoming>| {
            let (body, captured) = tee(request.into_body(), 1024);
            let _ = report.send(captured);
            async move { Ok::<_, std::convert::Infallible>(http::Response::new(body)) }
        });
        let connection = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server), service);
        let connection = tokio::spawn(connection);
        client.write_all(request).await.unwrap();
        if hang_up {
            client.shutdown().await.unwrap();
        }

        let captured = timeout(Duration::from_secs(5), reports.recv())
            .await
            .unwrap()
            .unwrap();
        let captured = timeout(Duration::from_secs(5), captured)
            .await
            .expect("capture reported without waiting for the connection to close")
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let _ = connection.await;
        (response, captured)
    }

    #[tokio::test]
    async fn hyper_content_length_body_is_complete() {
        let (response, captured) = echo_through_hyper(
            b"POST / HTTP/1.1\r\nhost: t\r\ncontent-length: 5\r\n\r\nhello",
            false,
        )
        .await;
        assert!(
            response.ends_with(b"\r\n\r\nhello"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(captured.bytes, "hello");
        assert!(captured.record.complete);
    }

    #[tokio::test]
    async fn hyper_chunked_body_with_trailers_is_complete() {
        let (response, captured) = echo_through_hyper(
            b"POST / HTTP/1.1\r\nhost: t\r\ntransfer-encoding: chunked\r\ntrailer: x-checksum\r\n\
              te: trailers\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\nx-checksum: abc\r\n\r\n",
            false,
        )
        .await;
        let response = String::from_utf8_lossy(&response).into_owned();
        assert!(response.contains("5\r\nhello\r\n1\r\n!\r\n"), "{response}");
        assert_eq!(captured.bytes, "hello!");
        assert_eq!(captured.record.size, 6);
        assert!(captured.record.complete, "trailers are the end of the body");
    }

    #[tokio::test]
    async fn hyper_client_disconnect_mid_body_is_incomplete() {
        let (response, captured) = echo_through_hyper(
            b"POST / HTTP/1.1\r\nhost: t\r\ncontent-length: 100\r\n\r\nonly part",
            true,
        )
        .await;
        assert!(String::from_utf8_lossy(&response).contains("only part"));
        assert_eq!(captured.bytes, "only part");
        assert!(!captured.record.complete);
    }

    #[tokio::test]
    async fn helpers_build_bodies() {
        assert_eq!(full("abc").collect().await.unwrap().to_bytes(), "abc");
        assert!(empty().is_end_stream());
        assert!(empty().collect().await.unwrap().to_bytes().is_empty());
        let (_sender, inner) = channel();
        let boxed = boxed(inner);
        assert!(!boxed.is_end_stream());
    }
}

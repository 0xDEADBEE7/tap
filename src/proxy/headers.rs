//! Headers between client and upstream: how they are recorded, and which are
//! hop-by-hop (about one connection only, so never forwarded; hyper re-frames).

use crate::record::Headers;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode, Version};

/// Names lowercased (as hyper stores them), values decoded lossily, in HeaderMap order.
pub(super) fn record(headers: &HeaderMap) -> Headers {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// A header map from (hook-edited) pairs. Hooks validate names and values, so
/// nothing is dropped in practice; a pair invalid on the wire would be skipped.
pub(super) fn from_pairs(pairs: &Headers) -> HeaderMap {
    let mut map = HeaderMap::with_capacity(pairs.len());
    for (name, value) in pairs {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            map.append(name, value);
        }
    }
    map
}

pub(super) fn version_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

/// `Connection: upgrade` plus an `Upgrade` header (WebSocket and the like).
/// An upgrade to `h2c` only is not one: TAP could not record what follows, so
/// the request is forwarded as plain HTTP/1.1 (the server keeps speaking it).
pub(super) fn is_upgrade(headers: &HeaderMap) -> bool {
    let mut protocols = headers
        .get_all(header::UPGRADE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty());
    protocols.any(|protocol| !protocol.eq_ignore_ascii_case("h2c"))
        && connection_tokens(headers).any(|token| token.eq_ignore_ascii_case("upgrade"))
}

/// Whether the message announced a body (`Content-Length` or `Transfer-Encoding`).
pub(super) fn has_framing(headers: &HeaderMap) -> bool {
    headers.contains_key(header::CONTENT_LENGTH) || headers.contains_key(header::TRANSFER_ENCODING)
}

/// Responses that never carry a body, whatever their headers say.
pub(super) fn body_forbidden(method: &Method, status: StatusCode) -> bool {
    method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

/// Makes client request headers fit for upstream: hop-by-hop headers go, and so
/// do `host` (the client derives Host / `:authority` from the URI) and `expect`
/// (hyper already answered `100-continue`). `te: trailers` is end-to-end
/// meaningful (gRPC) and kept. HTTP/2 clients may split cookies into several
/// headers; they are joined as HTTP/1.1 requires.
pub(super) fn to_upstream(headers: &mut HeaderMap, client_version: Version, upgrade: bool) {
    let trailers_only = headers
        .get_all(header::TE)
        .iter()
        .all(|value| value.as_bytes().eq_ignore_ascii_case(b"trailers"));
    let mut names = vec![
        header::PROXY_AUTHORIZATION,
        header::PROXY_AUTHENTICATE,
        header::HOST,
        header::EXPECT,
    ];
    if !trailers_only {
        names.push(header::TE);
    }
    strip(headers, upgrade, names);
    if client_version == Version::HTTP_2 {
        join_cookies(headers);
    }
}

/// Makes upstream response headers fit for the client.
pub(super) fn to_client(headers: &mut HeaderMap, upgrade: bool) {
    strip(
        headers,
        upgrade,
        vec![header::PROXY_AUTHENTICATE, header::TE],
    );
}

/// Leaves exactly one correct `content-length` for a buffered body of `len`
/// bytes, or none when the message announced no body and has none.
pub(super) fn set_content_length(headers: &mut HeaderMap, len: usize, framed: bool) {
    if len > 0 || framed || headers.contains_key(header::CONTENT_LENGTH) {
        // Replaces every value, in the first one's place.
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    }
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Removes `names`, `connection` and every header it names, `proxy-connection`,
/// `keep-alive` and `transfer-encoding`. For an upgrade, `upgrade` stays and
/// `connection` is reduced to its `upgrade` token. A `content-length` next to a
/// `transfer-encoding` goes too: the body was framed by the latter, so the length
/// is wrong (RFC 9112 6.3). The map is rebuilt so the remaining headers keep
/// their order (`HeaderMap::remove` would reorder them).
fn strip(headers: &mut HeaderMap, upgrade: bool, mut names: Vec<HeaderName>) {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        names.push(header::CONTENT_LENGTH);
    }
    let mut connection = None;
    for token in connection_tokens(headers) {
        if upgrade && token.eq_ignore_ascii_case("upgrade") {
            connection = connection.or_else(|| HeaderValue::from_str(token).ok());
        } else if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            names.push(name);
        }
    }
    names.extend([
        HeaderName::from_static("proxy-connection"),
        HeaderName::from_static("keep-alive"),
        header::TRANSFER_ENCODING,
    ]);
    if connection.is_none() {
        names.push(header::UPGRADE);
    }
    let old = std::mem::take(headers);
    for (name, value) in &old {
        if name == header::CONNECTION {
            if let Some(token) = connection.take() {
                headers.append(header::CONNECTION, token);
            }
        } else if !names.contains(name) {
            headers.append(name.clone(), value.clone());
        }
    }
}

fn join_cookies(headers: &mut HeaderMap) {
    let mut values = headers.get_all(header::COOKIE).iter();
    let (Some(_), Some(_)) = (values.next(), values.next()) else {
        return;
    };
    let joined: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    if let Ok(value) = HeaderValue::from_bytes(&joined.join(&b"; "[..])) {
        headers.insert(header::COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn names(headers: &HeaderMap) -> Vec<&str> {
        headers.keys().map(HeaderName::as_str).collect()
    }

    #[test]
    fn strips_hop_by_hop_and_named_headers() {
        let mut headers = map(&[
            ("host", "example.com"),
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("proxy-connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("proxy-authorization", "Basic abc"),
            ("te", "gzip"),
            ("upgrade", "websocket"),
            ("expect", "100-continue"),
            ("accept", "*/*"),
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
        ]);
        to_upstream(&mut headers, Version::HTTP_11, false);
        assert_eq!(names(&headers), ["accept", "set-cookie"]);
        let mut ordered = map(&[
            ("a", "1"),
            ("connection", "close"),
            ("b", "2"),
            ("c", "3"),
            ("a", "4"),
        ]);
        to_upstream(&mut ordered, Version::HTTP_11, false);
        assert_eq!(
            record(&ordered),
            [("a", "1"), ("a", "4"), ("b", "2"), ("c", "3")]
                .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        assert_eq!(headers.get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn keeps_te_trailers_and_upgrade_headers() {
        let mut headers = map(&[
            ("te", "trailers"),
            ("connection", "Upgrade, keep-alive"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", "k"),
        ]);
        assert!(is_upgrade(&headers));
        to_upstream(&mut headers, Version::HTTP_11, true);
        assert_eq!(headers["te"], "trailers");
        assert_eq!(headers["connection"], "Upgrade");
        assert_eq!(headers["upgrade"], "websocket");
        assert_eq!(headers["sec-websocket-key"], "k");
    }

    #[test]
    fn response_side() {
        let mut headers = map(&[
            ("connection", "close"),
            ("transfer-encoding", "chunked"),
            ("proxy-authenticate", "Basic"),
            ("content-type", "text/plain"),
        ]);
        to_client(&mut headers, false);
        assert_eq!(names(&headers), ["content-type"]);
    }

    #[test]
    fn h2c_is_not_an_upgrade_tap_relays() {
        let h2c = map(&[
            ("connection", "Upgrade, HTTP2-Settings"),
            ("upgrade", "h2c"),
            ("http2-settings", "AAMA"),
            ("accept", "*/*"),
        ]);
        assert!(!is_upgrade(&h2c));
        let mut headers = h2c.clone();
        to_upstream(&mut headers, Version::HTTP_11, is_upgrade(&h2c));
        assert_eq!(names(&headers), ["accept"]);
        assert!(is_upgrade(&map(&[
            ("connection", "upgrade"),
            ("upgrade", "websocket")
        ])));
        assert!(!is_upgrade(&map(&[("upgrade", "websocket")])));
    }

    #[test]
    fn content_length_beside_transfer_encoding_goes() {
        let mut headers = map(&[
            ("content-length", "3"),
            ("transfer-encoding", "chunked"),
            ("content-type", "text/plain"),
        ]);
        to_client(&mut headers, false);
        assert_eq!(names(&headers), ["content-type"]);
        let mut headers = map(&[("content-length", "3"), ("content-type", "text/plain")]);
        to_client(&mut headers, false);
        assert_eq!(names(&headers), ["content-length", "content-type"]);
    }

    #[test]
    fn joins_http2_cookies() {
        let mut headers = map(&[("cookie", "a=1"), ("cookie", "b=2")]);
        to_upstream(&mut headers, Version::HTTP_2, false);
        assert_eq!(headers.get_all("cookie").iter().count(), 1);
        assert_eq!(headers["cookie"], "a=1; b=2");
    }

    #[test]
    fn content_length_is_single_and_correct() {
        let mut headers = map(&[("content-length", "3"), ("content-length", "3")]);
        set_content_length(&mut headers, 3, true);
        assert_eq!(headers.get_all("content-length").iter().count(), 1);
        assert_eq!(headers["content-length"], "3");

        let mut headers = map(&[("content-length", "10")]);
        set_content_length(&mut headers, 4, true);
        assert_eq!(headers["content-length"], "4");

        let mut headers = HeaderMap::new();
        set_content_length(&mut headers, 0, false);
        assert!(headers.is_empty(), "no body, no framing: nothing added");
        set_content_length(&mut headers, 0, true);
        assert_eq!(headers["content-length"], "0");

        let mut headers = map(&[("a", "1"), ("content-length", "9"), ("b", "2")]);
        set_content_length(&mut headers, 12, true);
        assert_eq!(
            names(&headers),
            ["a", "content-length", "b"],
            "stays in place"
        );
    }
}

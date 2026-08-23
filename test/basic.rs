use std::io::Cursor;
use tap::http::{encode, parse, read, Response};
use tap::intercept::FilterSet;

#[test]
fn parses_absolute_http_request_with_body() {
    let raw = b"POST http://example.com/items HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let request = read(&mut Cursor::new(raw)).unwrap();
    assert_eq!(request.host, "example.com");
    assert_eq!(request.path, "/items");
    assert_eq!(request.body, b"abc");
}

#[test]
fn response_round_trip_preserves_status_and_body() {
    let response = Response {
        status: 201,
        headers: vec![("Content-Type".into(), "text/plain".into())],
        body: b"created".to_vec(),
    };
    let parsed = parse(&encode(&response)).unwrap();
    assert_eq!(parsed.status, 201);
    assert_eq!(parsed.body, b"created");
}

#[test]
fn filters_match_fields_and_headers() {
    let filters = FilterSet::from_specs(&["method=GET,header:x-token=secret".into()]).unwrap();
    assert!(filters.allows_request(
        "GET",
        "https",
        "example.com",
        443,
        "/",
        &[("X-Token".into(), "secret".into())],
    ));
    assert!(!filters.allows_request("POST", "https", "example.com", 443, "/", &[]));
}

#[test]
fn empty_filter_set_allows_requests() {
    assert!(FilterSet::default().allows_request("GET", "http", "localhost", 80, "/", &[]));
}

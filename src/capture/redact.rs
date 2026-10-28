//! Header redaction for records. Secrets are replaced by a length and a short
//! fingerprint, so different keys can be told apart without being stored.

use crate::record::{Exchange, Headers};
use sha2::{Digest, Sha256};

/// Header names redacted when a session does not configure `redact`.
pub const DEFAULT_REDACT: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
    "set-cookie",
];

pub fn default_redact() -> Vec<String> {
    DEFAULT_REDACT.iter().map(|name| name.to_string()).collect()
}

/// Replaces a secret with a stable, non-reversible fingerprint so different
/// keys can still be told apart: `[REDACTED len=108 sha256=1a2b3c4d]`
/// (first 8 hex chars of the SHA-256 of the value).
pub fn redact_value(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let fingerprint: String = digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "[REDACTED len={} sha256={fingerprint}]",
        value.chars().count()
    )
}

/// Redacts every header whose name matches one of `names` (case-insensitive).
/// Returns how many values were redacted.
pub fn redact_headers(headers: &mut Headers, names: &[String]) -> usize {
    let mut count = 0;
    for (name, value) in headers.iter_mut() {
        let listed = names.iter().any(|listed| listed.eq_ignore_ascii_case(name));
        if listed && !is_redacted(value) {
            *value = redact_value(value);
            count += 1;
        }
    }
    count
}

/// Redacts request and response headers of `exchange` in place.
pub fn redact_exchange(exchange: &mut Exchange, names: &[String]) {
    redact_headers(&mut exchange.request.headers, names);
    if let Some(response) = exchange.response.as_mut() {
        redact_headers(&mut response.headers, names);
    }
}

/// True for values produced by [`redact_value`], so redacting twice changes nothing.
fn is_redacted(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("[REDACTED len=")
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return false;
    };
    let Some((len, hash)) = inner.split_once(" sha256=") else {
        return false;
    };
    !len.is_empty()
        && len.bytes().all(|byte| byte.is_ascii_digit())
        && hash.len() == 8
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{RequestRecord, ResponseRecord};

    fn pairs(items: &[(&str, &str)]) -> Headers {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn value_has_length_and_stable_fingerprint() {
        assert_eq!(redact_value("secret"), "[REDACTED len=6 sha256=2bb80d53]");
        assert_eq!(redact_value(""), "[REDACTED len=0 sha256=e3b0c442]");
        assert_eq!(
            redact_value("sk-ant-api03-abc"),
            "[REDACTED len=16 sha256=5365cccb]"
        );
        assert_eq!(redact_value("secret"), redact_value("secret"));
        assert_ne!(redact_value("secret1"), redact_value("secret2"));
        // Length counts characters, the fingerprint covers the UTF-8 bytes.
        assert!(redact_value("héllo").starts_with("[REDACTED len=5 sha256="));
    }

    #[test]
    fn redacts_listed_headers_case_insensitively() {
        let mut headers = pairs(&[
            ("authorization", "Bearer abc"),
            ("content-type", "application/json"),
            ("X-Api-Key", "key-1"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
        ]);
        let names = vec![
            "Authorization".to_string(),
            "x-api-key".to_string(),
            "COOKIE".to_string(),
        ];
        assert_eq!(redact_headers(&mut headers, &names), 4);
        assert_eq!(
            headers[0],
            ("authorization".into(), redact_value("Bearer abc"))
        );
        assert_eq!(
            headers[1],
            ("content-type".into(), "application/json".into())
        );
        assert_eq!(headers[2], ("X-Api-Key".into(), redact_value("key-1")));
        assert_eq!(headers[3].1, redact_value("a=1"));
        assert_eq!(headers[4].1, redact_value("b=2"));
    }

    #[test]
    fn redaction_is_idempotent() {
        let mut headers = pairs(&[("authorization", "Bearer abc"), ("x-api-key", "k")]);
        let names = default_redact();
        assert_eq!(redact_headers(&mut headers, &names), 2);
        let once = headers.clone();
        assert_eq!(redact_headers(&mut headers, &names), 0);
        assert_eq!(headers, once);
    }

    #[test]
    fn lookalike_values_are_still_redacted() {
        for value in [
            "[REDACTED]",
            "[REDACTED len=3 sha256=XYZ]",
            "[REDACTED len= sha256=12345678]",
            "[REDACTED len=3 sha256=1234567]",
            "[REDACTED len=3 sha256=12345678] trailing",
        ] {
            let mut headers = pairs(&[("authorization", value)]);
            assert_eq!(
                redact_headers(&mut headers, &default_redact()),
                1,
                "{value}"
            );
            assert_eq!(headers[0].1, redact_value(value));
        }
    }

    #[test]
    fn no_names_means_no_change() {
        let mut headers = pairs(&[("authorization", "Bearer abc")]);
        assert_eq!(redact_headers(&mut headers, &[]), 0);
        assert_eq!(headers[0].1, "Bearer abc");
    }

    #[test]
    fn redacts_request_and_response_headers() {
        let mut exchange = Exchange {
            request: RequestRecord {
                headers: pairs(&[("authorization", "Bearer abc"), ("accept", "*/*")]),
                ..Default::default()
            },
            response: Some(ResponseRecord {
                headers: pairs(&[("set-cookie", "session=1"), ("content-length", "2")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        redact_exchange(&mut exchange, &default_redact());
        assert_eq!(exchange.request.headers[0].1, redact_value("Bearer abc"));
        assert_eq!(exchange.request.headers[1].1, "*/*");
        let response = exchange.response.as_ref().unwrap();
        assert_eq!(response.headers[0].1, redact_value("session=1"));
        assert_eq!(response.headers[1].1, "2");

        let before = exchange.clone();
        redact_exchange(&mut exchange, &default_redact());
        assert_eq!(exchange, before);

        let mut no_response = Exchange::default();
        no_response.request.headers = pairs(&[("x-goog-api-key", "g")]);
        redact_exchange(&mut no_response, &default_redact());
        assert_eq!(no_response.request.headers[0].1, redact_value("g"));
    }
}

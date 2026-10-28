//! The capture format. `events.jsonl` holds one [`Event`] per line; request and
//! response bodies are stored as raw bytes under `bodies/`.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Header name/value pairs in the order they were seen. Repeated names are kept.
pub type Headers = Vec<(String, String)>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
// Events are built and written one at a time, so the size difference costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// Written each time a session's proxy process starts.
    SessionStart(SessionStart),
    /// One complete request/response (or tunnel), written when it finishes.
    Exchange(Exchange),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionStart {
    pub session_id: String,
    pub at: String,
    pub pid: u32,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Plain `http://` request sent to TAP as a forward proxy.
    #[default]
    Forward,
    /// HTTPS (or plain HTTP) decrypted inside a `CONNECT` tunnel.
    Mitm,
    /// Origin-form request rewritten to the session's configured upstream.
    Reverse,
    /// Opaque bytes relayed without inspection (a `CONNECT` that was not intercepted).
    /// Upgraded exchanges (`101`) keep their mode and carry `tunnel` byte counts.
    Tunnel,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Forward => "forward",
            Mode::Mitm => "mitm",
            Mode::Reverse => "reverse",
            Mode::Tunnel => "tunnel",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Exchange {
    /// Session-unique, increasing across runs. This is the number users type (`tap show S 12`).
    pub seq: u64,
    pub session_id: String,
    /// RFC 3339 UTC with milliseconds, e.g. `2026-10-28T06:29:42.123Z`.
    pub started_at: String,
    pub started_unix_ms: u64,
    /// Request start until the response head arrived.
    #[serde(default)]
    pub ttfb_ms: Option<u64>,
    /// Request start until the response body (or tunnel) finished.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    pub mode: Mode,
    /// Peer address of the client connection, e.g. `127.0.0.1:53422`.
    pub client_addr: String,
    pub request: RequestRecord,
    #[serde(default)]
    pub response: Option<ResponseRecord>,
    #[serde(default)]
    pub tunnel: Option<TunnelStats>,
    /// Set when the exchange failed (upstream unreachable, TLS failure, timeout, ...).
    #[serde(default)]
    pub error: Option<String>,
    /// Human-readable remarks: hook failures/modifications, truncation, redaction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RequestRecord {
    pub method: String,
    /// Absolute URL (`https://api.example.com/v1/x?y=1`); for tunnels `host:port`.
    pub url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path plus query string; empty for tunnels.
    pub path: String,
    /// `HTTP/1.0`, `HTTP/1.1` or `HTTP/2`.
    pub version: String,
    /// As received from the client (names lowercased), after redaction.
    pub headers: Headers,
    pub body: BodyRecord,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ResponseRecord {
    pub status: u16,
    /// Canonical reason phrase for `status` (may be empty for unknown codes).
    pub reason: String,
    pub version: String,
    /// As received from upstream (names lowercased), after redaction.
    pub headers: Headers,
    pub body: BodyRecord,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct BodyRecord {
    /// Bytes that passed through (after transfer decoding, before content decoding).
    pub size: u64,
    /// Bytes saved to `file` (`<= size`).
    pub captured: u64,
    /// True when `captured < size` because of the session's `max_body` limit.
    pub truncated: bool,
    /// True when the body stream ended cleanly; false if either side aborted it.
    pub complete: bool,
    /// Path relative to the session directory, e.g. `bodies/12.req`. None when nothing was captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct TunnelStats {
    /// Client to upstream.
    pub bytes_up: u64,
    /// Upstream to client.
    pub bytes_down: u64,
}

impl Exchange {
    pub fn status(&self) -> Option<u16> {
        self.response.as_ref().map(|response| response.status)
    }
}

/// First value for `name` (case-insensitive).
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

/// Formats milliseconds since the Unix epoch as RFC 3339 UTC, e.g. `2026-10-28T06:29:42.123Z`.
pub fn rfc3339(unix_ms: u64) -> String {
    let seconds = unix_ms / 1000;
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let rem = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        unix_ms % 1000
    )
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe as i64 + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(1_761_632_982_123), "2025-10-28T06:29:42.123Z");
    }

    #[test]
    fn exchange_round_trips_with_type_tag() {
        let event = Event::Exchange(Exchange {
            seq: 3,
            request: RequestRecord {
                headers: vec![("a".into(), "1".into()), ("a".into(), "2".into())],
                ..Default::default()
            },
            ..Default::default()
        });
        let line = serde_json::to_string(&event).unwrap();
        assert!(line.starts_with(r#"{"type":"exchange","seq":3"#));
        assert_eq!(serde_json::from_str::<Event>(&line).unwrap(), event);
    }
}

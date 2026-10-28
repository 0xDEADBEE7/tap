//! Viewer tests against a hand-built session directory.

use super::args::{parse_show, ShowArgs};
use super::term::{size, LocalTime, Style};
use super::{show, Term};
use crate::record::{
    BodyRecord, Event, Exchange, Mode, RequestRecord, ResponseRecord, SessionStart, TunnelStats,
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

const T0: u64 = 1_761_632_982_123;

const ANTHROPIC_SSE: &str = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\"}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: ping\n\
data: {\"type\": \"ping\"}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\", world!\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"a\\\"\"}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";

const OPENAI_SSE: &str = "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\
\n\
data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\
\n\
data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" there\"}}]}\n\
\n\
data: [DONE]\n\
\n";

const REQUEST_JSON: &str = r#"{"model":"claude-sonnet-4-5","max_tokens":5,"stream":true}"#;
const GZIP_JSON: &str = r#"{"items":[1,2,3],"ok":true}"#;
const BROTLI_JSON: &str = r#"{"compressed":"br"}"#;
const TRUNCATED_JSON: &str =
    r#"{"events":[{"name":"app_open","ts":1},{"name":"app_close","ts":2}],"device":"abc123"}"#;

struct Fixture {
    base: PathBuf,
    dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let base = std::env::temp_dir().join(format!("tap-view-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = base.join("work");
        fs::create_dir_all(dir.join("bodies")).unwrap();
        Fixture { base, dir }
    }

    fn body(&self, file: &str, bytes: &[u8]) -> BodyRecord {
        fs::write(self.dir.join(file), bytes).unwrap();
        BodyRecord {
            size: bytes.len() as u64,
            captured: bytes.len() as u64,
            truncated: false,
            complete: true,
            file: Some(file.to_string()),
        }
    }

    fn events(&self, lines: &[String]) {
        fs::write(self.dir.join("events.jsonl"), lines.join("\n") + "\n").unwrap();
    }

    /// The directory name is the session id, as in a real session.
    fn session(&self) -> String {
        self.dir.file_name().unwrap().to_string_lossy().into_owned()
    }

    fn show(&self, args: &[&str]) -> String {
        self.show_with(
            args,
            Term {
                style: Style::plain(),
                width: None,
            },
        )
    }

    fn show_with(&self, args: &[&str], term: Term) -> String {
        let mut out = Vec::new();
        show(&self.dir, &self.session(), &parse(args), &mut out, term).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn show_bytes(&self, args: &[&str]) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        show(
            &self.dir,
            &self.session(),
            &parse(args),
            &mut out,
            Term {
                style: Style::plain(),
                width: None,
            },
        )?;
        Ok(out)
    }
}

fn parse(args: &[&str]) -> ShowArgs {
    parse_show(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()).unwrap()
}

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn brotli(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
        writer.write_all(bytes).unwrap();
    }
    out
}

fn binary_bytes() -> Vec<u8> {
    (0..300u32).map(|i| (i % 256) as u8).collect()
}

fn line(exchange: Exchange) -> String {
    serde_json::to_string(&Event::Exchange(exchange)).unwrap()
}

fn request(method: &str, url: &str, path: &str, body: BodyRecord) -> RequestRecord {
    let scheme = url.split("://").next().unwrap_or("").to_string();
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', ':']).next())
        .unwrap_or(url)
        .to_string();
    RequestRecord {
        method: method.into(),
        url: url.into(),
        scheme,
        host,
        port: 443,
        path: path.into(),
        version: "HTTP/1.1".into(),
        headers: Vec::new(),
        body,
    }
}

fn response(status: u16, reason: &str, pairs: &[(&str, &str)], body: BodyRecord) -> ResponseRecord {
    ResponseRecord {
        status,
        reason: reason.into(),
        version: "HTTP/1.1".into(),
        headers: headers(pairs),
        body,
    }
}

fn exchange(seq: u64, mode: Mode, request: RequestRecord, duration: u64) -> Exchange {
    Exchange {
        seq,
        session_id: "work".into(),
        started_at: crate::record::rfc3339(T0 + seq * 1000),
        started_unix_ms: T0 + seq * 1000,
        ttfb_ms: Some(duration / 2),
        duration_ms: Some(duration),
        mode,
        client_addr: "127.0.0.1:53422".into(),
        request,
        ..Default::default()
    }
}

/// Eight exchanges plus a session_start, an old-format line and a corrupt line.
fn session(name: &str) -> (Fixture, Vec<Exchange>) {
    let f = Fixture::new(name);
    let empty = BodyRecord {
        complete: true,
        ..Default::default()
    };

    let mut anthropic = exchange(
        1,
        Mode::Mitm,
        request(
            "POST",
            "https://api.anthropic.com/v1/messages",
            "/v1/messages",
            f.body("bodies/1.req", REQUEST_JSON.as_bytes()),
        ),
        2400,
    );
    anthropic.ttfb_ms = Some(271);
    anthropic.request.headers = headers(&[
        ("host", "api.anthropic.com"),
        ("content-type", "application/json"),
        ("x-api-key", "[REDACTED len=108 sha256=1a2b3c4d]"),
        ("anthropic-version", "2023-06-01"),
        ("content-length", "58"),
        ("accept-encoding", "gzip"),
    ]);
    anthropic.response = Some(response(
        200,
        "OK",
        &[
            ("content-type", "text/event-stream; charset=utf-8"),
            ("request-id", "req_1"),
        ],
        f.body("bodies/1.res", ANTHROPIC_SSE.as_bytes()),
    ));

    let mut openai = exchange(
        2,
        Mode::Mitm,
        request(
            "POST",
            "https://api.openai.com/v1/chat/completions",
            "/v1/chat/completions",
            empty.clone(),
        ),
        900,
    );
    openai.response = Some(response(
        200,
        "OK",
        &[],
        f.body("bodies/2.res", OPENAI_SSE.as_bytes()),
    ));

    let gzipped = gzip(GZIP_JSON.as_bytes());
    let mut gz = exchange(
        3,
        Mode::Mitm,
        request(
            "GET",
            "https://example.com/data.json",
            "/data.json",
            empty.clone(),
        ),
        45,
    );
    gz.response = Some(response(
        200,
        "OK",
        &[
            ("content-type", "application/json"),
            ("content-encoding", "gzip"),
        ],
        f.body("bodies/3.res", &gzipped),
    ));

    let mut br = exchange(
        4,
        Mode::Mitm,
        request("GET", "https://example.com/br", "/br", empty.clone()),
        46,
    );
    br.response = Some(response(
        200,
        "OK",
        &[
            ("content-type", "application/json"),
            ("content-encoding", "br"),
        ],
        f.body("bodies/4.res", &brotli(BROTLI_JSON.as_bytes())),
    ));

    let mut png = exchange(
        5,
        Mode::Mitm,
        request(
            "GET",
            "https://example.com/logo.png",
            "/logo.png",
            empty.clone(),
        ),
        12,
    );
    png.response = Some(response(
        200,
        "OK",
        &[("content-type", "image/png")],
        f.body("bodies/5.res", &binary_bytes()),
    ));

    let mut truncated_body = f.body("bodies/6.req", &TRUNCATED_JSON.as_bytes()[..20]);
    truncated_body.size = TRUNCATED_JSON.len() as u64;
    truncated_body.truncated = true;
    let mut telemetry = exchange(
        6,
        Mode::Mitm,
        request(
            "POST",
            "https://telemetry.example.com/v1/batch",
            "/v1/batch",
            truncated_body,
        ),
        271,
    );
    telemetry.request.headers = headers(&[("content-type", "application/json")]);
    let mut unauthorized = response(
        401,
        "Unauthorized",
        &[("content-type", "application/json")],
        f.body(
            "bodies/6.res",
            br#"{"error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        ),
    );
    unauthorized.version = "HTTP/2".into();
    telemetry.response = Some(unauthorized);
    telemetry.notes = vec!["request body truncated at 20 bytes (max_body)".into()];

    let mut failed = exchange(
        7,
        Mode::Forward,
        request("GET", "http://localhost:9/", "/", empty.clone()),
        30,
    );
    failed.request.headers = headers(&[("host", "localhost:9"), ("user-agent", "curl/8.7.1")]);
    failed.ttfb_ms = None;
    failed.error = Some(
        "upstream unreachable: connection refused (os error 61)\ncaused by: tcp connect".into(),
    );

    let mut tunnel = exchange(
        8,
        Mode::Tunnel,
        request("CONNECT", "example.org:443", "", empty),
        12_000,
    );
    tunnel.request.scheme = String::new();
    tunnel.request.host = "example.org".into();
    tunnel.request.headers = headers(&[("host", "example.org:443")]);
    tunnel.ttfb_ms = None;
    tunnel.tunnel = Some(TunnelStats {
        bytes_up: 1229,
        bytes_down: 4096,
    });

    let start = serde_json::to_string(&Event::SessionStart(SessionStart {
        session_id: "work".into(),
        at: crate::record::rfc3339(T0),
        pid: 42,
        version: "0.2.0".into(),
    }))
    .unwrap();
    let exchanges = vec![anthropic, openai, gz, br, png, telemetry, failed, tunnel];
    let mut lines = vec![start];
    lines.push(line(exchanges[1].clone()));
    lines.push(line(exchanges[0].clone()));
    lines.push(r#"{"type":"request","method":"GET","host":"old.example","path":"/"}"#.into());
    for exchange in &exchanges[2..] {
        lines.push(line(exchange.clone()));
    }
    lines.push(r#"{"type":"exchange","seq":9,"request":{"#.into());
    f.events(&lines);
    (f, exchanges)
}

fn row(cells: [&str; 7]) -> String {
    format!(
        "{:>1}  {:<12}  {:<7}  {:<6}  {:>8}  {:>13}  {}",
        cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6]
    )
    .trim_end()
    .to_string()
}

fn time(seq: u64) -> String {
    LocalTime::from_unix_ms(T0 + seq * 1000).time()
}

#[test]
fn lists_one_row_per_exchange_in_seq_order() {
    let (f, exchanges) = session("list");
    let out = f.show(&[]);
    let lines: Vec<&str> = out.lines().collect();
    let size_of = |seq: usize| size(exchanges[seq - 1].response.as_ref().unwrap().body.size, "");
    let expected = [
        row(["#", "TIME", "METHOD", "STATUS", "DURATION", "SIZE", "URL"]),
        row([
            "1",
            &time(1),
            "POST",
            "200",
            "2.4s",
            &size_of(1),
            "https://api.anthropic.com/v1/messages",
        ]),
        row([
            "2",
            &time(2),
            "POST",
            "200",
            "900ms",
            &size_of(2),
            "https://api.openai.com/v1/chat/completions",
        ]),
        row([
            "3",
            &time(3),
            "GET",
            "200",
            "45ms",
            &size_of(3),
            "https://example.com/data.json",
        ]),
        row([
            "4",
            &time(4),
            "GET",
            "200",
            "46ms",
            &size_of(4),
            "https://example.com/br",
        ]),
        row([
            "5",
            &time(5),
            "GET",
            "200",
            "12ms",
            "300B",
            "https://example.com/logo.png",
        ]),
        row([
            "6",
            &time(6),
            "POST",
            "401",
            "271ms",
            "71B",
            "https://telemetry.example.com/v1/batch",
        ]),
        row([
            "7",
            &time(7),
            "GET",
            "ERR",
            "30ms",
            "-",
            "http://localhost:9/ — upstream unreachable: connection refused (os error 61)",
        ]),
        row([
            "8",
            &time(8),
            "CONNECT",
            "TUN",
            "12.0s",
            "↑1.2KB ↓4.0KB",
            "example.org:443",
        ]),
        "8 of 8 exchanges (2 unreadable lines skipped)".to_string(),
    ];
    assert_eq!(lines, expected);
}

#[test]
fn list_fits_the_terminal_and_keeps_the_error_visible() {
    let (f, _) = session("width");
    let out = f.show_with(
        &[],
        Term {
            style: Style::plain(),
            width: Some(100),
        },
    );
    for line in out.lines() {
        assert!(line.chars().count() <= 100, "too wide: {line:?}");
    }
    let error_row = out.lines().find(|line| line.starts_with("7  ")).unwrap();
    assert!(
        error_row.contains("http://localhost:9/ — upstream unreach"),
        "{error_row}"
    );
    assert!(error_row.ends_with('…'));
    let unlimited = f.show(&[]);
    assert!(unlimited.contains("https://api.openai.com/v1/chat/completions\n"));
}

#[test]
fn list_last_json_and_colour() {
    let (f, exchanges) = session("last");
    let out = f.show(&["--last", "2"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4);
    assert!(lines[1].starts_with("7  "));
    assert!(lines[2].starts_with("8  "));
    assert_eq!(lines[3], "2 of 8 exchanges (2 unreadable lines skipped)");

    let json = f.show(&["--json"]);
    let parsed: Vec<Exchange> = json
        .lines()
        .map(|line| match serde_json::from_str::<Event>(line).unwrap() {
            Event::Exchange(exchange) => exchange,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(parsed, exchanges);

    let coloured = f.show_with(
        &[],
        Term {
            style: Style { color: true },
            width: None,
        },
    );
    assert!(coloured.contains("\x1b[32m200   \x1b[0m"));
    assert!(coloured.contains("\x1b[33m401   \x1b[0m"));
    assert!(coloured.contains("\x1b[31mERR   \x1b[0m"));
    assert!(coloured.contains("\x1b[2m#  TIME"));
}

#[test]
fn list_prefixes_dates_when_the_capture_spans_days() {
    let f = Fixture::new("days");
    let empty = BodyRecord::default();
    let first = exchange(
        1,
        Mode::Forward,
        request("GET", "http://a.test/", "/", empty.clone()),
        5,
    );
    let mut later = exchange(
        2,
        Mode::Forward,
        request("GET", "http://a.test/", "/", empty),
        5,
    );
    later.started_unix_ms += 2 * 86_400_000;
    f.events(&[line(first), line(later.clone())]);
    let out = f.show(&[]);
    let local = LocalTime::from_unix_ms(later.started_unix_ms);
    let stamp = format!("{} {}", local.date(), local.time());
    assert!(
        out.lines()
            .nth(2)
            .unwrap()
            .starts_with(&format!("2  {stamp}  GET")),
        "{out}"
    );
    assert!(out
        .lines()
        .next()
        .unwrap()
        .starts_with("#  TIME                     METHOD"));
}

#[test]
fn empty_capture_explains_what_to_check() {
    let f = Fixture::new("empty");
    let out = f.show(&[]);
    assert!(out.starts_with("No exchanges recorded yet in "), "{out}");
    assert!(out.contains("Is the session running?"));
    assert!(out.contains("tap exec work -- curl https://example.com"));
    assert!(!out.contains("skipped"));

    f.events(&[r#"{"type":"response","status":200}"#.to_string()]);
    let out = f.show(&[]);
    assert!(out.ends_with("(1 unreadable line skipped: corrupt, or written by an older TAP)\n"));
    assert_eq!(f.show(&["--json"]), "");
}

#[test]
fn detail_shows_request_and_response_sections_with_sse() {
    let (f, _) = session("detail");
    let out = f.show(&["1"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "#1  POST https://api.anthropic.com/v1/messages");
    let local = LocalTime::from_unix_ms(T0 + 1000);
    assert_eq!(
        lines[1],
        format!(
            "mitm · {} {} · ttfb 271ms · total 2.4s · client 127.0.0.1:53422",
            local.date(),
            local.time()
        )
    );
    let request_at = lines.iter().position(|line| *line == "Request").unwrap();
    assert_eq!(
        &lines[request_at..request_at + 13],
        [
            "Request",
            "POST /v1/messages HTTP/1.1",
            "host:              api.anthropic.com",
            "content-type:      application/json",
            "x-api-key:         [REDACTED len=108 sha256=1a2b3c4d]",
            "anthropic-version: 2023-06-01",
            "content-length:    58",
            "accept-encoding:   gzip",
            "",
            "{",
            "  \"model\": \"claude-sonnet-4-5\",",
            "  \"max_tokens\": 5,",
            "  \"stream\": true",
        ]
    );
    let response_at = lines.iter().position(|line| *line == "Response").unwrap();
    assert_eq!(
        &lines[response_at..],
        [
            "Response",
            "HTTP/1.1 200 OK",
            "content-type: text/event-stream; charset=utf-8",
            "request-id:   req_1",
            "",
            "(event stream: 7 events)",
            r#"[1] message_start  {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5"}}"#,
            r#"[2] content_block_start  {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"[3] ping  {"type":"ping"}"#,
            r#"[4] content_block_delta  {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#,
            r#"[5] content_block_delta  {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":", world!"}}"#,
            r#"[6] content_block_delta  {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\""}}"#,
            r#"[7] message_stop  {"type":"message_stop"}"#,
            "",
            "assembled text:",
            "Hello, world!",
            "",
            "raw bodies: tap show work 1 --body req|res · replay: tap show work 1 --curl",
        ]
    );
}

#[test]
fn detail_detects_openai_sse_without_content_type() {
    let (f, _) = session("openai");
    let out = f.show(&["2"]);
    let expected = [
        "(event stream: 4 events)",
        r#"[1] message  {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}"#,
        r#"[2] message  {"id":"c1","choices":[{"index":0,"delta":{"content":"Hi"}}]}"#,
        r#"[3] message  {"id":"c1","choices":[{"index":0,"delta":{"content":" there"}}]}"#,
        "[4] message  [DONE]",
        "",
        "assembled text:",
        "Hi there",
    ]
    .join("\n");
    assert!(out.contains(&expected), "{out}");
    assert!(
        out.contains("Request\nPOST /v1/chat/completions HTTP/1.1\n\n(no body)\n"),
        "{out}"
    );
}

#[test]
fn detail_decodes_gzip_and_brotli() {
    let (f, _) = session("decode");
    let gzipped = gzip(GZIP_JSON.as_bytes()).len() as u64;
    let out = f.show(&["3"]);
    let expected = format!(
        "\n\n({}: {} → {})\n{{\n  \"items\": [\n    1,\n    2,\n    3\n  ],\n  \"ok\": true\n}}\n",
        "gzip",
        size(gzipped, " "),
        size(GZIP_JSON.len() as u64, " ")
    );
    assert!(out.contains(&expected), "{out}");

    let out = f.show(&["4"]);
    assert!(out.contains("(br: "), "{out}");
    assert!(out.contains(&format!(
        "→ {})\n{{\n  \"compressed\": \"br\"\n}}\n",
        size(BROTLI_JSON.len() as u64, " ")
    )));
}

#[test]
fn detail_hexdumps_binary_bodies() {
    let (f, _) = session("binary");
    let out = f.show(&["5"]);
    let expected = [
        "binary, 300 bytes",
        "00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |................|",
        "00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  |................|",
        "00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f  | !\"#$%&'()*+,-./|",
    ]
    .join("\n");
    assert!(out.contains(&expected), "{out}");
    assert!(out.contains("000000f0  f0 f1 f2 f3 f4 f5 f6 f7  f8 f9 fa fb fc fd fe ff  |................|\n… 44 more bytes\nsave it: tap show work 5 --body res > file\n"));
    assert!(!out.contains("00000100"));
}

#[test]
fn detail_notes_truncation_notes_and_http2() {
    let (f, _) = session("truncated");
    let out = f.show(&["6"]);
    assert!(out.contains("note: request body truncated at 20 bytes (max_body)\n"));
    assert!(
        out.contains("\n(truncated: captured 20 B of 85 B — the session's max_body limit)\n{\"events\":[{\"name\":\"\n"),
        "{out}"
    );
    assert!(!out.contains("not valid JSON"));
    assert!(out.contains(
        "Response\nHTTP/2 401 Unauthorized\ncontent-type: application/json\n\n{\n  \"error\": {\n"
    ));
}

#[test]
fn detail_shows_errors_and_tunnels() {
    let (f, _) = session("errors");
    let out = f.show(&["7"]);
    assert!(out.contains(
        "error: upstream unreachable: connection refused (os error 61)\ncaused by: tcp connect\n"
    ));
    assert!(out.contains(
        "Request\nGET / HTTP/1.1\nhost:       localhost:9\nuser-agent: curl/8.7.1\n\n(no body)\n"
    ));
    assert!(out.contains("Response\n(no response: the exchange failed, see error above)\n"));
    assert!(out.lines().nth(1).unwrap().starts_with("forward · "));

    let out = f.show(&["8"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "#8  CONNECT example.org:443");
    assert!(out
        .contains("Request\nCONNECT example.org:443 HTTP/1.1\nhost: example.org:443\n\nTunnel\n"));
    assert!(out.contains(
        "↑ 1.2 KB  client → upstream (1229 bytes)\n↓ 4.0 KB  upstream → client (4096 bytes)\n"
    ));
    assert!(!out.contains("Response"));
}

#[test]
fn detail_cuts_long_bodies_unless_full() {
    let f = Fixture::new("long");
    let text: String = (1..=230).map(|n| format!("line {n}\n")).collect();
    let mut long = exchange(
        1,
        Mode::Forward,
        request("GET", "http://a.test/", "/", BodyRecord::default()),
        5,
    );
    long.response = Some(response(
        200,
        "OK",
        &[("content-type", "text/plain")],
        f.body("bodies/1.res", text.as_bytes()),
    ));
    f.events(&[line(long)]);
    let out = f.show(&["1"]);
    assert!(
        out.contains("line 200\n… 30 more lines (use --full)\n"),
        "{out}"
    );
    assert!(!out.contains("line 201"));
    let out = f.show(&["1", "--full"]);
    assert!(out.contains("line 229\nline 230\n"));
    assert!(!out.contains("more lines"));
}

#[test]
fn curl_replays_with_exported_secrets_and_the_body_file() {
    let (f, _) = session("curl");
    let out = f.show(&["1", "--curl"]);
    let body = std::path::absolute(f.dir.join("bodies/1.req")).unwrap();
    let expected = format!(
        "# These header values were redacted when recorded. Export the real values first:\n\
         #   export X_API_KEY='<the full header value>'\n\
         curl https://api.anthropic.com/v1/messages \\\n\
         \x20 -H 'content-type: application/json' \\\n\
         \x20 -H \"x-api-key: $X_API_KEY\" \\\n\
         \x20 -H 'anthropic-version: 2023-06-01' \\\n\
         \x20 -H 'accept-encoding: gzip' \\\n\
         \x20 --compressed \\\n\
         \x20 --data-binary {}\n",
        super::detail::shell_quote(&format!("@{}", body.display()))
    );
    assert_eq!(out, expected);

    let out = f.show(&["6", "--curl"]);
    assert!(
        out.starts_with("# warning: only 20 B of the 85 B request body was captured"),
        "{out}"
    );
    assert!(out.contains("curl https://telemetry.example.com/v1/batch \\\n  -H 'content-type: application/json' \\\n  --data-binary "));

    assert_eq!(
        f.show(&["7", "--curl"]),
        "curl http://localhost:9/ \\\n  -H 'user-agent: curl/8.7.1'\n"
    );
    let error = f.show_bytes(&["8", "--curl"]).unwrap_err();
    assert!(error.to_string().contains("opaque tunnel"));
}

#[test]
fn body_flag_writes_the_stored_bytes_exactly() {
    let (f, _) = session("raw");
    assert_eq!(
        f.show_bytes(&["3", "--body", "res"]).unwrap(),
        gzip(GZIP_JSON.as_bytes())
    );
    assert_eq!(
        f.show_bytes(&["1", "--body", "req"]).unwrap(),
        REQUEST_JSON.as_bytes()
    );
    assert_eq!(f.show_bytes(&["5", "--body=res"]).unwrap(), binary_bytes());
    assert_eq!(
        f.show_bytes(&["6", "--body", "req"]).unwrap(),
        &TRUNCATED_JSON.as_bytes()[..20]
    );
    let error = f.show_bytes(&["7", "--body", "res"]).unwrap_err();
    assert!(error.to_string().contains("has no response"));
    let error = f.show_bytes(&["2", "--body", "req"]).unwrap_err();
    assert!(error.to_string().contains("empty request body"));

    let terminal = Term {
        style: Style::plain(),
        width: Some(80),
    };
    let mut out = Vec::new();
    let error = show(
        &f.dir,
        &f.session(),
        &parse(&["5", "--body", "res"]),
        &mut out,
        terminal,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Save it: tap show work 5 --body res > file"),
        "{error}"
    );
    assert!(out.is_empty());
    show(
        &f.dir,
        &f.session(),
        &parse(&["1", "--body", "req"]),
        &mut out,
        terminal,
    )
    .unwrap();
    assert_eq!(out, REQUEST_JSON.as_bytes());
}

#[test]
fn json_detail_and_missing_exchanges() {
    let (f, exchanges) = session("json");
    let out = f.show(&["3", "--json"]);
    assert!(out.starts_with("{\n  \"type\": \"exchange\",\n  \"seq\": 3,"));
    let parsed: Event = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed, Event::Exchange(exchanges[2].clone()));

    let error = f.show_bytes(&["99"]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "no exchange #99 in session work (it has #1 to #8; list them: tap show work)"
    );
}

#[test]
fn commands_reject_bad_arguments_with_usage() {
    let dir = std::env::temp_dir().join("tap-view-never-created");
    let error = super::show_command(&dir, "work", &["--bogus".to_string()]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error
        .to_string()
        .starts_with("unknown option --bogus\n\ntap show"));
    let error = super::tail_command(&dir, &["--last".to_string()]).unwrap_err();
    assert!(error.to_string().contains("examples:"));
    assert!(super::usage().contains("tap show work 12 --body res > response.bin"));
}

#[test]
fn upgrades_keep_their_status_and_are_not_called_opaque() {
    let f = Fixture::new("upgrade");
    let mut ws = exchange(
        1,
        Mode::Mitm,
        request("GET", "https://a.test/ws", "/ws", BodyRecord::default()),
        5,
    );
    ws.request.headers = headers(&[("upgrade", "websocket"), ("connection", "Upgrade")]);
    ws.response = Some(response(
        101,
        "Switching Protocols",
        &[("upgrade", "websocket")],
        BodyRecord::default(),
    ));
    ws.tunnel = Some(TunnelStats {
        bytes_up: 10,
        bytes_down: 2048,
    });
    f.events(&[line(ws)]);
    let row = f.show(&[]).lines().nth(1).unwrap().to_string();
    assert!(row.contains("  GET     101   "), "{row}");
    assert!(row.contains("↑10B ↓2.0KB  https://a.test/ws"), "{row}");
    let out = f.show(&["1"]);
    assert!(out.contains("Response\nHTTP/1.1 101 Switching Protocols\n"));
    assert!(out.contains("Tunnel\n↑ 10 B  client → upstream (10 bytes)\n"));
    assert!(out.contains("the connection was upgraded"), "{out}");
    assert!(!out.contains("opaque"), "{out}");
    let error = f.show_bytes(&["1", "--curl"]).unwrap_err().to_string();
    assert!(error.contains("upgraded the connection"), "{error}");
}

#[test]
fn captured_text_cannot_send_terminal_controls() {
    let f = Fixture::new("controls");
    let mut evil = exchange(
        1,
        Mode::Mitm,
        request(
            "POST",
            "https://a.test/\x1b[2J",
            "/\x1b[2J",
            f.body(
                "bodies/1.req",
                "{\"a\":\"csi \u{9b}31m nel \u{85} del \u{7f}\",\"padding\":\"plenty of ordinary text here\"}"
                    .as_bytes(),
            ),
        ),
        5,
    );
    evil.request.headers = headers(&[
        ("content-type", "application/json"),
        ("x-evil", "\x1b]0;title\x07"),
    ]);
    evil.response = Some(response(
        200,
        "OK\x1b[0m",
        &[("content-type", "text/event-stream")],
        f.body(
            "bodies/1.res",
            "event: x\u{9b}\ndata: {\"delta\":{\"text\":\"\u{9b}2J\"}}\n\n".as_bytes(),
        ),
    ));
    evil.error = Some("bad \x1b[31m thing".into());
    evil.notes = vec!["note \u{9b}".into()];
    let mut ndjson = exchange(
        2,
        Mode::Mitm,
        request("GET", "https://a.test/n", "/n", BodyRecord::default()),
        5,
    );
    ndjson.response = Some(response(
        200,
        "OK",
        &[("content-type", "application/x-ndjson")],
        f.body("bodies/2.res", "{\"a\":\"\u{9b}\"}\n[1]\n".as_bytes()),
    ));
    f.events(&[line(evil), line(ndjson)]);
    for args in [&[][..], &["1"][..], &["2"][..]] {
        let out = f.show(args);
        assert!(
            !out.chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "{args:?}: {out:?}"
        );
    }
    let out = f.show(&["1"]);
    assert!(
        out.contains("\"a\": \"csi \\u{009b}31m nel \\u{0085} del \\x7f\""),
        "{out}"
    );
    assert!(
        out.contains("[1] x\\u{009b}  {\"delta\":{\"text\":\"\\u{009b}2J\"}}"),
        "{out}"
    );
    assert!(out.contains("x-evil:       \\x1b]0;title\\x07"), "{out}");
}

#[test]
fn very_long_lines_are_cut_unless_full() {
    let f = Fixture::new("longline");
    let image = "A".repeat(10_000);
    let body = format!("{{\"type\":\"image\",\"data\":\"{image}\"}}");
    let mut upload = exchange(
        1,
        Mode::Mitm,
        request(
            "POST",
            "https://api.anthropic.com/v1/messages",
            "/v1/messages",
            f.body("bodies/1.req", body.as_bytes()),
        ),
        5,
    );
    upload.request.headers = headers(&[("content-type", "application/json")]);
    f.events(&[line(upload)]);
    let out = f.show(&["1"]);
    let data = out
        .lines()
        .find(|line| line.starts_with("  \"data\""))
        .unwrap();
    let kept = super::render::MAX_LINE_CHARS;
    let more = "  \"data\": \"".len() + image.len() + 1 - kept;
    assert_eq!(
        data,
        format!(
            "{} … {more} more characters (use --full)",
            &format!("  \"data\": \"{image}\"")[..kept]
        )
    );
    let full = f.show(&["1", "--full"]);
    assert!(full.contains(&format!("  \"data\": \"{image}\"\n")));
}

#[test]
fn unreadable_bodies_and_unrecorded_numbers_are_explained() {
    let f = Fixture::new("missing");
    let mut gone = exchange(
        4,
        Mode::Mitm,
        request("GET", "https://a.test/m", "/m", BodyRecord::default()),
        5,
    );
    let mut record = f.body("bodies/4.res", b"x");
    record.file = Some("bodies/deleted.res".into());
    gone.response = Some(response(200, "OK", &[], record));
    let later = exchange(
        9,
        Mode::Mitm,
        request("GET", "https://a.test/", "/", BodyRecord::default()),
        5,
    );
    f.events(&[line(gone), line(later)]);
    let error = f.show_bytes(&["4", "--body", "res"]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(
        error
            .to_string()
            .starts_with("could not read the response body of exchange #4 (bodies/deleted.res): "),
        "{error}"
    );
    assert!(f
        .show(&["4"])
        .contains("(1 B body: could not read bodies/deleted.res: "));
    assert_eq!(
        f.show_bytes(&["6"]).unwrap_err().to_string(),
        "no exchange #6 in session work (#6 was not recorded: it was outside the session's filters \
         or has not finished yet; list them: tap show work)"
    );
    assert!(f
        .show_bytes(&["12"])
        .unwrap_err()
        .to_string()
        .contains("(it has #4 to #9;"));
}

#[test]
fn failed_connects_are_not_offered_for_replay() {
    let f = Fixture::new("connect");
    let mut handshake = exchange(
        1,
        Mode::Mitm,
        request("CONNECT", "a.test:443", "", BodyRecord::default()),
        5,
    );
    handshake.error = Some("client TLS handshake failed: does the client trust TAP's CA?".into());
    f.events(&[line(handshake)]);
    let out = f.show(&["1"]);
    assert!(
        out.contains("Request\nCONNECT a.test:443 HTTP/1.1\n"),
        "{out}"
    );
    assert!(!out.contains("--curl"), "{out}");
    let error = f.show_bytes(&["1", "--curl"]).unwrap_err().to_string();
    assert!(error.contains("is a CONNECT"), "{error}");
}

#[test]
fn curl_picks_the_method_flag_and_quotes_everything() {
    let f = Fixture::new("curlmethods");
    let body = f.body("bodies/1.req", b"{}");
    let mut aborted = f.body("bodies/4.req", b"par");
    aborted.complete = false;
    let cases = [
        exchange(
            1,
            Mode::Forward,
            request("GET", "http://a.test/x?a=1&b='2'", "/", body),
            5,
        ),
        exchange(
            2,
            Mode::Forward,
            request("POST", "http://a.test/", "/", BodyRecord::default()),
            5,
        ),
        exchange(
            3,
            Mode::Forward,
            request("HEAD", "http://a.test/", "/", BodyRecord::default()),
            5,
        ),
        exchange(
            4,
            Mode::Forward,
            request("PUT", "http://a.test/", "/", aborted),
            5,
        ),
    ];
    f.events(&cases.iter().cloned().map(line).collect::<Vec<_>>());
    let curl = |seq: &str| String::from_utf8(f.show_bytes(&[seq, "--curl"]).unwrap()).unwrap();
    let get = curl("1");
    assert!(
        get.starts_with(
            "curl 'http://a.test/x?a=1&b='\\''2'\\''' \\\n  -X GET \\\n  --data-binary "
        ),
        "{get}"
    );
    assert_eq!(curl("2"), "curl http://a.test/ \\\n  -X POST\n");
    assert_eq!(curl("3"), "curl http://a.test/ \\\n  --head\n");
    let put = curl("4");
    assert!(
        put.starts_with("# warning: the client aborted the request body"),
        "{put}"
    );
    assert!(put.contains("\n  -X PUT \\\n  --data-binary "), "{put}");
}

//! Turning captured body bytes into something a person can read: content decoding,
//! server-sent events, JSON, text and hexdumps. Pure functions; no I/O.

use super::term::{sanitize, sanitize_line, size, Style};
use crate::record::{header, BodyRecord};
use std::io::Read;

/// Bodies render at most this many lines unless `full` is set.
pub const MAX_LINES: usize = 200;
/// Longer lines are cut unless `full` is set, so one huge line cannot flood the terminal.
pub const MAX_LINE_CHARS: usize = 2000;
const HEXDUMP_BYTES: usize = 256;
const MAX_DECODED: u64 = 64 * 1024 * 1024;

pub struct RenderOptions<'a> {
    /// Do not cut long output.
    pub full: bool,
    pub style: Style,
    /// Command that saves the raw body, e.g. `tap show S 12 --body res`.
    pub save_command: &'a str,
}

/// Renders a captured body (`bytes` exactly as stored, still content-encoded) for display.
/// `headers` are the message's headers (for `content-type` / `content-encoding`).
/// The result has no trailing newline.
pub fn render_body(
    bytes: &[u8],
    headers: &[(String, String)],
    record: &BodyRecord,
    options: &RenderOptions,
) -> String {
    let style = options.style;
    let mut notes = Vec::new();
    if bytes.is_empty() {
        let line = if record.size == 0 {
            "(no body)".to_string()
        } else if record.truncated {
            format!(
                "({} body, not captured: over the session's max_body limit)",
                size(record.size, " ")
            )
        } else {
            format!("({} body, not captured)", size(record.size, " "))
        };
        return style.dim(&line);
    }
    if record.truncated {
        notes.push(format!(
            "(truncated: captured {} of {} — the session's max_body limit)",
            size(record.captured, " "),
            size(record.size, " ")
        ));
    }
    if !record.complete {
        notes.push(format!(
            "(incomplete: the stream ended early, after {} — the client or upstream aborted it)",
            size(record.size, " ")
        ));
    }
    let cut_short = record.truncated || !record.complete;

    let decoded = decode_content(bytes, header(headers, "content-encoding"), &mut notes);
    let content_type = header(headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut out: Vec<String> = notes.iter().map(|note| style.dim(note)).collect();
    match text_of(&decoded) {
        None => out.extend(binary(&decoded, options)),
        Some(text) if content_type.contains("text/event-stream") || looks_like_sse(text) => {
            out.extend(event_stream(text, options))
        }
        Some(text) => {
            let wants_json = content_type.contains("json");
            let trimmed = text.trim_start();
            let looks_json = trimmed.starts_with('{') || trimmed.starts_with('[');
            let lines = if (wants_json || looks_json) && is_json(text) {
                sanitize(&pretty_json(text))
                    .lines()
                    .map(String::from)
                    .collect()
            } else if wants_json && is_json_lines(text) {
                text.lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| sanitize_line(&compact_json(line)))
                    .collect()
            } else {
                if wants_json && !cut_short && !text.trim().is_empty() {
                    out.push(style.dim("(content-type says JSON, but this is not valid JSON)"));
                }
                sanitize(text).lines().map(String::from).collect()
            };
            out.extend(cut(lines, options));
        }
    }
    out.join("\n")
}

/// Decodes `Content-Encoding` (gzip, x-gzip, deflate, br; listed in the order applied) for display.
/// On failure the raw bytes come back, and `notes` says what happened.
fn decode_content(bytes: &[u8], encoding: Option<&str>, notes: &mut Vec<String>) -> Vec<u8> {
    let codings: Vec<String> = encoding
        .unwrap_or("")
        .split(',')
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty() && coding != "identity")
        .collect();
    if codings.is_empty() {
        return bytes.to_vec();
    }
    let label = codings.join(", ");
    let mut current = bytes.to_vec();
    for coding in codings.iter().rev() {
        match decode_one(coding, &current) {
            Decoded::Unsupported => {
                notes.push(format!(
                    "(content-encoding {coding} is not decoded for display; showing the raw bytes)"
                ));
                return bytes.to_vec();
            }
            Decoded::Failed(error) => {
                notes.push(format!(
                    "({coding} decoding failed: {error}; showing the raw bytes)"
                ));
                return bytes.to_vec();
            }
            Decoded::Partial(output, error) => {
                notes.push(format!(
                    "({label}: decoded {} before an error: {error})",
                    size(output.len() as u64, " ")
                ));
                return output;
            }
            Decoded::Capped(output) => {
                notes.push(format!(
                    "({label}: showing the first {} of the decoded body)",
                    size(output.len() as u64, " ")
                ));
                return output;
            }
            Decoded::Done(output) => current = output,
        }
    }
    notes.push(format!(
        "({label}: {} → {})",
        size(bytes.len() as u64, " "),
        size(current.len() as u64, " ")
    ));
    current
}

enum Decoded {
    Done(Vec<u8>),
    Capped(Vec<u8>),
    Partial(Vec<u8>, String),
    Failed(String),
    Unsupported,
}

fn decode_one(coding: &str, input: &[u8]) -> Decoded {
    match coding {
        "gzip" | "x-gzip" => read_all(flate2::read::MultiGzDecoder::new(input)),
        "deflate" => match read_all(flate2::read::ZlibDecoder::new(input)) {
            Decoded::Done(output) => Decoded::Done(output),
            zlib => match read_all(flate2::read::DeflateDecoder::new(input)) {
                Decoded::Done(output) => Decoded::Done(output),
                raw => {
                    let produced = |decoded: &Decoded| match decoded {
                        Decoded::Partial(output, _) | Decoded::Capped(output) => output.len(),
                        _ => 0,
                    };
                    if produced(&raw) > produced(&zlib) {
                        raw
                    } else {
                        zlib
                    }
                }
            },
        },
        "br" => read_all(brotli::Decompressor::new(input, 4096)),
        _ => Decoded::Unsupported,
    }
}

fn read_all(reader: impl Read) -> Decoded {
    let mut output = Vec::new();
    let mut limited = reader.take(MAX_DECODED + 1);
    match limited.read_to_end(&mut output) {
        Ok(_) if output.len() as u64 > MAX_DECODED => {
            output.truncate(MAX_DECODED as usize);
            Decoded::Capped(output)
        }
        Ok(_) => Decoded::Done(output),
        Err(error) if output.is_empty() => Decoded::Failed(error.to_string()),
        Err(error) => Decoded::Partial(output, error.to_string()),
    }
}

/// The body as text, unless it is not UTF-8 or is mostly control characters.
fn text_of(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut total = 0usize;
    let mut control = 0usize;
    for c in text.chars() {
        total += 1;
        if c == '\0' {
            return None;
        }
        if c.is_control() && !matches!(c, '\n' | '\t' | '\r' | '\x0c' | '\x1b') {
            control += 1;
        }
    }
    (control * 20 <= total).then_some(text)
}

fn cut(lines: Vec<String>, options: &RenderOptions) -> Vec<String> {
    if options.full {
        return lines;
    }
    let more = lines.len().saturating_sub(MAX_LINES);
    let mut lines: Vec<String> = lines
        .into_iter()
        .take(MAX_LINES)
        .map(|line| shorten(line, options.style))
        .collect();
    if more > 0 {
        lines.push(
            options
                .style
                .dim(&format!("… {more} more lines (use --full)")),
        );
    }
    lines
}

/// Cuts one very long line (a base64 image, a minified bundle) to `MAX_LINE_CHARS`.
fn shorten(line: String, style: Style) -> String {
    let Some((end, _)) = line.char_indices().nth(MAX_LINE_CHARS) else {
        return line;
    };
    let more = line[end..].chars().count();
    format!(
        "{}{}",
        &line[..end],
        style.dim(&format!(" … {more} more characters (use --full)"))
    )
}

fn binary(bytes: &[u8], options: &RenderOptions) -> Vec<String> {
    let mut out = vec![format!("binary, {} bytes", bytes.len())];
    out.extend(hexdump(&bytes[..bytes.len().min(HEXDUMP_BYTES)]));
    if bytes.len() > HEXDUMP_BYTES {
        out.push(
            options
                .style
                .dim(&format!("… {} more bytes", bytes.len() - HEXDUMP_BYTES)),
        );
    }
    out.push(
        options
            .style
            .dim(&format!("save it: {} > file", options.save_command)),
    );
    out
}

/// `hexdump -C` style: offset, 16 bytes in two groups of 8, printable ASCII.
pub fn hexdump(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let mut hex = String::new();
            for column in 0..16 {
                if column == 8 {
                    hex.push(' ');
                }
                match chunk.get(column) {
                    Some(byte) => hex.push_str(&format!("{byte:02x} ")),
                    None => hex.push_str("   "),
                }
            }
            let ascii: String = chunk
                .iter()
                .map(|&byte| {
                    if byte.is_ascii_graphic() || byte == b' ' {
                        byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:08x}  {hex} |{ascii}|", row * 16)
        })
        .collect()
}

/// One parsed server-sent event.
#[derive(Debug, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field; `message` when absent.
    pub name: String,
    /// `data:` lines joined with `\n`.
    pub data: String,
}

const SSE_FIELDS: [&str; 4] = ["event", "data", "id", "retry"];

/// A body that starts like an event stream and has no lines that are not SSE fields.
fn looks_like_sse(text: &str) -> bool {
    let mut lines = text.lines().map(|line| line.trim_end_matches('\r'));
    let Some(first) = lines.by_ref().find(|line| !line.is_empty()) else {
        return false;
    };
    if !(first.starts_with("event:") || first.starts_with("data:")) {
        return false;
    }
    lines.all(|line| {
        line.is_empty()
            || line.starts_with(':')
            || SSE_FIELDS.iter().any(|field| {
                line.strip_prefix(field)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
            })
    })
}

/// Parses an event stream (also an unfinished one: a pending event at the end is kept).
pub fn parse_sse(text: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut name = String::new();
    let mut data: Vec<&str> = Vec::new();
    let mut flush = |name: &mut String, data: &mut Vec<&str>| {
        if !name.is_empty() || !data.is_empty() {
            events.push(SseEvent {
                name: if name.is_empty() {
                    "message".to_string()
                } else {
                    std::mem::take(name)
                },
                data: data.join("\n"),
            });
        }
        name.clear();
        data.clear();
    };
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            flush(&mut name, &mut data);
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => name = value.to_string(),
            "data" => data.push(value),
            _ => {}
        }
    }
    flush(&mut name, &mut data);
    events
}

/// Text from streamed deltas: Anthropic `delta.text`, OpenAI chat `choices[].delta.content`
/// and OpenAI responses `response.output_text.delta`. None when the stream has no text deltas.
pub fn assembled_text(events: &[SseEvent]) -> Option<String> {
    let mut text = String::new();
    let mut found = false;
    for event in events {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&event.data) else {
            continue;
        };
        if let Some(delta) = value.get("delta") {
            let kind = delta.get("type").and_then(|kind| kind.as_str());
            if let (Some(piece), None | Some("text_delta")) =
                (delta.get("text").and_then(|text| text.as_str()), kind)
            {
                text.push_str(piece);
                found = true;
            }
            if value.get("type").and_then(|kind| kind.as_str())
                == Some("response.output_text.delta")
            {
                if let Some(piece) = delta.as_str() {
                    text.push_str(piece);
                    found = true;
                }
            }
        }
        if let Some(choices) = value.get("choices").and_then(|choices| choices.as_array()) {
            for choice in choices {
                let index = choice.get("index").and_then(|index| index.as_u64());
                if !matches!(index, None | Some(0)) {
                    continue;
                }
                let piece = choice
                    .get("delta")
                    .and_then(|delta| delta.get("content"))
                    .and_then(|content| content.as_str());
                if let Some(piece) = piece {
                    text.push_str(piece);
                    found = true;
                }
            }
        }
    }
    found.then_some(text)
}

fn event_stream(text: &str, options: &RenderOptions) -> Vec<String> {
    let style = options.style;
    let events = parse_sse(text);
    let mut out = vec![style.dim(&format!(
        "(event stream: {} event{})",
        events.len(),
        if events.len() == 1 { "" } else { "s" }
    ))];
    let listed = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let data = if is_json(&event.data) {
                sanitize_line(&compact_json(&event.data))
            } else {
                sanitize_line(&event.data)
            };
            format!(
                "{} {}  {data}",
                style.dim(&format!("[{}]", index + 1)),
                sanitize_line(&event.name)
            )
        })
        .collect();
    out.extend(cut(listed, options));
    if let Some(assembled) = assembled_text(&events) {
        out.push(String::new());
        out.push(style.bold("assembled text:"));
        out.extend(cut(
            sanitize(&assembled).lines().map(String::from).collect(),
            options,
        ));
    }
    out
}

/// Whether `text` is one complete, valid JSON value.
pub fn is_json(text: &str) -> bool {
    !text.trim().is_empty() && serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok()
}

/// Two or more lines, each one valid JSON value (NDJSON / JSON Lines).
fn is_json_lines(text: &str) -> bool {
    let mut count = 0;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if !is_json(line) {
            return false;
        }
        count += 1;
    }
    count >= 2
}

/// Re-indents valid JSON with 2 spaces. Strings, numbers, key order and duplicate keys are
/// kept exactly as captured.
pub fn pretty_json(text: &str) -> String {
    reformat_json(text, true)
}

/// Valid JSON on one line, without insignificant whitespace; tokens kept exactly.
pub fn compact_json(text: &str) -> String {
    reformat_json(text, false)
}

fn reformat_json(text: &str, pretty: bool) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + bytes.len() / 4);
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let newline = |out: &mut Vec<u8>, depth: usize| {
        if pretty {
            out.push(b'\n');
            out.extend(std::iter::repeat_n(b' ', depth * 2));
        }
    };
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if in_string {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' => {}
            b'"' => {
                in_string = true;
                out.push(byte);
            }
            b'{' | b'[' => {
                out.push(byte);
                let close = if byte == b'{' { b'}' } else { b']' };
                let next = bytes[index..]
                    .iter()
                    .position(|b| !b.is_ascii_whitespace())
                    .map(|offset| index + offset);
                match next {
                    Some(position) if bytes[position] == close => {
                        out.push(close);
                        index = position + 1;
                    }
                    _ => {
                        depth += 1;
                        newline(&mut out, depth);
                    }
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                newline(&mut out, depth);
                out.push(byte);
            }
            b',' => {
                out.push(byte);
                newline(&mut out, depth);
            }
            b':' => {
                out.push(byte);
                if pretty {
                    out.push(b' ');
                }
            }
            _ => out.push(byte),
        }
    }
    String::from_utf8(out).unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(len: usize) -> BodyRecord {
        BodyRecord {
            size: len as u64,
            captured: len as u64,
            truncated: false,
            complete: true,
            file: Some("bodies/1.res".into()),
        }
    }

    fn options() -> RenderOptions<'static> {
        RenderOptions {
            full: false,
            style: Style::plain(),
            save_command: "tap show s 1 --body res",
        }
    }

    fn render(bytes: &[u8], headers: &[(&str, &str)]) -> String {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        render_body(bytes, &headers, &complete(bytes.len()), &options())
    }

    #[test]
    fn pretty_json_keeps_tokens_order_and_duplicates() {
        let text = r#" {"z":1.10,"a":[ ],"a":{"b":[1,2e5,"x, \"y\": {"]},"e":{}} "#;
        assert_eq!(
            pretty_json(text),
            "{\n  \"z\": 1.10,\n  \"a\": [],\n  \"a\": {\n    \"b\": [\n      1,\n      2e5,\n      \"x, \\\"y\\\": {\"\n    ]\n  },\n  \"e\": {}\n}"
        );
        assert_eq!(
            compact_json("{ \"a\" : [ 1 , \"b c\" ] }"),
            r#"{"a":[1,"b c"]}"#
        );
        assert!(is_json("[1]"));
        assert!(!is_json("{\"a\":"));
        assert!(!is_json(" "));
    }

    #[test]
    fn json_by_content_type_or_shape() {
        assert_eq!(
            render(br#"{"a":1}"#, &[("content-type", "text/plain")]),
            "{\n  \"a\": 1\n}"
        );
        assert_eq!(
            render(b"not json", &[("content-type", "application/json")]),
            "(content-type says JSON, but this is not valid JSON)\nnot json"
        );
        assert_eq!(
            render(
                b"{ \"a\": 1 }\n\n[2]\n",
                &[("content-type", "application/x-ndjson")]
            ),
            "{\"a\":1}\n[2]"
        );
        assert_eq!(render(b"hello\nworld", &[]), "hello\nworld");
        assert_eq!(render(b"a\x1b[2Jb", &[]), "a\\x1b[2Jb");
    }

    #[test]
    fn hexdump_matches_hexdump_c() {
        let lines = hexdump(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRab");
        assert_eq!(
            lines,
            [
                "00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|",
                "00000010  61 62                                             |ab|",
            ]
        );
    }

    #[test]
    fn parses_sse_fields() {
        let events =
            parse_sse("event: a\ndata: 1\ndata:2\n\n: comment\nid: 3\ndata: x\r\n\r\ndata: tail");
        assert_eq!(
            events,
            [
                SseEvent {
                    name: "a".into(),
                    data: "1\n2".into()
                },
                SseEvent {
                    name: "message".into(),
                    data: "x".into()
                },
                SseEvent {
                    name: "message".into(),
                    data: "tail".into()
                },
            ]
        );
        assert!(looks_like_sse("data: {}\n\ndata: [DONE]\n\n"));
        assert!(!looks_like_sse("data: x\nsomething else\n"));
        assert!(!looks_like_sse("hello"));
    }

    #[test]
    fn deflate_accepts_zlib_and_raw() {
        use std::io::Write;
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"zlib text").unwrap();
        let zlib = zlib.finish().unwrap();
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw text").unwrap();
        let raw = raw.finish().unwrap();
        let zlib_out = render(&zlib, &[("content-encoding", "deflate")]);
        assert!(zlib_out.ends_with("\nzlib text"), "{zlib_out}");
        assert!(zlib_out.starts_with("(deflate: "));
        assert!(render(&raw, &[("content-encoding", "deflate")]).ends_with("\nraw text"));
    }

    #[test]
    fn truncated_and_stacked_encodings() {
        use std::io::Write;
        let text: String = (0..400).map(|n| format!("{{\"n\":{n}}}\n")).collect();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(text.as_bytes()).unwrap();
        let gzip = gzip.finish().unwrap();
        let half = &gzip[..gzip.len() / 2];
        let record = BodyRecord {
            size: gzip.len() as u64,
            captured: half.len() as u64,
            truncated: true,
            complete: true,
            file: Some("bodies/1.res".into()),
        };
        let headers = [
            ("content-encoding".to_string(), "gzip".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let out = render_body(half, &headers, &record, &options());
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("(truncated: captured "), "{out}");
        assert!(lines[1].starts_with("(gzip: decoded "), "{out}");
        assert!(lines[1].contains(" before an error: "), "{out}");
        assert_eq!(lines[2], "{\"n\":0}");
        assert!(!out.contains("not valid JSON"));

        let mut brotli = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut brotli, 4096, 9, 22);
            writer.write_all(br#"{"stacked":true}"#).unwrap();
        }
        let mut both = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        both.write_all(&brotli).unwrap();
        let both = both.finish().unwrap();
        let out = render(&both, &[("content-encoding", "br, gzip")]);
        assert!(out.starts_with("(br, gzip: "), "{out}");
        assert!(out.ends_with("→ 16 B)\n{\n  \"stacked\": true\n}"), "{out}");
    }

    #[test]
    fn long_lines_are_cut_once_even_in_event_streams() {
        let long = "x".repeat(MAX_LINE_CHARS + 5);
        let out = render(format!("data: {long}\n\n").as_bytes(), &[]);
        let event = out.lines().nth(1).unwrap();
        assert!(event.starts_with("[1] message  xxx"), "{event}");
        assert!(
            event.ends_with("x … 18 more characters (use --full)"),
            "{event}"
        );
        assert_eq!(
            render(long.as_bytes(), &[]),
            format!(
                "{} … 5 more characters (use --full)",
                "x".repeat(MAX_LINE_CHARS)
            )
        );
    }

    #[test]
    fn undecodable_encodings_fall_back_to_raw() {
        let out = render(b"plain", &[("content-encoding", "gzip")]);
        assert!(out.starts_with("(gzip decoding failed: "), "{out}");
        assert!(out.ends_with("; showing the raw bytes)\nplain"), "{out}");
        assert_eq!(
            render(b"zz", &[("content-encoding", "zstd")]),
            "(content-encoding zstd is not decoded for display; showing the raw bytes)\nzz"
        );
    }

    #[test]
    fn long_output_is_cut_unless_full() {
        let text: String = (1..=250).map(|n| format!("line {n}\n")).collect();
        let out = render(text.as_bytes(), &[]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 201);
        assert_eq!(lines[199], "line 200");
        assert_eq!(lines[200], "… 50 more lines (use --full)");
        let full = RenderOptions {
            full: true,
            ..options()
        };
        let out = render_body(text.as_bytes(), &[], &complete(text.len()), &full);
        assert_eq!(out.lines().count(), 250);
    }

    #[test]
    fn empty_and_uncaptured_bodies() {
        assert_eq!(
            render_body(b"", &[], &BodyRecord::default(), &options()),
            "(no body)"
        );
        let skipped = BodyRecord {
            size: 2048,
            truncated: true,
            complete: true,
            ..Default::default()
        };
        assert_eq!(
            render_body(b"", &[], &skipped, &options()),
            "(2.0 KB body, not captured: over the session's max_body limit)"
        );
    }
}

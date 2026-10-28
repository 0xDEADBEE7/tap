//! One exchange in full (`tap show S N`), its raw bodies (`--body`) and a replay command (`--curl`).

use super::args::Side;
use super::render::{render_body, RenderOptions};
use super::term::{duration, sanitize, sanitize_line, size, LocalTime, Style};
use crate::capture::read;
use crate::record::{BodyRecord, Exchange, Headers, Mode};
use std::io::{self, Write};
use std::path::Path;

pub struct DetailOptions<'a> {
    /// What the user calls the session in commands (`tap show <session> N ...`).
    pub session: &'a str,
    pub full: bool,
    pub style: Style,
}

/// Title, meta line, error/notes, then the Request, Response and Tunnel sections.
pub fn detail(session_dir: &Path, exchange: &Exchange, options: &DetailOptions) -> String {
    let style = options.style;
    let request = &exchange.request;
    let tunnel = exchange.mode == Mode::Tunnel || exchange.tunnel.is_some();
    let method = if request.method.is_empty() && tunnel {
        "CONNECT"
    } else {
        &request.method
    };
    let mut out = vec![style.bold(&format!(
        "#{}  {} {}",
        exchange.seq,
        sanitize_line(method),
        sanitize_line(&request.url)
    ))];

    let mut meta = vec![exchange.mode.as_str().to_string(), {
        let local = LocalTime::from_unix_ms(exchange.started_unix_ms);
        format!("{} {}", local.date(), local.time())
    }];
    if let Some(ttfb) = exchange.ttfb_ms {
        meta.push(format!("ttfb {}", duration(ttfb)));
    }
    if let Some(total) = exchange.duration_ms {
        meta.push(format!("total {}", duration(total)));
    }
    if !exchange.client_addr.is_empty() {
        meta.push(format!("client {}", sanitize_line(&exchange.client_addr)));
    }
    out.push(meta.join(" · "));
    if let Some(error) = &exchange.error {
        out.push(style.red(&format!("error: {}", sanitize(error.trim_end()))));
    }
    for note in &exchange.notes {
        out.push(format!("note: {}", sanitize(note.trim_end())));
    }

    let save = |side: &str| {
        format!(
            "tap show {} {} --body {side}",
            options.session, exchange.seq
        )
    };
    let (save_request, save_response) = (save("req"), save("res"));
    let request_options = RenderOptions {
        full: options.full,
        style,
        save_command: &save_request,
    };
    let response_options = RenderOptions {
        save_command: &save_response,
        ..request_options
    };

    out.push(String::new());
    out.push(style.bold("Request"));
    let target = if request.path.is_empty() {
        &request.url
    } else {
        &request.path
    };
    out.push(format!(
        "{} {} {}",
        sanitize_line(method),
        sanitize_line(target),
        sanitize_line(&request.version)
    ));
    out.extend(header_lines(&request.headers, style));
    if !tunnel || request.body.size > 0 {
        out.push(String::new());
        out.push(body_text(
            session_dir,
            &request.body,
            &request.headers,
            &request_options,
        ));
    }

    match &exchange.response {
        Some(response) => {
            out.push(String::new());
            out.push(style.bold("Response"));
            let status_line = format!("{} {}", response.status, sanitize_line(&response.reason));
            out.push(format!(
                "{} {}",
                sanitize_line(&response.version),
                style.status(Some(response.status), false, status_line.trim_end())
            ));
            out.extend(header_lines(&response.headers, style));
            if !tunnel || response.body.size > 0 {
                out.push(String::new());
                out.push(body_text(
                    session_dir,
                    &response.body,
                    &response.headers,
                    &response_options,
                ));
            }
        }
        None if !tunnel => {
            out.push(String::new());
            out.push(style.bold("Response"));
            out.push(style.dim(if exchange.error.is_some() {
                "(no response: the exchange failed, see error above)"
            } else {
                "(no response recorded)"
            }));
        }
        None => {}
    }

    if let Some(stats) = &exchange.tunnel {
        out.push(String::new());
        out.push(style.bold("Tunnel"));
        out.push(format!(
            "↑ {}  client → upstream ({} bytes)",
            size(stats.bytes_up, " "),
            stats.bytes_up
        ));
        out.push(format!(
            "↓ {}  upstream → client ({} bytes)",
            size(stats.bytes_down, " "),
            stats.bytes_down
        ));
        out.push(style.dim(if exchange.mode == Mode::Tunnel {
            "(opaque: relayed without decrypting: the host is in the session's tunnel list, interception is off, or the client spoke neither TLS nor HTTP)"
        } else {
            "(the connection was upgraded; the bytes relayed after the upgrade are counted, not recorded)"
        }));
    } else if !tunnel && !method.eq_ignore_ascii_case("CONNECT") {
        out.push(String::new());
        out.push(style.dim(&format!(
            "raw bodies: tap show {0} {1} --body req|res · replay: tap show {0} {1} --curl",
            options.session, exchange.seq
        )));
    }
    out.join("\n")
}

/// `name: value` with values aligned; names dimmed.
fn header_lines(headers: &Headers, style: Style) -> Vec<String> {
    let width = headers
        .iter()
        .map(|(name, _)| sanitize_line(name).chars().count() + 1)
        .max()
        .unwrap_or(0);
    headers
        .iter()
        .map(|(name, value)| {
            let label = format!("{}:", sanitize_line(name));
            let fill = " ".repeat(width - label.chars().count());
            format!("{}{fill} {}", style.dim(&label), sanitize_line(value))
        })
        .collect()
}

fn body_text(
    session_dir: &Path,
    body: &BodyRecord,
    headers: &Headers,
    options: &RenderOptions,
) -> String {
    match read::body(session_dir, body) {
        Ok(bytes) => render_body(bytes.as_deref().unwrap_or(&[]), headers, body, options),
        Err(error) => options.style.dim(&format!(
            "({} body: could not read {}: {error})",
            size(body.size, " "),
            body.file.as_deref().unwrap_or("?")
        )),
    }
}

/// Writes the captured bytes of one body exactly as stored. Returns a note for stderr when
/// what was written is not the whole body. With `refuse_binary` (stdout is a terminal),
/// bytes that are not text are not written; the error says how to save them instead.
pub fn write_raw_body(
    session_dir: &Path,
    session: &str,
    exchange: &Exchange,
    side: Side,
    refuse_binary: bool,
    out: &mut dyn Write,
) -> io::Result<Option<String>> {
    let (name, short, record) = match side {
        Side::Request => ("request", "req", Some(&exchange.request.body)),
        Side::Response => (
            "response",
            "res",
            exchange.response.as_ref().map(|r| &r.body),
        ),
    };
    let Some(record) = record else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("exchange #{} has no response", exchange.seq),
        ));
    };
    let read = read::body(session_dir, record).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not read the {name} body of exchange #{} ({}): {error}",
                exchange.seq,
                record.file.as_deref().unwrap_or("?")
            ),
        )
    })?;
    let Some(bytes) = read else {
        let message = if record.size == 0 {
            format!("exchange #{} has an empty {name} body", exchange.seq)
        } else {
            format!(
                "the {name} body of exchange #{} ({}) was not captured",
                exchange.seq,
                size(record.size, " ")
            )
        };
        return Err(io::Error::new(io::ErrorKind::NotFound, message));
    };
    let printable = std::str::from_utf8(&bytes).is_ok_and(|text| !text.contains('\0'));
    if refuse_binary && !printable {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the {name} body of exchange #{} is binary ({}); not writing it to the terminal. \
                 Save it: tap show {session} {} --body {short} > file",
                exchange.seq,
                size(bytes.len() as u64, " "),
                exchange.seq
            ),
        ));
    }
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(if record.truncated {
        Some(format!(
            "tap: note: wrote the captured {} of a {} {name} body (truncated by max_body)",
            size(record.captured, " "),
            size(record.size, " ")
        ))
    } else if !record.complete {
        Some(format!(
            "tap: note: the {name} body is incomplete (the stream was aborted)"
        ))
    } else {
        None
    })
}

const NOT_REPLAYED: [&str; 12] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
];

/// A copy-pasteable curl command that sends the same request again.
pub fn curl(session_dir: &Path, exchange: &Exchange) -> Result<String, String> {
    let request = &exchange.request;
    if exchange.mode == Mode::Tunnel {
        return Err(format!(
            "exchange #{} is an opaque tunnel; there is no decrypted request to replay",
            exchange.seq
        ));
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return Err(format!(
            "exchange #{} is a CONNECT with no request recorded inside it; there is nothing to replay",
            exchange.seq
        ));
    }
    if exchange.tunnel.is_some() {
        return Err(format!(
            "exchange #{} upgraded the connection (e.g. to a WebSocket); curl cannot replay that",
            exchange.seq
        ));
    }
    let body = &request.body;
    let mut comments = Vec::new();
    let mut exports: Vec<String> = Vec::new();
    let mut parts = Vec::new();

    let has_body = body.file.is_some();
    match request.method.as_str() {
        "HEAD" => parts.push("--head".to_string()),
        "GET" if !has_body => {}
        "POST" if has_body => {}
        method => parts.push(format!("-X {}", shell_quote(method))),
    }
    let mut compressed = false;
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with(':') || NOT_REPLAYED.contains(&lower.as_str()) {
            continue;
        }
        if lower == "accept-encoding" {
            let value = value.to_ascii_lowercase();
            compressed |= ["gzip", "deflate", "br"].iter().any(|c| value.contains(c));
        }
        if value.starts_with("[REDACTED") {
            let mut variable = env_name(name);
            let mut n = 2;
            while exports.contains(&variable) {
                variable = format!("{}_{n}", env_name(name));
                n += 1;
            }
            parts.push(format!("-H \"{}: ${variable}\"", double_quote_escape(name)));
            exports.push(variable);
        } else {
            parts.push(format!("-H {}", shell_quote(&format!("{name}: {value}"))));
        }
    }
    if compressed {
        parts.push("--compressed".to_string());
    }
    if let Some(file) = &body.file {
        let path =
            std::path::absolute(session_dir.join(file)).unwrap_or_else(|_| session_dir.join(file));
        parts.push(format!(
            "--data-binary {}",
            shell_quote(&format!("@{}", path.display()))
        ));
        if body.truncated {
            comments.push(format!(
                "# warning: only {} of the {} request body was captured; this sends the captured part",
                size(body.captured, " "),
                size(body.size, " ")
            ));
        } else if !body.complete {
            comments.push(
                "# warning: the client aborted the request body; this sends the part that arrived"
                    .to_string(),
            );
        }
    } else if body.size > 0 {
        comments.push(format!(
            "# warning: the {} request body was not captured; this sends no body",
            size(body.size, " ")
        ));
    }
    if !exports.is_empty() {
        comments.push(
            "# These header values were redacted when recorded. Export the real values first:"
                .to_string(),
        );
        for variable in &exports {
            comments.push(format!("#   export {variable}='<the full header value>'"));
        }
    }

    let mut command = format!("curl {}", shell_quote(&request.url));
    for part in parts {
        command.push_str(" \\\n  ");
        command.push_str(&part);
    }
    comments.push(command);
    Ok(comments.join("\n"))
}

/// `x-api-key` -> `X_API_KEY`.
fn env_name(header: &str) -> String {
    let mut name: String = header
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

fn double_quote_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '"' | '\\' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Single-quotes for POSIX shells unless every character is obviously safe.
pub(super) fn shell_quote(text: &str) -> String {
    let safe = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c));
    if safe {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_for_the_shell() {
        assert_eq!(shell_quote("@/tmp/x/bodies/1.req"), "@/tmp/x/bodies/1.req");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(env_name("x-api-key"), "X_API_KEY");
        assert_eq!(env_name("1x"), "_1X");
        assert_eq!(double_quote_escape("a$`\"b"), "a\\$\\`\\\"b");
    }
}

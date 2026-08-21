use super::upstream;
use crate::cli::Config;
use crate::http::{encode, parse};
use crate::intercept::{FilterSet, HookRunner, HookSpec};
use crate::output;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::TcpStream;

pub fn handle(mut client: TcpStream, config: &Config) -> io::Result<()> {
    let mut request = crate::http::read(&mut client)?;
    let log_path = config
        .session_id
        .as_ref()
        .map(|id| session_log_path(id));
    let hooks = HookRunner::with_log(config.on_request.clone().into_iter().map(HookSpec::into_hook).collect(), log_path.clone());
    hooks.request(&mut request);
    let filters = FilterSet::from_specs(&config.filters)?;
    if !filters.allows_request(
        &request.method,
        &request.scheme,
        &request.host,
        request.port,
        &request.path,
        &request.headers,
    ) {
        return reject(&mut client);
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        let server = match upstream::connect(&request.host, request.port) {
            Ok(server) => server,
            Err(error) => return upstream_failure(&mut client, error),
        };
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        upstream::tunnel(client, server)?;
        return Ok(());
    }
    if request.scheme != "http" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported request scheme",
        ));
    }
    let mut server = upstream::connect(&request.host, request.port)?;
    let mut wire = format!("{} {} HTTP/1.1\r\n", request.method, request.path).into_bytes();
    for (key, value) in &request.headers {
        wire.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    wire.extend_from_slice(b"Connection: close\r\n\r\n");
    wire.extend_from_slice(&request.body);
    server.write_all(&wire)?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = server.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let response_hooks = HookRunner::with_log(config.on_response.clone().into_iter().map(HookSpec::into_hook).collect(), log_path.clone());
    let response = parse(&bytes)?;
    let mut response = response;
    response_hooks.response(&mut response, "request-id");
    let response_wire = encode(&response);
    client.write_all(&response_wire)?;
    let event_hooks = HookRunner::with_log(config.on_event.clone().into_iter().map(HookSpec::into_hook).collect(), log_path);
    if filters.allows_event(&request.method, &request.host, &request.path, response.status) {
        let mut event = json!({
            "type": "response",
            "id": "request-id",
            "session_id": config.session_id,
            "method": request.method,
            "host": request.host,
            "path": request.path,
            "status": response.status
        });
        event_hooks.event(&mut event);
        persist_event(config, &event)?;
    }
    if config.json {
        output::json_response(
            &request.method,
            &request.host,
            &request.path,
            response.status,
        );
    } else {
        output::human_response(
            &request.method,
            &request.host,
            &request.path,
            response.status,
        );
    }
    Ok(())
}

fn session_log_path(id: &str) -> std::path::PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("tap/sessions")
        .join(id)
        .join("tap.log")
}

fn persist_event(config: &Config, event: &Value) -> io::Result<()> {
    let Some(path) = &config.events_path else {
        return Ok(());
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, event).map_err(|error| io::Error::other(error.to_string()))?;
    file.write_all(b"\n")
}

fn upstream_failure(stream: &mut TcpStream, error: io::Error) -> io::Result<()> {
    let body = format!("upstream connection failed: {error}\n");
    write!(
        stream,
        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

fn reject(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
}

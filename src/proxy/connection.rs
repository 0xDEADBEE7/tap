use super::upstream;
use crate::cli::Config;
use crate::http::{encode, parse};
use crate::intercept::{FilterSet, HookRunner, HookSpec};
use crate::output;
use std::io::{self, Read, Write};
use std::net::TcpStream;

pub fn handle(mut client: TcpStream, config: &Config) -> io::Result<()> {
    let mut request = crate::http::read(&mut client)?;
    let hooks = HookRunner::new(config.on_request.clone().into_iter().map(HookSpec::into_hook).collect());
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
    let response_hooks = HookRunner::new(config.on_response.clone().into_iter().map(HookSpec::into_hook).collect());
    let response = parse(&bytes)?;
    let mut response = response;
    response_hooks.response(&mut response, "request-id");
    let response_wire = encode(&response);
    client.write_all(&response_wire)?;
    if filters.allows_response(response.status) {
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
    }
    Ok(())
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

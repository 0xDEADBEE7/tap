use std::io;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn parse(bytes: &[u8]) -> io::Result<Response> {
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| invalid("incomplete response headers"))?;
    let text = std::str::from_utf8(&bytes[..end])
        .map_err(|_| invalid("response headers are not UTF-8"))?;
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("invalid response status"))?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().into(), value.trim().into()))
        .collect();
    Ok(Response { status, headers, body: bytes[end + 4..].to_vec() })
}

pub fn encode(response: &Response) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 {}\r\n", response.status).into_bytes();
    for (key, value) in &response.headers {
        wire.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    wire.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", response.body.len()).as_bytes());
    wire.extend_from_slice(&response.body);
    wire
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

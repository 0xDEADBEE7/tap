use std::io;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn read(stream: &mut impl io::Read) -> io::Result<Request> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let end;
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete request",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            end = index + 4;
            break;
        }
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
    let text = String::from_utf8(bytes[..end - 4].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "headers are not UTF-8"))?;
    let mut lines = text.lines();
    let start = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty request"))?;
    let mut fields = start.split_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let target = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target"))?;
    let (scheme, authority, path) = if method.eq_ignore_ascii_case("CONNECT") {
        ("https", target, target.to_string())
    } else {
        let uri = target.strip_prefix("http://").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "expected absolute HTTP URI")
        })?;
        let (authority, suffix) = uri.split_once('/').unwrap_or((uri, ""));
        (
            "http",
            authority,
            if suffix.is_empty() {
                "/".to_string()
            } else {
                format!("/{suffix}")
            },
        )
    };
    let (host, port) = authority
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse().ok().map(|port| (host, port)))
        .unwrap_or((authority, if scheme == "https" { 443 } else { 80 }));
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    let length = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    while bytes.len() - end < length {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete body",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(Request {
        method,
        scheme: scheme.into(),
        host: host.into(),
        port,
        path,
        headers,
        body: bytes[end..end + length].to_vec(),
    })
}

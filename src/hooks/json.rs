//! The JSON objects hooks read on stdin, and how their output is applied.

use super::{HookContext, HookMessage, Phase};
use crate::record::{Event, Exchange, Headers};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http::uri::PathAndQuery;
use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};
use serde_json::{Map, Value};

pub type Object = Map<String, Value>;

const REQUEST_READ_ONLY: &[&str] = &["type", "session_id", "seq", "url", "scheme", "host", "port"];
const RESPONSE_READ_ONLY: &[&str] = &["type", "session_id", "seq", "request"];
const HEADERS_SHAPE: &str =
    r#"printed invalid headers (expected [["name", "value"], ...] or {"name": "value"})"#;

/// What a sync hook's output turned into: the new value, the fields it changed, and
/// read-only fields whose changes were ignored.
pub struct Applied<T> {
    pub value: T,
    pub changed: Vec<String>,
    pub ignored: Vec<String>,
}

pub fn encode(object: &Object) -> Vec<u8> {
    serde_json::to_vec(object).unwrap_or_default()
}

/// Parses a sync hook's stdout. Blank output means "no change".
pub fn decode(stdout: &[u8]) -> Result<Option<Value>, String> {
    if stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    serde_json::from_slice(stdout)
        .map(Some)
        .map_err(|error| format!("printed invalid JSON ({error})"))
}

pub fn message_input(phase: Phase, context: &HookContext, message: &HookMessage) -> Object {
    match phase {
        Phase::Request => request_input(context, message),
        Phase::Response | Phase::Event => response_input(context, message),
    }
}

fn request_input(context: &HookContext, message: &HookMessage) -> Object {
    let target = Target::parse(&context.url);
    let path = message.path.clone().unwrap_or_else(|| target.path.clone());
    let url = if path == target.path {
        context.url.clone()
    } else {
        target
            .with_path(&path)
            .unwrap_or_else(|| context.url.clone())
    };
    let mut object = Object::new();
    object.insert("type".into(), "request".into());
    object.insert("session_id".into(), context.session_id.clone().into());
    object.insert("seq".into(), context.seq.into());
    object.insert(
        "method".into(),
        message
            .method
            .clone()
            .unwrap_or_else(|| context.method.clone())
            .into(),
    );
    object.insert("url".into(), url.into());
    object.insert("scheme".into(), target.scheme.into());
    object.insert("host".into(), target.host.into());
    object.insert("port".into(), target.port.into());
    object.insert("path".into(), path.into());
    object.insert("headers".into(), headers_value(&message.headers));
    insert_body(&mut object, &message.body);
    object
}

fn response_input(context: &HookContext, message: &HookMessage) -> Object {
    let mut request = Object::new();
    request.insert("method".into(), context.method.clone().into());
    request.insert("url".into(), context.url.clone().into());
    let mut object = Object::new();
    object.insert("type".into(), "response".into());
    object.insert("session_id".into(), context.session_id.clone().into());
    object.insert("seq".into(), context.seq.into());
    object.insert("request".into(), Value::Object(request));
    object.insert("status".into(), message.status.into());
    object.insert("headers".into(), headers_value(&message.headers));
    insert_body(&mut object, &message.body);
    object
}

fn headers_value(headers: &Headers) -> Value {
    headers
        .iter()
        .map(|(name, value)| Value::Array(vec![name.clone().into(), value.clone().into()]))
        .collect()
}

fn insert_body(object: &mut Object, body: &Bytes) {
    match std::str::from_utf8(body) {
        Ok(text) => {
            object.insert("body".into(), text.into());
        }
        Err(_) => {
            object.insert("body".into(), Value::Null);
            object.insert("body_base64".into(), STANDARD.encode(body).into());
        }
    }
}

/// Applies a sync request/response hook's output to `message`. `input` is what the
/// hook was given. Any invalid field rejects the whole output.
pub fn apply_message(
    phase: Phase,
    input: &Object,
    message: &HookMessage,
    output: Value,
) -> Result<Applied<HookMessage>, String> {
    let Value::Object(mut output) = output else {
        return Err("printed JSON that is not an object".into());
    };
    let read_only = match phase {
        Phase::Request => REQUEST_READ_ONLY,
        Phase::Response | Phase::Event => RESPONSE_READ_ONLY,
    };
    let ignored = read_only
        .iter()
        .filter(|key| {
            output
                .get(**key)
                .is_some_and(|value| input.get(**key) != Some(value))
        })
        .map(|key| key.to_string())
        .collect();
    let mut next = message.clone();
    let mut changed = Vec::new();
    if phase == Phase::Request {
        // Only values the hook changed are checked, so echoing the input back always works.
        if let Some(method) = take_changed(&mut output, input, "method")? {
            if Method::from_bytes(method.as_bytes()).is_err() {
                return Err(format!(
                    "printed an invalid method `{}`",
                    method.escape_debug()
                ));
            }
            changed.push("method".into());
            next.method = Some(method);
        }
        if let Some(path) = take_changed(&mut output, input, "path")? {
            // A #fragment is never sent, so upstream would get a different path than printed.
            if !path.starts_with('/') || path.contains('#') || path.parse::<PathAndQuery>().is_err()
            {
                return Err(format!(
                    "printed an invalid path `{}` (it must start with /, be URL-encoded and have no #fragment)",
                    path.escape_debug()
                ));
            }
            changed.push("path".into());
            next.path = Some(path);
        }
    } else {
        match output.remove("status") {
            None | Some(Value::Null) => {}
            Some(value) => {
                let status = value
                    .as_u64()
                    .and_then(|number| u16::try_from(number).ok())
                    .filter(|number| StatusCode::from_u16(*number).is_ok())
                    .ok_or_else(|| {
                        format!("printed an invalid status `{value}` (expected 100-999)")
                    })?;
                if message.status != Some(status) {
                    changed.push("status".into());
                    next.status = Some(status);
                }
            }
        }
    }
    if let Some(headers) = take_headers(&mut output)? {
        if headers != message.headers {
            changed.push("headers".into());
            next.headers = headers;
        }
    }
    if let Some(body) = take_body(&mut output)? {
        if body != message.body {
            changed.push("body".into());
            fix_content_length(&mut next.headers, body.len());
            next.body = body;
        }
    }
    Ok(Applied {
        value: next,
        changed,
        ignored,
    })
}

fn take_string(object: &mut Object, key: &str) -> Result<Option<String>, String> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(format!("printed a `{key}` that is not a string")),
    }
}

/// The string at `key` when it differs from the hook's input.
fn take_changed(object: &mut Object, input: &Object, key: &str) -> Result<Option<String>, String> {
    let value = take_string(object, key)?;
    Ok(value.filter(|value| input.get(key).and_then(Value::as_str) != Some(value.as_str())))
}

fn take_headers(object: &mut Object) -> Result<Option<Headers>, String> {
    let pairs: Vec<(String, String)> = match object.remove("headers") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| match item {
                Value::Array(pair) => match <[Value; 2]>::try_from(pair) {
                    Ok([Value::String(name), Value::String(value)]) => Ok((name, value)),
                    _ => Err(HEADERS_SHAPE.to_string()),
                },
                _ => Err(HEADERS_SHAPE.to_string()),
            })
            .collect::<Result<_, _>>()?,
        Some(Value::Object(map)) => map
            .into_iter()
            .map(|(name, value)| match value {
                Value::String(value) => Ok((name, value)),
                _ => Err(HEADERS_SHAPE.to_string()),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(HEADERS_SHAPE.into()),
    };
    pairs
        .into_iter()
        .map(|(name, value)| checked_header(name, value))
        .collect::<Result<_, _>>()
        .map(Some)
}

/// Header names are lowercased (as recorded); names and values must be valid on the wire.
fn checked_header(name: String, value: String) -> Result<(String, String), String> {
    let parsed = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("printed an invalid header name `{}`", name.escape_debug()))?;
    if HeaderValue::from_bytes(value.as_bytes()).is_err() {
        return Err(format!("printed an invalid value for header `{parsed}`"));
    }
    Ok((parsed.as_str().to_owned(), value))
}

/// `body_base64` (a string) wins over `body` (a string); neither means unchanged.
fn take_body(object: &mut Object) -> Result<Option<Bytes>, String> {
    match object.remove("body_base64") {
        None | Some(Value::Null) => {}
        Some(Value::String(text)) => {
            let decoded = if text.bytes().any(|byte| byte.is_ascii_whitespace()) {
                let compact: Vec<u8> = text
                    .bytes()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect();
                STANDARD.decode(compact)
            } else {
                STANDARD.decode(text)
            };
            return decoded
                .map(|bytes| Some(Bytes::from(bytes)))
                .map_err(|error| format!("printed invalid body_base64 ({error})"));
        }
        Some(_) => return Err("printed a `body_base64` that is not a string".into()),
    }
    Ok(take_string(object, "body")?.map(|text| Bytes::from(text.into_bytes())))
}

/// Keeps a `content-length` header (if any) true to a body a hook replaced.
fn fix_content_length(headers: &mut Headers, length: usize) {
    let mut seen = false;
    headers.retain_mut(|(name, value)| {
        if !name.eq_ignore_ascii_case("content-length") {
            return true;
        }
        if seen {
            return false;
        }
        seen = true;
        *value = length.to_string();
        true
    });
}

/// The exchange exactly as it is written to events.jsonl (with `"type":"exchange"`).
pub fn event_input(exchange: &Exchange) -> Object {
    match serde_json::to_value(Event::Exchange(exchange.clone())) {
        Ok(Value::Object(object)) => object,
        _ => Object::new(),
    }
}

/// Applies a sync `on_event` hook's output: top-level fields it printed replace the
/// original's (so a partial object is fine). `seq` and `session_id` must not change.
pub fn apply_event(
    original: &Exchange,
    input: &Object,
    output: Value,
) -> Result<Applied<Exchange>, String> {
    let Value::Object(output) = output else {
        return Err("printed JSON that is not an object".into());
    };
    let mut merged = input.clone();
    for (key, value) in output {
        if key == "type" {
            if value.as_str() != Some("exchange") {
                return Err(format!("printed an event of type {value}, not an exchange"));
            }
            continue;
        }
        merged.insert(key, value);
    }
    merged.remove("type");
    let exchange: Exchange = serde_json::from_value(Value::Object(merged))
        .map_err(|error| format!("printed an invalid exchange ({error})"))?;
    if exchange.seq != original.seq {
        return Err(format!(
            "tried to change seq from {} to {}, which must stay the same",
            original.seq, exchange.seq
        ));
    }
    if exchange.session_id != original.session_id {
        return Err(format!(
            "tried to change session_id to `{}`, which must stay the same",
            exchange.session_id.escape_debug()
        ));
    }
    let updated = event_input(&exchange);
    let mut changed: Vec<String> = updated
        .iter()
        .filter(|(key, value)| input.get(*key) != Some(*value))
        .map(|(key, _)| key.clone())
        .collect();
    changed.extend(
        input
            .keys()
            .filter(|key| !updated.contains_key(*key))
            .cloned(),
    );
    Ok(Applied {
        value: exchange,
        changed,
        ignored: Vec::new(),
    })
}

/// The read-only parts of a request URL, and its path for when a hook changes it.
#[derive(Default)]
struct Target {
    scheme: String,
    authority: String,
    host: String,
    port: u16,
    path: String,
}

impl Target {
    fn parse(url: &str) -> Target {
        let Ok(uri) = url.parse::<Uri>() else {
            return Target::default();
        };
        let scheme = uri.scheme_str().unwrap_or_default().to_string();
        let default_port = match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => 0,
        };
        Target {
            authority: uri
                .authority()
                .map(|authority| authority.as_str().to_string())
                .unwrap_or_default(),
            host: uri
                .host()
                .unwrap_or_default()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port: uri.port_u16().unwrap_or(default_port),
            path: uri
                .path_and_query()
                .map_or_else(|| uri.path().to_string(), |path| path.as_str().to_string()),
            scheme,
        }
    }

    fn with_path(&self, path: &str) -> Option<String> {
        (!self.scheme.is_empty() && !self.authority.is_empty())
            .then(|| format!("{}://{}{path}", self.scheme, self.authority))
    }
}

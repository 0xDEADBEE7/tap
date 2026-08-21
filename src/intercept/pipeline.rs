use crate::http::{Request, Response};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Clone, Copy)]
pub enum Phase {
    Request,
    Response,
    Event,
}

#[derive(Clone)]
pub struct Hook {
    pub mode: Mode,
    pub command: Vec<String>,
    pub timeout: Duration,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Sync,
    Async,
}

pub struct HookRunner {
    hooks: Vec<Hook>,
}

impl HookRunner {
    pub fn new(hooks: Vec<Hook>) -> Self {
        Self { hooks }
    }

    pub fn request(&self, request: &mut Request) {
        let mut value = request_value(request);
        self.transform(Phase::Request, &mut value);
        if let Some(updated) = request_from_value(value) {
            *request = updated;
        }
    }

    pub fn response(&self, response: &mut Response, request_id: &str) {
        let mut value = response_value(response, request_id);
        self.transform(Phase::Response, &mut value);
        if let Some(updated) = response_from_value(value) {
            *response = updated;
        }
    }

    pub fn event(&self, event: &mut Value) {
        self.transform(Phase::Event, event);
    }

    fn transform(&self, phase: Phase, value: &mut Value) {
        let mut sync = self.hooks.iter().filter(|hook| hook.mode == Mode::Sync);
        for hook in sync.by_ref() {
            if let Ok(output) = run(hook, value) {
                if valid_result(phase, value, &output) {
                    *value = output;
                }
            }
        }
        for hook in self.hooks.iter().filter(|hook| hook.mode == Mode::Async) {
            spawn_async(hook, value);
        }
    }
}

fn spawn_async(hook: &Hook, value: &Value) {
    let Some(program) = hook.command.first() else {
        return;
    };
    let Ok(mut child) = Command::new(program)
        .args(&hook.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn() else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(serde_json::to_string(value).unwrap_or_default().as_bytes());
    }
}

fn run(hook: &Hook, value: &Value) -> io::Result<Value> {
    let Some(program) = hook.command.first() else {
        return Err(invalid("hook command cannot be empty"));
    };
    let mut child = Command::new(program)
        .args(&hook.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(serde_json::to_string(value)?.as_bytes())?;
    }
    let output = wait_for_output(child, hook.timeout)?;
    if !output.status.success() {
        return Err(invalid("hook exited unsuccessfully"));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| invalid("hook stdout was not JSON"))
}

fn wait_for_output(mut child: std::process::Child, timeout: Duration) -> io::Result<std::process::Output> {
    let started = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("hook timed out"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn valid_result(phase: Phase, original: &Value, result: &Value) -> bool {
    if !result.is_object() || result.get("type") != original.get("type") {
        return false;
    }
    let immutable = match phase {
        Phase::Request => &["type", "method", "host", "port", "path"][..],
        Phase::Response => &["type", "request_id", "status"][..],
        Phase::Event => &["type", "id", "session_id"][..],
    };
    immutable.iter().all(|field| result.get(*field) == original.get(*field))
}

fn request_value(request: &Request) -> Value {
    json!({"type":"request", "method":request.method, "scheme":request.scheme,
        "host":request.host, "port":request.port, "path":request.path,
        "headers":request.headers, "body":String::from_utf8_lossy(&request.body)})
}

fn response_value(response: &Response, request_id: &str) -> Value {
    json!({"type":"response", "request_id":request_id, "status":response.status,
        "headers":response.headers, "body":String::from_utf8_lossy(&response.body)})
}

fn request_from_value(value: Value) -> Option<Request> {
    Some(Request {
        method: value.get("method")?.as_str()?.into(),
        scheme: value.get("scheme")?.as_str()?.into(),
        host: value.get("host")?.as_str()?.into(),
        port: value.get("port")?.as_u64()?.try_into().ok()?,
        path: value.get("path")?.as_str()?.into(),
        headers: pairs(value.get("headers")?)?,
        body: value.get("body")?.as_str()?.as_bytes().to_vec(),
    })
}

fn response_from_value(value: Value) -> Option<Response> {
    Some(Response {
        status: value.get("status")?.as_u64()?.try_into().ok()?,
        headers: pairs(value.get("headers")?)?,
        body: value.get("body")?.as_str()?.as_bytes().to_vec(),
    })
}

fn pairs(value: &Value) -> Option<Vec<(String, String)>> {
    value.as_array()?.iter().map(|pair| {
        let pair = pair.as_array()?;
        Some((pair.first()?.as_str()?.into(), pair.get(1)?.as_str()?.into()))
    }).collect()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

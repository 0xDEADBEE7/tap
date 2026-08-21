use crate::cli::Config;
use crate::intercept::HookSpec;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Clone, Serialize, Deserialize, Default)]
struct Metadata {
    id: String,
    status: String,
    port: String,
    #[serde(default)]
    filters: Vec<String>,
    #[serde(default)]
    hooks: HookConfig,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HookConfig {
    #[serde(default)]
    pub on_request: Vec<HookSpec>,
    #[serde(default)]
    pub on_response: Vec<HookSpec>,
    #[serde(default)]
    pub on_event: Vec<HookSpec>,
}

pub fn create(port: String) -> io::Result<()> {
    port.parse::<u16>()
        .map_err(|_| invalid("port must be a number"))?;
    let id = unique_id();
    let directory = session_dir(&id);
    fs::create_dir_all(&directory)?;
    fs::File::create(directory.join("tap.log"))?;
    fs::File::create(directory.join("events.jsonl"))?;
    write_metadata(&id, "stopped", &port)?;
    println!(r#"{{"id":"{id}"}}"#);
    Ok(())
}

pub fn start(id: String) -> io::Result<()> {
    let metadata = read_metadata(&id)?;
    if metadata.status == "running" {
        return Err(invalid("session is already running"));
    }
    let executable = std::env::current_exe()?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(session_dir(&id).join("tap.log"))?;
    Command::new(executable)
        .args(["__run", &id])
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    write_metadata(&id, "running", &metadata.port)?;
    println!(r#"{{"id":"{id}","status":"running"}}"#);
    Ok(())
}

pub fn run(id: String) -> io::Result<()> {
    let metadata = read_metadata(&id)?;
    let result = crate::proxy::listener::run(Config {
        listen: format!("127.0.0.1:{}", metadata.port),
        filters: metadata.filters,
        hooks: metadata.hooks.on_request.into_iter()
            .chain(metadata.hooks.on_response)
            .chain(metadata.hooks.on_event)
            .collect(),
        json: false,
    });
    let _ = write_metadata(&id, "stopped", &metadata.port);
    result
}

pub fn stop(id: String) -> io::Result<()> {
    let metadata = read_metadata(&id)?;
    if metadata.status == "stopped" {
        return Ok(());
    }
    let output = Command::new("ps")
        .args(["-ax", "-o", "pid=", "-o", "command="])
        .output()?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((pid, command)) = line.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        if command.contains("tap __run ") && command.ends_with(&id) {
            unsafe {
                libc_kill(pid.trim().parse().unwrap_or(0));
            }
            write_metadata(&id, "stopped", &metadata.port)?;
            println!(r#"{{"id":"{id}","status":"stopped"}}"#);
            return Ok(());
        }
    }
    write_metadata(&id, "stopped", &metadata.port)
}

pub fn list() -> io::Result<()> {
    let mut ids = Vec::new();
    if let Ok(entries) = fs::read_dir(sessions_dir()) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                ids.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    println!(
        r#"{{"sessions":[{}]}}"#,
        ids.iter()
            .map(|id| format!(r#""{id}""#))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(())
}

fn read_metadata(id: &str) -> io::Result<Metadata> {
    serde_json::from_str(&fs::read_to_string(session_dir(id).join("metadata.json"))?)
        .map_err(|error| invalid(&format!("invalid metadata: {error}")))
}

fn write_metadata(id: &str, status: &str, port: &str) -> io::Result<()> {
    let mut metadata = read_metadata(id).unwrap_or_else(|_| Metadata {
        id: id.into(), status: status.into(), port: port.into(), filters: Vec::new(), hooks: HookConfig::default(),
    });
    metadata.status = status.into();
    metadata.port = port.into();
    let text = serde_json::to_string_pretty(&metadata)
        .map_err(|error| invalid(&format!("cannot encode metadata: {error}")))?;
    fs::write(session_dir(id).join("metadata.json"), text)
}

fn sessions_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|| PathBuf::from("."))
        })
        .join("tap")
        .join("sessions")
}
fn session_dir(id: &str) -> PathBuf {
    sessions_dir().join(id)
}
fn unique_id() -> String {
    format!("{:016x}", std::process::id() as u64 ^ current_nanos())
}
fn current_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
unsafe fn libc_kill(pid: i32) -> i32 {
    extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    kill(pid, 15)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

use crate::cli::Config;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
        filters: Vec::new(),
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

struct Metadata {
    status: String,
    port: String,
}

fn read_metadata(id: &str) -> io::Result<Metadata> {
    let text = fs::read_to_string(session_dir(id).join("metadata.json"))?;
    let status = field(&text, "status").ok_or_else(|| invalid("invalid metadata"))?;
    let port = field(&text, "port").ok_or_else(|| invalid("invalid metadata"))?;
    Ok(Metadata { status, port })
}

fn write_metadata(id: &str, status: &str, port: &str) -> io::Result<()> {
    fs::write(
        session_dir(id).join("metadata.json"),
        format!(r#"{{"id":"{id}","status":"{status}","port":{port}}}"#),
    )
}

fn field(text: &str, name: &str) -> Option<String> {
    let marker = format!(r#""{name}":"#);
    let value = text.split_once(&marker)?.1;
    if let Some(value) = value.strip_prefix('"') {
        Some(value.split('"').next()?.to_string())
    } else {
        Some(value.split([',', '}']).next()?.trim().to_string())
    }
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

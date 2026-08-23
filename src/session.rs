use crate::cli::Config;
use crate::intercept::HookSpec;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Clone, Serialize, Deserialize, Default)]
struct Metadata {
    id: String,
    status: String,
    #[serde(default)]
    label: String,
    port: String,
    #[serde(default)]
    pid: Option<u32>,
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
    let id = unique_id()?;
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
        .truncate(true)
        .write(true)
        .open(session_dir(&id).join("tap.log"))?;
    let child = Command::new(executable)
        .args(["__run", &id])
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let mut metadata = metadata;
    metadata.status = "running".into();
    metadata.pid = Some(child.id());
    write_metadata_value(&id, &metadata)?;
    println!(r#"{{"id":"{id}","status":"running"}}"#);
    Ok(())
}

pub fn run(id: String) -> io::Result<()> {
    let metadata = read_metadata(&id)?;
    let result = crate::proxy::listener::run(Config {
        listen: format!("127.0.0.1:{}", metadata.port),
        filters: metadata.filters,
        on_request: metadata.hooks.on_request,
        on_response: metadata.hooks.on_response,
        on_event: metadata.hooks.on_event,
        session_id: Some(id.clone()),
        events_path: Some(session_dir(&id).join("events.jsonl")),
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
    let pid = metadata
        .pid
        .ok_or_else(|| invalid("running session has no process ID"))?;
    let status = unsafe { libc_kill(pid as i32) };
    if status != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    write_metadata(&id, "stopped", &metadata.port)?;
    println!(r#"{{"id":"{id}","status":"stopped"}}"#);
    Ok(())
}

pub fn list(table: bool) -> io::Result<()> {
    let mut sessions = Vec::new();
    if let Ok(entries) = fs::read_dir(sessions_dir()) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Ok(metadata) = read_metadata(&entry.file_name().to_string_lossy()) {
                    sessions.push(metadata);
                }
            }
        }
    }

    if table {
        print_table(&sessions);
    } else {
        let sessions = sessions
            .iter()
            .map(|metadata| {
                serde_json::json!({
                    "id": metadata.id,
                    "status": metadata.status,
                    "label": metadata.label,
                    "port": metadata.port,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::json!({"sessions": sessions}));
    }
    Ok(())
}

fn print_table(sessions: &[Metadata]) {
    const STATUS_WIDTH: usize = 6;
    const PORT_WIDTH: usize = 4;
    const ID_HEADER_WIDTH: usize = 2;
    const LABEL_HEADER_WIDTH: usize = 5;
    let status_width = sessions
        .iter()
        .map(|metadata| metadata.status.chars().count())
        .max()
        .unwrap_or(STATUS_WIDTH)
        .max(STATUS_WIDTH);
    let label_width = sessions
        .iter()
        .map(|metadata| metadata.label.chars().count())
        .max()
        .unwrap_or(LABEL_HEADER_WIDTH)
        .max(LABEL_HEADER_WIDTH);
    let port_width = sessions
        .iter()
        .map(|metadata| metadata.port.chars().count())
        .max()
        .unwrap_or(PORT_WIDTH)
        .max(PORT_WIDTH);
    let id_width = sessions
        .iter()
        .map(|metadata| metadata.id.chars().count())
        .max()
        .unwrap_or(ID_HEADER_WIDTH)
        .max(ID_HEADER_WIDTH);
    let widths = [status_width, label_width, port_width, id_width];
    let border = table_line('┌', '┬', '┐', '─', &widths);
    let divider = table_line('├', '┼', '┤', '─', &widths);
    let bottom = table_line('└', '┴', '┘', '─', &widths);

    println!("{border}");
    println!(
        "│ {:<status_width$} │ {:<label_width$} │ {:<port_width$} │ {:<id_width$} │",
        "STATUS", "LABEL", "PORT", "ID"
    );
    println!("{divider}");
    for metadata in sessions {
        println!(
            "│ {:<status_width$} │ {:<label_width$} │ {:<port_width$} │ {:<id_width$} │",
            metadata.status.to_uppercase(),
            metadata.label,
            metadata.port,
            metadata.id
        );
    }
    println!("{bottom}");
}

fn table_line(left: char, middle: char, right: char, fill: char, widths: &[usize; 4]) -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}",
        left,
        fill.to_string().repeat(widths[0] + 2),
        middle,
        fill.to_string().repeat(widths[1] + 2),
        middle,
        fill.to_string().repeat(widths[2] + 2),
        middle,
        fill.to_string().repeat(widths[3] + 2),
        right
    )
}

fn read_metadata(id: &str) -> io::Result<Metadata> {
    serde_json::from_str(&fs::read_to_string(session_dir(id).join("metadata.json"))?)
        .map_err(|error| invalid(&format!("invalid metadata: {error}")))
}

fn write_metadata(id: &str, status: &str, port: &str) -> io::Result<()> {
    let mut metadata = read_metadata(id).unwrap_or_else(|_| Metadata {
        id: id.into(),
        status: status.into(),
        label: String::new(),
        port: port.into(),
        pid: None,
        filters: Vec::new(),
        hooks: HookConfig::default(),
    });
    metadata.status = status.into();
    metadata.port = port.into();
    metadata.pid = if status == "running" {
        metadata.pid
    } else {
        None
    };
    write_metadata_value(id, &metadata)
}

fn write_metadata_value(id: &str, metadata: &Metadata) -> io::Result<()> {
    let text = serde_json::to_string_pretty(metadata)
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
fn unique_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
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

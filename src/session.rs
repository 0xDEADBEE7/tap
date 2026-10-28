//! Session lifecycle: create/start/stop/list/delete, the background `tap __run`
//! process, and routing `env`, `exec`, `show` and `tail` to a session.

use crate::capture::redact::default_redact;
use crate::capture::Store;
use crate::filter::FilterSet;
use crate::hooks::{self, HookConfig, Hooks};
use crate::paths::{self, session_dir, sessions_dir};
use crate::proxy::{self, Runtime};
use crate::record;
use crate::tls::{self, Ca};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub label: String,
    /// Stored as a string; a number is accepted when reading.
    #[serde(deserialize_with = "port_string")]
    pub port: String,
    #[serde(default)]
    pub pid: Option<u32>,
    /// Capture scope (see `filter`). Empty records everything.
    #[serde(default)]
    pub filters: Vec<String>,
    #[serde(default)]
    pub hooks: HookConfig,
    /// Base URL for origin-form requests (reverse / base-URL mode).
    #[serde(default)]
    pub upstream: Option<String>,
    /// Decrypt HTTPS inside CONNECT tunnels using the local TAP CA.
    #[serde(default = "default_true")]
    pub intercept: bool,
    /// Host regexes whose CONNECT tunnels are relayed without interception.
    #[serde(default)]
    pub tunnel: Vec<String>,
    /// Header names redacted in records.
    #[serde(default = "default_redact")]
    pub redact: Vec<String>,
    /// Per-body capture limit in bytes.
    #[serde(default = "default_max_body")]
    pub max_body: u64,
}

fn default_true() -> bool {
    true
}

fn default_max_body() -> u64 {
    16 * 1024 * 1024
}

fn port_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Port {
        Text(String),
        Number(u64),
    }
    Ok(match Port::deserialize(deserializer)? {
        Port::Text(text) => text,
        Port::Number(number) => number.to_string(),
    })
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            id: String::new(),
            status: "stopped".into(),
            label: String::new(),
            port: String::new(),
            pid: None,
            filters: Vec::new(),
            hooks: HookConfig::default(),
            upstream: None,
            intercept: true,
            tunnel: Vec::new(),
            redact: default_redact(),
            max_body: default_max_body(),
        }
    }
}

/// Arguments of `tap create`, as given on the command line.
#[derive(Clone, Debug, Default)]
pub struct CreateOptions {
    pub port: String,
    pub label: Option<String>,
    pub upstream: Option<String>,
    pub filters: Vec<String>,
    pub tunnel: Vec<String>,
    pub no_intercept: bool,
    /// None keeps the default (16 MiB).
    pub max_body: Option<u64>,
}

pub fn create(options: CreateOptions) -> io::Result<()> {
    let port = parse_port(&options.port)?;
    let entries = load_all()?;
    if let Some(other) = entries.iter().find(|entry| entry.port() == Some(port)) {
        return Err(invalid(format!(
            "port {port} is already assigned to session {}; choose another port or delete that session (tap delete {})",
            other.name(),
            other.selector()
        )));
    }
    let label = match options.label {
        Some(label) => {
            validate_label(&label)?;
            if let Some(other) = entries
                .iter()
                .find(|entry| entry.label() == Some(label.as_str()))
            {
                return Err(invalid(format!(
                    "label '{label}' is already used by session {}; choose another label",
                    other.id
                )));
            }
            label
        }
        None => String::new(),
    };
    if let Some(url) = &options.upstream {
        parse_upstream(url)?;
    }
    FilterSet::parse(&options.filters)
        .map_err(|error| invalid(format!("invalid --filter: {error}")))?;
    parse_tunnel(&options.tunnel)?;

    let mut id = unique_id()?;
    while session_dir(&id).exists() {
        id = unique_id()?;
    }
    let directory = session_dir(&id);
    paths::create_private_dir(&directory)?;
    paths::open_private_append(&directory.join("tap.log"))?;
    paths::open_private_append(&directory.join("events.jsonl"))?;
    let metadata = Metadata {
        id: id.clone(),
        label: label.clone(),
        port: port.to_string(),
        filters: options.filters,
        upstream: options.upstream,
        intercept: !options.no_intercept,
        tunnel: options.tunnel,
        max_body: options.max_body.unwrap_or_else(default_max_body),
        ..Metadata::default()
    };
    write_metadata(&id, &metadata)?;
    println!(
        "{}",
        json!({"id": id, "label": label, "port": port.to_string()})
    );
    Ok(())
}

pub fn start(selector: &str) -> io::Result<()> {
    let id = resolve(Some(selector))?;
    let log_path = session_dir(&id).join("tap.log");
    // Held until this start finishes: a concurrent start of the same session
    // waits, then finds it running instead of racing for the port.
    let _lock = lock_file(&log_path);
    let metadata = load_valid(&id)?;
    let name = display_name(&id, &metadata);
    if metadata.status == "running" {
        if let Some(pid) = metadata
            .pid
            .filter(|pid| inspect(&id, *pid) == Process::Ours)
        {
            return Err(invalid(format!(
                "session {name} is already running (pid {pid}, proxy http://127.0.0.1:{})",
                metadata.port
            )));
        }
        mark_stopped(&id, metadata.pid)?;
    }
    let metadata_path = session_dir(&id).join("metadata.json");
    let port = parse_port(&metadata.port).map_err(|error| {
        invalid(format!(
            "session {name}: {error} (edit {})",
            metadata_path.display()
        ))
    })?;
    prepare(&metadata).map_err(|error| {
        invalid(format!(
            "session {name} cannot start: {error} (edit {})",
            metadata_path.display()
        ))
    })?;
    if metadata.intercept {
        load_ca()?;
    }
    check_port_free(port)?;

    // The run process appends the `--- tap start` header itself (see `run`).
    let log = paths::open_private_append(&log_path)?;
    let run_starts_at = log.metadata()?.len();
    let mut command = Command::new(std::env::current_exe()?);
    // Hooks inherit this environment; a hook making HTTP calls must not loop back through TAP.
    for name in PROXY_VARS {
        command.env_remove(name);
    }
    let mut child = command
        .args(["__run", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .process_group(0)
        .spawn()?;
    let pid = child.id();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(current) = read_metadata(&id) {
            if current.status == "running" && current.pid == Some(pid) {
                break;
            }
        }
        if let Some(status) = child.try_wait()? {
            print_log_tail(&log_path, run_starts_at, 15);
            return Err(io::Error::other(format!(
                "session {name} failed to start ({status}); full log: {}",
                log_path.display()
            )));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = mark_stopped(&id, Some(pid));
            print_log_tail(&log_path, run_starts_at, 15);
            return Err(io::Error::other(format!(
                "session {name} did not become ready within 5s and was killed; full log: {}",
                log_path.display()
            )));
        }
        thread::sleep(Duration::from_millis(50));
    }

    println!(
        "{}",
        json!({
            "id": id,
            "status": "running",
            "port": port.to_string(),
            "proxy": format!("http://127.0.0.1:{port}"),
            "pid": pid,
        })
    );
    if io::stderr().is_terminal() {
        eprintln!(
            "route a command: tap exec {} -- <cmd>",
            selector_for(&id, &metadata)
        );
    }
    Ok(())
}

/// `tap __run ID`: the background proxy process. Reports readiness by writing
/// `status=running` and its own pid to metadata.json once the port is bound.
pub fn run(id: String) -> io::Result<()> {
    // First, in one write: the parent appending it instead would race (and
    // interleave mid-line) with this process's first output in tap.log.
    let header = format!(
        "--- tap start {} pid {} ---\n",
        record::rfc3339(record::unix_ms_now()),
        std::process::id()
    );
    let _ = io::stderr().write_all(header.as_bytes());
    let metadata = load_valid(&id)?;
    let port = parse_port(&metadata.port)?;
    let directory = session_dir(&id);
    let prepared = prepare(&metadata)?;
    let ca = if metadata.intercept {
        Some(Arc::new(load_ca()?))
    } else {
        None
    };
    let executor = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let listener = executor
        .block_on(tokio::net::TcpListener::bind(("127.0.0.1", port)))
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot listen on 127.0.0.1:{port}: {error}"),
            )
        })?;
    let store = Store::open(&directory, &id)?;
    let runtime = Arc::new(Runtime {
        session_id: id.clone(),
        session_dir: directory.clone(),
        filters: prepared.filters,
        hooks: Hooks::new(metadata.hooks.clone()),
        store: store.clone(),
        ca,
        tunnel_hosts: prepared.tunnel_hosts,
        upstream: prepared.upstream,
        upstream_ca: std::env::var_os("TAP_UPSTREAM_CA").map(Into::into),
        redact: metadata
            .redact
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect(),
        max_body: metadata.max_body,
        connect_timeout: Duration::from_secs(10),
        // Idle time only (the proxy restarts it while the body uploads); LLM SDKs wait up to 10 minutes.
        response_timeout: Duration::from_secs(3600),
    });
    let pid = std::process::id();
    let outcome: io::Result<Option<&str>> = executor.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        update_metadata(&id, |current| {
            current.status = "running".into();
            current.pid = Some(pid);
        })?;
        eprintln!("TAP listening on 127.0.0.1:{port} (pid {pid})");
        let mut stopped_by = None;
        let stop = async {
            stopped_by = Some(tokio::select! {
                _ = terminate.recv() => "SIGTERM",
                _ = interrupt.recv() => "SIGINT",
            });
        };
        // On a signal, serve_until cuts open connections and waits for their records.
        proxy::serve_until(listener, runtime, stop).await?;
        Ok(stopped_by)
    });
    // Stop the remaining tasks (async hooks) first so nothing is queued after the flush.
    executor.shutdown_timeout(Duration::from_millis(500));
    store.flush();
    if let Err(error) = mark_stopped(&id, Some(pid)) {
        eprintln!("tap: cannot record that session {id} stopped: {error}");
    }
    if let Ok(Some(signal)) = outcome {
        eprintln!("TAP stopped ({signal})");
    }
    outcome.map(|_| ())
}

pub fn stop(selector: Option<&str>) -> io::Result<()> {
    let id = resolve(selector)?;
    let metadata = load_valid(&id)?;
    let stale = stop_session(&id, &metadata)?;
    if let Some(reason) = &stale {
        eprintln!(
            "tap: session {} was not running ({reason}); marked it stopped",
            display_name(&id, &metadata)
        );
    }
    println!(
        "{}",
        json!({"id": id, "status": "stopped", "stale": stale.is_some()})
    );
    Ok(())
}

/// Stops the session's run process if it is really ours, and always leaves
/// metadata at `stopped` with no pid. Returns why the record was stale, if it was.
fn stop_session(id: &str, metadata: &Metadata) -> io::Result<Option<String>> {
    let stale = match metadata.pid {
        Some(pid) => match inspect(id, pid) {
            Process::Ours => {
                terminate(id, pid)?;
                None
            }
            Process::Foreign => Some(format!(
                "pid {pid} is not this session's proxy process; it was not signalled"
            )),
            Process::Gone => Some(format!("pid {pid} is no longer running")),
        },
        None if metadata.status == "running" => Some("no pid was recorded".to_string()),
        None => None,
    };
    update_metadata(id, |current| {
        current.status = "stopped".into();
        current.pid = None;
    })?;
    Ok(stale)
}

fn terminate(id: &str, pid: u32) -> io::Result<()> {
    send_signal(pid, libc::SIGTERM)?;
    if wait_gone(id, pid, Duration::from_secs(5)) {
        return Ok(());
    }
    if inspect(id, pid) == Process::Ours {
        eprintln!("tap: pid {pid} did not exit within 5s of SIGTERM; sending SIGKILL");
        send_signal(pid, libc::SIGKILL)?;
        wait_gone(id, pid, Duration::from_secs(1));
    }
    Ok(())
}

fn send_signal(pid: u32, signal: i32) -> io::Result<()> {
    let Some(pid) = signalable(pid) else {
        return Ok(());
    };
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(io::Error::new(
            error.kind(),
            format!("cannot signal pid {pid}: {error}"),
        ))
    }
}

/// Polls until `pid` is gone (or no longer our run process, e.g. a zombie).
fn wait_gone(id: &str, pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    for round in 0u32.. {
        if !alive(pid) || (round % 10 == 9 && inspect(id, pid) != Process::Ours) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

pub fn list(table: bool) -> io::Result<()> {
    let mut rows = Vec::new();
    for entry in load_all()? {
        let exchanges = count_exchanges(&session_dir(&entry.id));
        let row = match entry.metadata {
            Ok(metadata) => {
                let metadata = refresh(&entry.id, metadata);
                json!({
                    "id": entry.id,
                    "label": metadata.label,
                    "port": metadata.port,
                    "status": metadata.status,
                    "pid": metadata.pid,
                    "upstream": metadata.upstream,
                    "intercept": metadata.intercept,
                    "exchanges": exchanges,
                })
            }
            Err(error) => json!({
                "id": entry.id,
                "label": "",
                "port": "",
                "status": "invalid",
                "pid": null,
                "upstream": null,
                "intercept": null,
                "exchanges": exchanges,
                "error": error,
            }),
        };
        rows.push(row);
    }
    rows.sort_by_key(|row| {
        let port = row["port"]
            .as_str()
            .and_then(|port| port.parse::<u32>().ok());
        (
            port.unwrap_or(u32::MAX),
            row["id"].as_str().unwrap_or_default().to_string(),
        )
    });

    if !table {
        println!("{}", json!({"sessions": rows}));
        return Ok(());
    }
    let text =
        |row: &serde_json::Value, key: &str| row[key].as_str().unwrap_or_default().to_string();
    let with_upstream = rows.iter().any(|row| row["upstream"].is_string());
    let mut headers = vec!["STATUS", "LABEL", "PORT"];
    if with_upstream {
        headers.push("UPSTREAM");
    }
    headers.extend(["EXCHANGES", "ID"]);
    let cells = rows
        .iter()
        .map(|row| {
            let mut cells = vec![
                text(row, "status").to_uppercase(),
                text(row, "label"),
                text(row, "port"),
            ];
            if with_upstream {
                cells.push(row["upstream"].as_str().unwrap_or("-").to_string());
            }
            cells.push(row["exchanges"].to_string());
            cells.push(text(row, "id"));
            cells
        })
        .collect::<Vec<_>>();
    print_table(&headers, &cells);
    for row in rows.iter().filter(|row| row["status"] == "invalid") {
        eprintln!("tap: session {}: {}", text(row, "id"), text(row, "error"));
    }
    Ok(())
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let widths = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .chain([header.chars().count()])
                .max()
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    let line = |left: char, middle: char, right: char| {
        let parts = widths
            .iter()
            .map(|width| "─".repeat(width + 2))
            .collect::<Vec<_>>();
        format!("{left}{}{right}", parts.join(&middle.to_string()))
    };
    let row = |cells: Vec<&str>| {
        let parts = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!(" {cell:<width$} "))
            .collect::<Vec<_>>();
        format!("│{}│", parts.join("│"))
    };
    println!("{}", line('┌', '┬', '┐'));
    println!("{}", row(headers.to_vec()));
    println!("{}", line('├', '┼', '┤'));
    for cells in rows {
        println!("{}", row(cells.iter().map(String::as_str).collect()));
    }
    println!("{}", line('└', '┴', '┘'));
}

pub fn delete(selector: &str, force: bool) -> io::Result<()> {
    let id = resolve(Some(selector))?;
    if let Ok(metadata) = read_metadata(&id) {
        let metadata = refresh(&id, metadata);
        if metadata.status == "running" {
            if !force {
                return Err(invalid(format!(
                    "session {} is running; stop it first (tap stop {}) or pass --force",
                    display_name(&id, &metadata),
                    selector_for(&id, &metadata)
                )));
            }
            stop_session(&id, &metadata)?;
        }
    }
    fs::remove_dir_all(session_dir(&id))?;
    println!("{}", json!({"id": id, "deleted": true}));
    Ok(())
}

pub fn env(selector: Option<&str>, as_json: bool) -> io::Result<()> {
    let id = resolve(selector)?;
    let metadata = refresh(&id, load_valid(&id)?);
    let port = parse_port(&metadata.port)?;
    let vars = proxy_env(&metadata, port)?;
    if metadata.status != "running" {
        eprintln!(
            "tap: note: session {} is not running; start it with: tap start {}",
            display_name(&id, &metadata),
            selector_for(&id, &metadata)
        );
    }
    if as_json {
        let object = vars
            .iter()
            .map(|(name, value)| (name.to_string(), json!(value.to_string_lossy())))
            .collect::<serde_json::Map<_, _>>();
        println!("{}", serde_json::Value::Object(object));
        return Ok(());
    }
    for (name, value) in &vars {
        println!("export {name}={}", shell_quote(&value.to_string_lossy()));
    }
    if let Some(upstream) = metadata.upstream.as_deref().filter(|url| !url.is_empty()) {
        println!(
            "# this session forwards origin-form requests to {upstream}: set your client's base URL to http://127.0.0.1:{port}"
        );
    }
    Ok(())
}

/// Runs `command` with the session's proxy environment. Returns the exit code
/// to exit with (128+signal when the command was killed by a signal).
pub fn exec(selector: Option<&str>, command: &[String]) -> io::Result<i32> {
    let Some((program, arguments)) = command.split_first() else {
        return Err(invalid("usage: tap exec [SESSION] -- CMD [ARGS...]"));
    };
    let id = resolve(selector)?;
    let metadata = refresh(&id, load_valid(&id)?);
    if metadata.status != "running" {
        return Err(invalid(format!(
            "session {} is not running; start it first: tap start {}",
            display_name(&id, &metadata),
            selector_for(&id, &metadata)
        )));
    }
    let port = parse_port(&metadata.port)?;
    let vars = proxy_env(&metadata, port)?;
    let mut child = match Command::new(program).args(arguments).envs(vars).spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("tap: cannot run {program}: {error}");
            return Ok(if error.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
    };
    // The command shares our terminal: let it alone decide what Ctrl-C does.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
    let status = child.wait()?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or_default()))
}

/// `tap ca [--path]`: ensures the CA and trust bundle exist and explains how to use them.
pub fn ca(path_only: bool) -> io::Result<()> {
    let (cert, bundle) = ensure_trust_files(!path_only)?;
    if path_only {
        println!("{}", cert.display());
        return Ok(());
    }
    let key = absolute(paths::ca_dir().join("ca.key"));
    println!("TAP local CA (used to decrypt HTTPS in intercepting sessions)");
    println!("  certificate   {}", cert.display());
    println!("  private key   {}  (keep it private)", key.display());
    println!(
        "  trust bundle  {}  (system roots + TAP CA)",
        bundle.display()
    );
    println!();
    println!(
        "tap env / tap exec set these for you (trust variables only for intercepting sessions)."
    );
    println!("What each client needs:");
    let rows = [
        ("client", "proxy", "trust"),
        (
            "curl",
            "HTTPS_PROXY, lowercase http_proxy",
            "CURL_CA_BUNDLE=bundle.pem",
        ),
        (
            "Python requests",
            "HTTPS_PROXY / HTTP_PROXY",
            "REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE=bundle.pem (not SSL_CERT_FILE)",
        ),
        (
            "Python httpx (anthropic, openai SDKs)",
            "HTTPS_PROXY / HTTP_PROXY",
            "SSL_CERT_FILE=bundle.pem",
        ),
        (
            "Node fetch/undici, JS SDKs",
            "HTTPS_PROXY + NODE_USE_ENV_PROXY=1",
            "NODE_EXTRA_CA_CERTS=ca.pem",
        ),
        ("Claude Code", "HTTPS_PROXY", "NODE_EXTRA_CA_CERTS=ca.pem"),
    ];
    let client_width = rows.iter().map(|row| row.0.len()).max().unwrap_or_default();
    let proxy_width = rows.iter().map(|row| row.1.len()).max().unwrap_or_default();
    for (client, proxy, trust) in rows {
        println!("  {client:<client_width$}  {proxy:<proxy_width$}  {trust}");
    }
    println!();
    println!(
        "TAP never changes system trust stores. To trust the CA system-wide yourself (optional):"
    );
    let cert_arg = shell_quote(&cert.to_string_lossy());
    if cfg!(target_os = "macos") {
        println!("  security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db {cert_arg}");
    } else {
        println!("  sudo cp {cert_arg} /usr/local/share/ca-certificates/tap.crt && sudo update-ca-certificates");
    }
    Ok(())
}

/// `tap show [SESSION] [ARGS...]`.
pub fn show(args: &[String]) -> io::Result<()> {
    let (id, rest) = split_selector(args)?;
    crate::view::show_command(&session_dir(&id), &name_for(&id), rest)
}

/// `tap tail [SESSION] [ARGS...]`.
pub fn tail(args: &[String]) -> io::Result<()> {
    let (id, rest) = split_selector(args)?;
    crate::view::tail_command(&session_dir(&id), rest)
}

/// The name suggested commands should use for a session: its label, or its id.
fn name_for(id: &str) -> String {
    match read_metadata(id) {
        Ok(metadata) => selector_for(id, &metadata).to_string(),
        Err(_) => id.to_string(),
    }
}

/// The leading argument is the session unless it looks like a viewer argument:
/// an option (`-x`), a filter (`key=value`) or an exchange number.
fn split_selector(args: &[String]) -> io::Result<(String, &[String])> {
    let Some(first) = args.first() else {
        return Ok((resolve(None)?, args));
    };
    if first.starts_with('-') || first.contains('=') {
        return Ok((resolve(None)?, args));
    }
    if !first.is_empty() && first.bytes().all(|byte| byte.is_ascii_digit()) {
        let entries = load_all()?;
        return match entries
            .iter()
            .find(|entry| entry.id == *first || entry.label() == Some(first.as_str()))
        {
            Some(entry) => Ok((entry.id.clone(), &args[1..])),
            None => Ok((single_running(&entries)?, args)),
        };
    }
    Ok((resolve(Some(first))?, &args[1..]))
}

/// Resolves a SESSION argument (full id, label, or unique id prefix of at least
/// 4 characters) to a session id. None picks the single running session.
pub fn resolve(selector: Option<&str>) -> io::Result<String> {
    let entries = load_all()?;
    match selector {
        Some(selector) => resolve_in(&entries, selector),
        None => single_running(&entries),
    }
}

fn resolve_in(entries: &[Entry], selector: &str) -> io::Result<String> {
    if let Some(entry) = entries.iter().find(|entry| entry.id == selector) {
        return Ok(entry.id.clone());
    }
    let labelled = entries
        .iter()
        .filter(|entry| entry.label() == Some(selector))
        .collect::<Vec<_>>();
    match labelled.as_slice() {
        [entry] => return Ok(entry.id.clone()),
        [] => {}
        many => return Err(ambiguous(selector, many)),
    }
    let prefixed = entries
        .iter()
        .filter(|entry| !selector.is_empty() && entry.id.starts_with(selector))
        .collect::<Vec<_>>();
    if selector.chars().count() >= 4 {
        match prefixed.as_slice() {
            [entry] => return Ok(entry.id.clone()),
            [] => {}
            many => return Err(ambiguous(selector, many)),
        }
    } else if !prefixed.is_empty() {
        return Err(invalid(format!(
            "no session is labelled '{selector}', and id prefixes need at least 4 characters"
        )));
    }
    let unreadable = entries
        .iter()
        .filter(|entry| entry.metadata.is_err())
        .count();
    let hint = match unreadable {
        0 => String::new(),
        1 => "; 1 session has an unreadable metadata.json and may be the one you mean".into(),
        n => format!(
            "; {n} sessions have an unreadable metadata.json and may include the one you mean"
        ),
    };
    Err(invalid(format!(
        "no session matches '{selector}'; use a full id, a label, or an id prefix of at least 4 characters (see tap list){hint}"
    )))
}

fn ambiguous(selector: &str, matches: &[&Entry]) -> io::Error {
    let names = matches
        .iter()
        .map(|entry| format!("\n  {}", entry.describe()))
        .collect::<String>();
    invalid(format!(
        "'{selector}' matches {} sessions; use more characters or the label:{names}",
        matches.len()
    ))
}

fn single_running(entries: &[Entry]) -> io::Result<String> {
    let running = entries
        .iter()
        .filter(|entry| match &entry.metadata {
            Ok(metadata) if metadata.status == "running" => {
                refresh(&entry.id, metadata.clone()).status == "running"
            }
            _ => false,
        })
        .collect::<Vec<_>>();
    match running.as_slice() {
        [entry] => Ok(entry.id.clone()),
        [] => Err(invalid(
            "no session is running; name one (see tap list) or start one with: tap start SESSION",
        )),
        many => {
            let names = many
                .iter()
                .map(|entry| format!("\n  {}", entry.describe()))
                .collect::<String>();
            Err(invalid(format!(
                "{} sessions are running; name one:{names}",
                many.len()
            )))
        }
    }
}

/// A directory under `sessions/`, with its metadata or the reason it could not be read.
struct Entry {
    id: String,
    metadata: Result<Metadata, String>,
}

impl Entry {
    fn label(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .ok()
            .map(|metadata| metadata.label.as_str())
            .filter(|label| !label.is_empty())
    }

    fn port(&self) -> Option<u16> {
        self.metadata
            .as_ref()
            .ok()
            .and_then(|metadata| metadata.port.trim().parse().ok())
    }

    fn name(&self) -> String {
        match &self.metadata {
            Ok(metadata) => display_name(&self.id, metadata),
            Err(_) => self.id.clone(),
        }
    }

    fn selector(&self) -> &str {
        self.label().unwrap_or(&self.id)
    }

    fn describe(&self) -> String {
        match &self.metadata {
            Ok(metadata) => format!(
                "{}  label={}  port={}  {}",
                self.id,
                if metadata.label.is_empty() {
                    "-"
                } else {
                    &metadata.label
                },
                metadata.port,
                metadata.status
            ),
            Err(_) => format!("{}  (invalid metadata.json)", self.id),
        }
    }
}

fn load_all() -> io::Result<Vec<Entry>> {
    let directory = match fs::read_dir(sessions_dir()) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("cannot read {}: {error}", sessions_dir().display()),
            ))
        }
    };
    let mut entries = Vec::new();
    for item in directory.flatten() {
        if !item.path().is_dir() {
            continue;
        }
        let Ok(id) = item.file_name().into_string() else {
            continue;
        };
        let metadata = read_metadata(&id).map_err(|error| error.to_string());
        entries.push(Entry { id, metadata });
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(entries)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Process {
    /// Alive and its command line ends with `__run <id>`.
    Ours,
    /// Alive but something else (recycled pid, zombie, another program).
    Foreign,
    Gone,
}

fn inspect(id: &str, pid: u32) -> Process {
    if signalable(pid).is_none() || !alive(pid) {
        return Process::Gone;
    }
    match command_line(pid) {
        Some(command) if is_run_command(&command, id) => Process::Ours,
        _ => Process::Foreign,
    }
}

/// The command line ends with exactly `__run <id>` (not an id that merely starts with `id`).
fn is_run_command(command: &str, id: &str) -> bool {
    command
        .split_whitespace()
        .collect::<Vec<_>>()
        .ends_with(&["__run", id])
}

/// Pids we may pass to kill(2): never 0, 1 or negative (process groups).
fn signalable(pid: u32) -> Option<i32> {
    i32::try_from(pid).ok().filter(|pid| *pid > 1)
}

fn alive(pid: u32) -> bool {
    let Some(pid) = signalable(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn command_line(pid: u32) -> Option<String> {
    if let Ok(bytes) = fs::read(format!("/proc/{pid}/cmdline")) {
        let words = bytes
            .split(|byte| *byte == 0)
            .filter(|word| !word.is_empty())
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>();
        return Some(words.join(" "));
    }
    let output = Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// A `running` record whose process is not our run process is stale: mark it
/// stopped (persisted, best effort) and return the corrected metadata.
fn refresh(id: &str, mut metadata: Metadata) -> Metadata {
    if metadata.status != "running" {
        return metadata;
    }
    if metadata
        .pid
        .is_some_and(|pid| inspect(id, pid) == Process::Ours)
    {
        return metadata;
    }
    if let Err(error) = mark_stopped(id, metadata.pid) {
        eprintln!("tap: cannot update session {id}: {error}");
    }
    metadata.status = "stopped".into();
    metadata.pid = None;
    metadata
}

/// Sets `stopped` unless the record changed meanwhile (its pid is no longer `expected_pid`).
fn mark_stopped(id: &str, expected_pid: Option<u32>) -> io::Result<()> {
    let mut metadata = read_metadata(id)?;
    if metadata.pid != expected_pid || (metadata.status == "stopped" && metadata.pid.is_none()) {
        return Ok(());
    }
    metadata.status = "stopped".into();
    metadata.pid = None;
    write_metadata(id, &metadata)
}

fn update_metadata(id: &str, change: impl FnOnce(&mut Metadata)) -> io::Result<()> {
    let mut metadata = read_metadata(id)?;
    change(&mut metadata);
    write_metadata(id, &metadata)
}

fn read_metadata(id: &str) -> io::Result<Metadata> {
    let path = session_dir(id).join("metadata.json");
    let text = fs::read_to_string(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot read {}: {error}", path.display()),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| invalid(format!("invalid metadata.json: {error}")))
}

fn load_valid(id: &str) -> io::Result<Metadata> {
    read_metadata(id).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("session {id}: {error}; fix it or remove the session with: tap delete {id}"),
        )
    })
}

fn write_metadata(id: &str, metadata: &Metadata) -> io::Result<()> {
    let text = serde_json::to_string_pretty(metadata)
        .map_err(|error| invalid(format!("cannot encode metadata: {error}")))?;
    let path = session_dir(id).join("metadata.json");
    paths::write_private_file(&path, text.as_bytes()).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot write {}: {error}", path.display()),
        )
    })
}

fn display_name(id: &str, metadata: &Metadata) -> String {
    if metadata.label.is_empty() {
        id.to_string()
    } else {
        format!("{} ({id})", metadata.label)
    }
}

fn selector_for<'a>(id: &'a str, metadata: &'a Metadata) -> &'a str {
    if metadata.label.is_empty() {
        id
    } else {
        &metadata.label
    }
}

/// Session configuration parsed and checked, ready for the proxy.
struct Prepared {
    filters: FilterSet,
    tunnel_hosts: Vec<Regex>,
    upstream: Option<http::Uri>,
}

fn prepare(metadata: &Metadata) -> io::Result<Prepared> {
    let filters = FilterSet::parse(&metadata.filters)
        .map_err(|error| invalid(format!("invalid filter: {error}")))?;
    hooks::validate(&metadata.hooks).map_err(|error| invalid(format!("invalid hook: {error}")))?;
    let tunnel_hosts = parse_tunnel(&metadata.tunnel)?;
    let upstream = metadata
        .upstream
        .as_deref()
        .filter(|url| !url.is_empty())
        .map(parse_upstream)
        .transpose()?;
    Ok(Prepared {
        filters,
        tunnel_hosts,
        upstream,
    })
}

fn parse_port(text: &str) -> io::Result<u16> {
    match text.trim().parse::<u32>() {
        Ok(port @ 1..=65535) => Ok(port as u16),
        _ => Err(invalid(format!(
            "port must be a number from 1 to 65535, got '{text}'"
        ))),
    }
}

fn parse_upstream(url: &str) -> io::Result<http::Uri> {
    let expected = "expected an absolute http:// or https:// URL such as https://api.anthropic.com";
    let uri = url
        .parse::<http::Uri>()
        .map_err(|error| invalid(format!("invalid upstream URL '{url}': {error}; {expected}")))?;
    let scheme_ok = matches!(uri.scheme_str(), Some("http") | Some("https"));
    if !scheme_ok || uri.host().is_none_or(str::is_empty) {
        return Err(invalid(format!("invalid upstream URL '{url}': {expected}")));
    }
    Ok(uri)
}

fn parse_tunnel(patterns: &[String]) -> io::Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern)
                .map_err(|error| invalid(format!("invalid --tunnel pattern '{pattern}': {error}")))
        })
        .collect()
}

fn validate_label(label: &str) -> io::Result<()> {
    if label.is_empty() || label.len() > 64 {
        return Err(invalid("label must be 1 to 64 characters long"));
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || label.starts_with('-')
    {
        return Err(invalid(format!(
            "invalid label '{label}': use letters, digits, '-', '_' and '.', not starting with '-'"
        )));
    }
    if label.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(format!(
            "invalid label '{label}': a label needs a non-digit (numbers select exchanges in tap show)"
        )));
    }
    if label.len() == 32 && label.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "invalid label '{label}': it looks like a session id; choose another"
        )));
    }
    Ok(())
}

fn load_ca() -> io::Result<Ca> {
    let directory = paths::ca_dir();
    Ca::load_or_create(&directory).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot load or create the TAP CA in {}: {error}",
                directory.display()
            ),
        )
    })
}

/// Ensures the CA and the trust bundle exist; returns (ca.pem, bundle.pem).
/// The bundle (platform roots, slow to load) is rewritten only when it is
/// missing or older than ca.pem, or when `refresh` is set (`tap ca`).
fn ensure_trust_files(refresh: bool) -> io::Result<(PathBuf, PathBuf)> {
    let directory = paths::ca_dir();
    let ca = load_ca()?;
    let cert = Ca::cert_path(&directory);
    let mut bundle = directory.join("bundle.pem");
    if refresh || !up_to_date(&bundle, &cert) {
        bundle = tls::write_trust_bundle(&directory, &ca).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot write the trust bundle in {}: {error}",
                    directory.display()
                ),
            )
        })?;
    }
    Ok((absolute(cert), absolute(bundle)))
}

/// Whether `path` exists and is no older than `source`.
fn up_to_date(path: &Path, source: &Path) -> bool {
    let modified = |path: &Path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    };
    matches!((modified(path), modified(source)), (Some(path), Some(source)) if path >= source)
}

fn absolute(path: PathBuf) -> PathBuf {
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(parent) = fs::canonicalize(parent) {
            return parent.join(name);
        }
    }
    std::path::absolute(&path).unwrap_or(path)
}

/// Proxy variables removed from the run process's environment.
const PROXY_VARS: [&str; 7] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NODE_USE_ENV_PROXY",
];

/// Exactly the variables `tap env` prints and `tap exec` sets.
fn proxy_env(metadata: &Metadata, port: u16) -> io::Result<Vec<(&'static str, OsString)>> {
    let proxy = OsString::from(format!("http://127.0.0.1:{port}"));
    let mut vars = vec![
        ("HTTP_PROXY", proxy.clone()),
        ("HTTPS_PROXY", proxy.clone()),
        ("http_proxy", proxy.clone()),
        ("https_proxy", proxy),
        ("NODE_USE_ENV_PROXY", OsString::from("1")),
    ];
    if metadata.intercept {
        let (cert, bundle) = ensure_trust_files(false)?;
        vars.push(("NODE_EXTRA_CA_CERTS", cert.into_os_string()));
        for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"] {
            vars.push((name, bundle.clone().into_os_string()));
        }
    }
    Ok(vars)
}

/// Single-quotes `value` for POSIX shells.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Counts exchange lines in events.jsonl without parsing them.
fn count_exchanges(directory: &Path) -> u64 {
    let Ok(file) = fs::File::open(directory.join("events.jsonl")) else {
        return 0;
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut count = 0;
    while matches!(reader.read_until(b'\n', &mut line), Ok(read) if read > 0) {
        if line.starts_with(br#"{"type":"exchange""#) {
            count += 1;
        }
        line.clear();
    }
    count
}

/// Prints the last `lines` lines appended to the log at or after byte offset `from`.
fn print_log_tail(path: &Path, from: u64, lines: usize) {
    let Ok(mut file) = fs::File::open(path) else {
        return;
    };
    let length = file
        .metadata()
        .map(|metadata| metadata.len())
        .unwrap_or_default();
    let start = from.min(length).max(length.saturating_sub(64 * 1024));
    let _ = file.seek(SeekFrom::Start(start));
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    let all = text.lines().collect::<Vec<_>>();
    for line in &all[all.len().saturating_sub(lines)..] {
        eprintln!("{line}");
    }
}

/// Takes an exclusive flock(2) on `path` (best effort), released when the file is dropped.
/// The file is opened separately, so the run process's log descriptors never hold the lock.
fn lock_file(path: &Path) -> Option<fs::File> {
    let file = paths::open_private_append(path).ok()?;
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0).then_some(file)
}

/// Fails when another process already holds 127.0.0.1:PORT. On macOS a loopback
/// bind also succeeds next to a wildcard (0.0.0.0) listener and would silently
/// shadow it, so that address is checked too (bound, never listened on).
fn check_port_free(port: u16) -> io::Result<()> {
    let busy = |error: io::Error, holder: &str| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot listen on 127.0.0.1:{port}: {error}{holder}; another process is using the port \
                 (see: lsof -nP -iTCP:{port} -sTCP:LISTEN) or create a session on another port"
            ),
        )
    };
    std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|error| busy(error, ""))?;
    if cfg!(target_os = "macos") {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket
            .bind((std::net::Ipv4Addr::UNSPECIFIED, port).into())
            .map_err(|error| busy(error, " (held on 0.0.0.0)"))?;
    }
    Ok(())
}

fn unique_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_port_as_string_or_number() {
        let text: Metadata =
            serde_json::from_str(r#"{"id":"a","status":"stopped","port":"8080"}"#).unwrap();
        let number: Metadata =
            serde_json::from_str(r#"{"id":"a","status":"stopped","port":8080}"#).unwrap();
        assert_eq!(text.port, "8080");
        assert_eq!(number.port, "8080");
        assert!(text.intercept);
        assert_eq!(text.max_body, 16 * 1024 * 1024);
    }

    #[test]
    fn validates_ports() {
        assert_eq!(parse_port("8080").unwrap(), 8080);
        for bad in ["0", "65536", "abc", "-1", ""] {
            assert!(parse_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn validates_upstreams() {
        assert!(parse_upstream("https://api.anthropic.com").is_ok());
        assert!(parse_upstream("http://127.0.0.1:9000/base").is_ok());
        for bad in [
            "api.anthropic.com",
            "/v1",
            "ftp://example.com",
            "https://",
            "",
        ] {
            assert!(parse_upstream(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn validates_labels() {
        assert!(validate_label("claude-code_2.1").is_ok());
        for bad in [
            "",
            "-x",
            "a b",
            "123",
            "0123456789abcdef0123456789abcdef",
            "a/b",
        ] {
            assert!(validate_label(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn quotes_for_shells() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn never_signals_special_pids() {
        assert_eq!(signalable(0), None);
        assert_eq!(signalable(1), None);
        assert_eq!(signalable(u32::MAX), None);
        assert_eq!(signalable(42), Some(42));
    }

    #[test]
    fn matches_only_the_exact_run_command() {
        let id = "abcd0000000000000000000000000001";
        assert!(is_run_command(
            &format!("/usr/local/bin/tap __run {id}"),
            id
        ));
        assert!(is_run_command(&format!("/a b/tap __run {id}"), id));
        assert!(!is_run_command(&format!("tap __run {id}"), &id[..31]));
        assert!(!is_run_command(&format!("tap __run {id} extra"), id));
        assert!(!is_run_command("<defunct>", id));
    }

    fn entry(id: &str, label: &str) -> Entry {
        Entry {
            id: id.into(),
            metadata: Ok(Metadata {
                id: id.into(),
                label: label.into(),
                port: "1".into(),
                ..Metadata::default()
            }),
        }
    }

    #[test]
    fn resolves_ids_labels_and_prefixes() {
        let entries = [
            entry("abcd0000000000000000000000000001", "one"),
            entry("abcd0000000000000000000000000002", ""),
            entry("ffff0000000000000000000000000003", "abcd"),
        ];
        assert_eq!(resolve_in(&entries, "one").unwrap(), entries[0].id);
        assert_eq!(
            resolve_in(&entries, "abcd").unwrap(),
            entries[2].id,
            "exact label beats prefix"
        );
        assert_eq!(resolve_in(&entries, "ffff00").unwrap(), entries[2].id);
        assert_eq!(resolve_in(&entries, &entries[1].id).unwrap(), entries[1].id);
        let error = resolve_in(&entries, "abcd0").unwrap_err().to_string();
        assert!(
            error.contains(&entries[0].id) && error.contains(&entries[1].id),
            "{error}"
        );
        assert!(resolve_in(&entries, "fff")
            .unwrap_err()
            .to_string()
            .contains("at least 4"));
        assert!(resolve_in(&entries, "nope").is_err());
    }
}

//! CLI and session lifecycle tests. Each test drives the real `tap` binary with
//! its own XDG_CONFIG_HOME and its own port from 19100-19199.

use serde_json::{json, Value};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TAP: &str = env!("CARGO_BIN_EXE_tap");

/// Ports of sessions that are created but never started (no test binds them).
const UNUSED_PORT_A: &str = "19148";
const UNUSED_PORT_B: &str = "19149";

/// A private TAP home. Dropping it kills any run process still recorded and removes it.
struct Home {
    dir: PathBuf,
}

impl Home {
    fn new(name: &str) -> Home {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tap-cli-{name}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Home { dir }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(TAP);
        command
            .args(args)
            .env("XDG_CONFIG_HOME", &self.dir)
            .env_remove("TAP_UPSTREAM_CA")
            .stdin(Stdio::null());
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NODE_EXTRA_CA_CERTS",
        ] {
            command.env_remove(name);
        }
        command
    }

    fn tap(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    /// Runs tap, asserts success, returns stdout.
    fn ok(&self, args: &[&str]) -> String {
        let output = self.tap(args);
        assert!(
            output.status.success(),
            "tap {args:?} failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let stdout = self.ok(args);
        serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("tap {args:?}: {error}: {stdout}"))
    }

    /// Runs tap, asserts a non-zero exit, returns stderr.
    fn fail(&self, args: &[&str]) -> String {
        let output = self.tap(args);
        assert!(
            !output.status.success(),
            "tap {args:?} unexpectedly succeeded:\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        String::from_utf8(output.stderr).unwrap()
    }

    fn create(&self, args: &[&str]) -> String {
        let mut full = vec!["create"];
        full.extend(args);
        let created = self.json(&full);
        created["id"].as_str().unwrap().to_string()
    }

    fn session_dir(&self, id: &str) -> PathBuf {
        self.dir.join("tap/sessions").join(id)
    }

    fn metadata(&self, id: &str) -> Value {
        serde_json::from_str(
            &fs::read_to_string(self.session_dir(id).join("metadata.json")).unwrap(),
        )
        .unwrap()
    }

    fn write_metadata(&self, id: &str, metadata: &Value) {
        fs::create_dir_all(self.session_dir(id)).unwrap();
        fs::write(
            self.session_dir(id).join("metadata.json"),
            serde_json::to_string_pretty(metadata).unwrap(),
        )
        .unwrap();
    }

    fn listed(&self, id: &str) -> Value {
        let list = self.json(&["list"]);
        list["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|session| session["id"] == id)
            .unwrap_or_else(|| panic!("{id} not in {list}"))
            .clone()
    }

    fn start(&self, selector: &str) -> u32 {
        let started = self.json(&["start", selector]);
        assert_eq!(started["status"], "running", "{started}");
        started["pid"].as_u64().unwrap() as u32
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(self.dir.join("tap/sessions")) {
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().to_string();
                let pid = fs::read_to_string(entry.path().join("metadata.json"))
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    .and_then(|metadata| metadata["pid"].as_u64());
                if let Some(pid) = pid {
                    if is_run_process(pid as u32, &id) {
                        kill(pid as u32, libc::SIGKILL);
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Kills the wrapped child when dropped (also on panic).
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn kill(pid: u32, signal: i32) {
    assert!(pid > 1);
    unsafe {
        libc::kill(pid as i32, signal);
    }
}

fn alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn is_run_process(pid: u32, id: &str) -> bool {
    Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .collect::<Vec<_>>()
                .ends_with(&["__run", id])
        })
        .unwrap_or(false)
}

/// Waits until `pid` has exited and been reaped (or is a zombie that is no longer our process).
fn wait_dead(pid: u32, id: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && is_run_process(pid, id) {
        assert!(Instant::now() < deadline, "pid {pid} still alive");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn create_list_start_stop_delete() {
    let home = Home::new("lifecycle");
    let created = home.json(&["create", "19100", "--label", "life"]);
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert_eq!(created["label"], "life");
    assert_eq!(created["port"], "19100");

    let session = home.listed(&id);
    assert_eq!(session["status"], "stopped");
    assert_eq!(session["label"], "life");
    assert_eq!(session["port"], "19100");
    assert_eq!(session["exchanges"], 0);
    assert!(session["upstream"].is_null());

    let started = home.json(&["start", &id]);
    assert_eq!(started["id"], id.as_str());
    assert_eq!(started["status"], "running");
    assert_eq!(started["port"], "19100");
    assert_eq!(started["proxy"], "http://127.0.0.1:19100");
    let pid = started["pid"].as_u64().unwrap() as u32;
    assert!(is_run_process(pid, &id));
    let metadata = home.metadata(&id);
    assert_eq!(metadata["status"], "running");
    assert_eq!(metadata["pid"], pid);
    TcpStream::connect("127.0.0.1:19100").expect("proxy port accepts connections");

    let session = home.listed(&id);
    assert_eq!(session["status"], "running");
    assert_eq!(session["pid"], pid);
    let table = home.ok(&["list", "--table"]);
    assert!(
        table.contains("RUNNING") && table.contains("life") && table.contains(&id),
        "{table}"
    );

    assert!(home.fail(&["start", "life"]).contains("already running"));

    let stopped = home.json(&["stop", &id]);
    assert_eq!(stopped["status"], "stopped");
    assert_eq!(stopped["stale"], false);
    wait_dead(pid, &id);
    let metadata = home.metadata(&id);
    assert_eq!(metadata["status"], "stopped");
    assert!(metadata["pid"].is_null());
    assert_eq!(home.listed(&id)["status"], "stopped");

    let deleted = home.json(&["delete", "life"]);
    assert_eq!(deleted["deleted"], true);
    assert!(!home.session_dir(&id).exists());
    assert_eq!(home.json(&["list"])["sessions"], serde_json::json!([]));
}

#[test]
fn resolves_labels_prefixes_and_the_single_running_session() {
    let home = Home::new("resolve");
    let id = home.create(&["19101", "--label", "alpha"]);
    let other = home.create(&[UNUSED_PORT_A, "--label", "beta"]);

    assert!(home.fail(&["stop"]).contains("no session is running"));
    let pid = home.start("alpha");
    assert_eq!(home.metadata(&id)["pid"], pid);

    // Selector omitted: the one running session.
    let stopped = home.json(&["stop"]);
    assert_eq!(stopped["id"], id.as_str());
    wait_dead(pid, &id);

    // Unique id prefix (>= 4 chars) and exact id.
    let pid = home.start(&id[..6]);
    assert_eq!(home.json(&["stop", &id[..8]])["id"], id.as_str());
    wait_dead(pid, &id);
    assert_eq!(home.json(&["stop", &other])["id"], other.as_str());
    assert!(home.fail(&["stop", &id[..3]]).contains("at least 4"));
    assert!(home
        .fail(&["stop", "gamma"])
        .contains("no session matches 'gamma'"));

    // Two sessions sharing a prefix.
    let first = "abcd0000000000000000000000000001";
    let second = "abcd0000000000000000000000000002";
    for (session, port) in [(first, "19146"), (second, "19147")] {
        home.write_metadata(
            session,
            &serde_json::json!({"id": session, "status": "stopped", "port": port}),
        );
    }
    let error = home.fail(&["stop", "abcd"]);
    assert!(
        error.contains("matches 2 sessions") && error.contains(first) && error.contains(second),
        "{error}"
    );
    assert_eq!(
        home.json(&["stop", "abcd0000000000000000000000000002"])["id"],
        second
    );

    // Labels must be unique and must not look like ids.
    assert!(home
        .fail(&["create", UNUSED_PORT_B, "--label", "alpha"])
        .contains("already used"));
    assert!(home
        .fail(&[
            "create",
            UNUSED_PORT_B,
            "--label",
            "0123456789abcdef0123456789abcdef"
        ])
        .contains("looks like a session id"));
}

#[test]
fn several_running_sessions_need_a_selector() {
    let home = Home::new("several");
    let one = home.create(&["19111", "--label", "one"]);
    let two = home.create(&["19112", "--label", "two"]);
    let pid_one = home.start("one");
    let pid_two = home.start("two");
    let error = home.fail(&["stop"]);
    assert!(
        error.contains("2 sessions are running") && error.contains(&one) && error.contains(&two),
        "{error}"
    );
    assert!(home.fail(&["env"]).contains("2 sessions are running"));
    home.ok(&["stop", "one"]);
    home.ok(&["stop", "two"]);
    wait_dead(pid_one, &one);
    wait_dead(pid_two, &two);
}

#[test]
fn create_validates_its_arguments() {
    let home = Home::new("validate");
    for port in ["0", "65536", "99999", "abc", "-1"] {
        let error = home.fail(&["create", port]);
        assert!(
            error.contains("port must be a number from 1 to 65535"),
            "{port}: {error}"
        );
    }
    let id = home.create(&[UNUSED_PORT_A, "--max-body", "10MB"]);
    assert_eq!(home.metadata(&id)["max_body"], 10 * 1024 * 1024);
    let error = home.fail(&["create", UNUSED_PORT_A]);
    assert!(
        error.contains("already assigned") && error.contains(&id),
        "{error}"
    );

    let small = home.create(&[
        UNUSED_PORT_B,
        "--max-body=512KB",
        "--no-intercept",
        "--tunnel",
        "apple\\.com$",
    ]);
    let metadata = home.metadata(&small);
    assert_eq!(metadata["max_body"], 512 * 1024);
    assert_eq!(metadata["intercept"], false);
    assert_eq!(metadata["tunnel"], serde_json::json!(["apple\\.com$"]));
    assert!(home
        .fail(&["create", "19145", "--max-body", "12XB"])
        .contains("invalid size"));

    for upstream in ["ftp://example.com", "api.example.com", "/v1"] {
        let error = home.fail(&["create", "19145", "--upstream", upstream]);
        assert!(
            error.contains("absolute http:// or https:// URL"),
            "{upstream}: {error}"
        );
    }
    assert!(home
        .fail(&["create", "19145", "--tunnel", "("])
        .contains("invalid --tunnel pattern"));
    assert!(home
        .fail(&["create", "19145", "--bogus"])
        .contains("unknown option '--bogus'"));

    // Filters are validated with the filter module; whatever it rejects, create rejects.
    let bad_filter = "nosuchkey=1".to_string();
    if let Err(message) = tap::filter::FilterSet::parse(std::slice::from_ref(&bad_filter)) {
        let error = home.fail(&["create", "19145", "--filter", &bad_filter]);
        assert!(
            error.contains("invalid --filter") && error.contains(&message),
            "{error}"
        );
    }
    let filtered = home.create(&[
        "19145",
        "--filter",
        "host=anthropic.com",
        "--filter",
        "status=5xx",
    ]);
    assert_eq!(
        home.metadata(&filtered)["filters"],
        serde_json::json!(["host=anthropic.com", "status=5xx"])
    );

    let upstream = home.create(&["19144", "--upstream", "https://api.example.com"]);
    assert_eq!(
        home.listed(&upstream)["upstream"],
        "https://api.example.com"
    );
    // Failed creates leave nothing behind.
    assert_eq!(
        home.json(&["list"])["sessions"].as_array().unwrap().len(),
        4
    );
}

#[test]
fn start_on_a_busy_port_fails_with_the_bind_error() {
    let home = Home::new("busy");
    let id = home.create(&["19103", "--label", "busy"]);
    let _holder = TcpListener::bind("127.0.0.1:19103").unwrap();
    let error = home.fail(&["start", "busy"]);
    assert!(error.contains("127.0.0.1:19103"), "{error}");
    assert!(error.to_lowercase().contains("in use"), "{error}");
    let metadata = home.metadata(&id);
    assert_eq!(metadata["status"], "stopped");
    assert!(metadata["pid"].is_null());
}

#[test]
fn killed_run_process_is_treated_as_stopped() {
    let home = Home::new("killed");
    let id = home.create(&["19104", "--label", "victim"]);

    let pid = home.start("victim");
    kill(pid, libc::SIGKILL);
    wait_dead(pid, &id);
    assert_eq!(home.listed(&id)["status"], "stopped");
    assert!(
        home.metadata(&id)["pid"].is_null(),
        "list persists the refresh"
    );

    let pid = home.start("victim");
    kill(pid, libc::SIGKILL);
    wait_dead(pid, &id);
    let output = home.tap(&["stop", "victim"]);
    assert!(output.status.success());
    let stopped: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stopped["status"], "stopped");
    assert_eq!(stopped["stale"], true);
    assert!(String::from_utf8_lossy(&output.stderr).contains("was not running"));

    let pid = home.start("victim");
    assert_eq!(home.json(&["stop", "victim"])["stale"], false);
    wait_dead(pid, &id);
}

#[test]
fn stop_never_signals_a_foreign_pid() {
    let home = Home::new("foreign");
    let id = home.create(&["19105", "--label", "foreign"]);
    let mut sleeper = Guard(Command::new("sleep").arg("30").spawn().unwrap());
    let sleeper_pid = sleeper.0.id();
    let mut metadata = home.metadata(&id);
    metadata["status"] = "running".into();
    metadata["pid"] = sleeper_pid.into();
    home.write_metadata(&id, &metadata);

    let output = home.tap(&["stop", "foreign"]);
    assert!(output.status.success(), "{output:?}");
    let stopped: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stopped["stale"], true);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not signalled"));
    thread::sleep(Duration::from_millis(100));
    assert!(
        sleeper.0.try_wait().unwrap().is_none(),
        "sleep was signalled"
    );
    assert_eq!(home.metadata(&id)["status"], "stopped");

    // A stale foreign pid does not block start, and is not touched by it either.
    home.write_metadata(&id, &metadata);
    let pid = home.start("foreign");
    assert_ne!(pid, sleeper_pid);
    home.ok(&["stop", "foreign"]);
    wait_dead(pid, &id);
    assert!(
        sleeper.0.try_wait().unwrap().is_none(),
        "sleep was signalled"
    );
}

#[test]
fn tap_log_is_appended_across_restarts() {
    let home = Home::new("log");
    let id = home.create(&["19106", "--label", "logged"]);
    let log = home.session_dir(&id).join("tap.log");
    let first = home.start("logged");
    home.ok(&["stop", "logged"]);
    wait_dead(first, &id);
    let after_first = fs::read_to_string(&log).unwrap();
    let second = home.start("logged");
    home.ok(&["stop", "logged"]);
    wait_dead(second, &id);
    let text = fs::read_to_string(&log).unwrap();
    assert!(text.starts_with(&after_first), "log was truncated:\n{text}");
    assert_eq!(text.matches("--- tap start ").count(), 2, "{text}");
    for pid in [first, second] {
        assert!(text.contains(&format!(" pid {pid} ---")), "{text}");
        assert!(
            text.contains(&format!("TAP listening on 127.0.0.1:19106 (pid {pid})")),
            "{text}"
        );
    }
    assert_eq!(text.matches("TAP stopped (SIGTERM)").count(), 2, "{text}");
}

#[test]
fn env_prints_exactly_the_proxy_and_trust_variables() {
    let home = Home::new("env");
    let id = home.create(&[
        "19107",
        "--label",
        "envy",
        "--upstream",
        "https://api.example.com",
    ]);
    let proxy = "http://127.0.0.1:19107";
    let text = home.ok(&["env", "envy"]);
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert!(
            text.contains(&format!("export {name}='{proxy}'\n")),
            "{name}: {text}"
        );
    }
    assert!(text.contains("export NODE_USE_ENV_PROXY='1'\n"), "{text}");
    assert!(
        text.contains("# ") && text.contains("https://api.example.com"),
        "{text}"
    );

    let vars = home.json(&["env", &id, "--json"]);
    let vars = vars.as_object().unwrap();
    let names = vars.keys().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NODE_USE_ENV_PROXY",
            "NODE_EXTRA_CA_CERTS",
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE"
        ]
    );
    assert!(vars["NODE_EXTRA_CA_CERTS"]
        .as_str()
        .unwrap()
        .ends_with("tap/ca/ca.pem"));
    for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"] {
        let value = vars[name].as_str().unwrap();
        assert!(value.ends_with("tap/ca/bundle.pem"), "{name}={value}");
        assert!(
            text.contains(&format!("export {name}='{value}'\n")),
            "{name}: {text}"
        );
    }

    home.create(&[UNUSED_PORT_A, "--label", "plain", "--no-intercept"]);
    let plain = home.json(&["env", "plain", "--json"]);
    let names = plain
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NODE_USE_ENV_PROXY"
        ]
    );

    let ca_path = home.ok(&["ca", "--path"]);
    assert_eq!(
        ca_path.trim(),
        vars["NODE_EXTRA_CA_CERTS"].as_str().unwrap()
    );
    let ca = home.ok(&["ca"]);
    assert!(
        ca.contains("NODE_EXTRA_CA_CERTS") && ca.contains("REQUESTS_CA_BUNDLE"),
        "{ca}"
    );
}

#[test]
fn exec_routes_the_command_and_propagates_its_exit_code() {
    let home = Home::new("exec");
    let id = home.create(&["19108", "--label", "runner"]);
    let error = home.fail(&["exec", "runner", "--", "true"]);
    assert!(
        error.contains("not running") && error.contains("tap start runner"),
        "{error}"
    );

    let pid = home.start("runner");
    let status = home
        .command(&[
            "exec",
            "runner",
            "--",
            "sh",
            "-c",
            "test -n \"$HTTPS_PROXY\" && exit 7",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(7));

    let script = "test \"$HTTPS_PROXY\" = http://127.0.0.1:19108 && test \"$http_proxy\" = \"$HTTPS_PROXY\" \
                  && test \"$NODE_USE_ENV_PROXY\" = 1 && test -n \"$NODE_EXTRA_CA_CERTS\" \
                  && test -n \"$CURL_CA_BUNDLE\" && exit 9";
    // Selector omitted: the single running session.
    let status = home
        .command(&["exec", "--", "sh", "-c", script])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(9));

    let status = home
        .command(&["exec", "runner", "--", "sh", "-c", "kill -TERM $$"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(128 + libc::SIGTERM));
    let output = home.tap(&["exec", "runner", "--", "tap-test-no-such-command"]);
    assert_eq!(output.status.code(), Some(127));
    assert!(home.fail(&["exec", "runner", "true"]).contains("--"));

    home.ok(&["stop", "runner"]);
    wait_dead(pid, &id);
}

#[test]
fn delete_refuses_a_running_session_unless_forced() {
    let home = Home::new("delete");
    let id = home.create(&["19109", "--label", "doomed"]);
    let pid = home.start("doomed");
    let error = home.fail(&["delete", "doomed"]);
    assert!(
        error.contains("running") && error.contains("--force"),
        "{error}"
    );
    assert!(home.session_dir(&id).exists());
    assert_eq!(home.json(&["delete", "doomed", "--force"])["deleted"], true);
    assert!(!home.session_dir(&id).exists());
    wait_dead(pid, &id);
}

#[test]
fn list_shows_invalid_and_legacy_metadata() {
    let home = Home::new("invalid");
    let broken = "badbadbadbadbadbadbadbadbadbad00";
    fs::create_dir_all(home.session_dir(broken)).unwrap();
    fs::write(home.session_dir(broken).join("metadata.json"), "{not json").unwrap();
    // Written by an older TAP: port as a string, no newer fields.
    let legacy = "01d0000000000000000000000000000a";
    home.write_metadata(
        legacy,
        &serde_json::json!({"id": legacy, "status": "stopped", "label": "", "port": "19110"}),
    );

    let session = home.listed(broken);
    assert_eq!(session["status"], "invalid");
    assert!(
        session["error"]
            .as_str()
            .unwrap()
            .contains("invalid metadata.json"),
        "{session}"
    );
    let output = home.tap(&["list", "--table"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("INVALID"));
    assert!(String::from_utf8_lossy(&output.stderr).contains(broken));
    assert!(home
        .fail(&["start", broken])
        .contains("invalid metadata.json"));

    assert_eq!(home.listed(legacy)["status"], "stopped");
    let pid = home.start(legacy);
    assert_eq!(home.metadata(legacy)["intercept"], true);
    home.ok(&["stop", legacy]);
    wait_dead(pid, legacy);

    home.ok(&["delete", broken]);
    assert!(!home.session_dir(broken).exists());
}

#[test]
fn exchanges_are_counted_in_list() {
    let home = Home::new("count");
    let id = home.create(&[UNUSED_PORT_A]);
    let events = home.session_dir(&id).join("events.jsonl");
    fs::write(
        &events,
        "{\"type\":\"session_start\",\"session_id\":\"x\",\"at\":\"t\",\"pid\":1,\"version\":\"0.2.0\"}\n\
         {\"type\":\"exchange\",\"seq\":1}\n{\"type\":\"exchange\",\"seq\":2}\n",
    )
    .unwrap();
    assert_eq!(home.listed(&id)["exchanges"], 2);
}

#[test]
fn help_show_tail_and_unknown_commands() {
    let home = Home::new("help");
    let help = home.ok(&["help"]);
    for command in [
        "tap create",
        "tap start",
        "tap exec",
        "tap env",
        "tap ca",
        "tap show",
        "tap tail",
        "--max-body",
    ] {
        assert!(help.contains(command), "{command}: {help}");
    }
    let error = home.fail(&["frobnicate"]);
    assert!(
        error.contains("unknown command") && error.contains("run tap help"),
        "{error}"
    );

    home.create(&[UNUSED_PORT_A, "--label", "viewed"]);
    assert!(home
        .fail(&["show", "nosuch"])
        .contains("no session matches 'nosuch'"));
    assert!(home.fail(&["show", "3"]).contains("no session is running"));
    assert!(home
        .fail(&["tail", "host=example.com"])
        .contains("no session is running"));
    let output = home.tap(&["show", "viewed"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("no session matches") && !stderr.contains("no session is running"),
        "{output:?}"
    );
}

// Ports 19150-19199: adversarial lifecycle tests.

#[test]
fn concurrent_starts_run_exactly_one_proxy() {
    let home = Home::new("race");
    let id = home.create(&["19150", "--label", "racy"]);
    let children = (0..3)
        .map(|_| {
            home.command(&["start", "racy"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    let winners = outputs
        .iter()
        .filter(|output| output.status.success())
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1, "{outputs:?}");
    let started: Value = serde_json::from_slice(&winners[0].stdout).unwrap();
    let pid = started["pid"].as_u64().unwrap() as u32;
    for output in outputs.iter().filter(|output| !output.status.success()) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("already running"), "{stderr}");
    }
    assert_eq!(home.metadata(&id)["pid"], pid);
    assert!(is_run_process(pid, &id));
    let log = fs::read_to_string(home.session_dir(&id).join("tap.log")).unwrap();
    assert_eq!(log.matches("--- tap start ").count(), 1, "{log}");
    home.ok(&["stop", "racy"]);
    wait_dead(pid, &id);
}

#[test]
fn start_shows_this_runs_log_when_the_run_process_fails() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores the directory permissions this relies on
    }
    let home = Home::new("crash");
    let id = home.create(&["19151", "--label", "crash"]);
    let dir = home.session_dir(&id);
    fs::write(dir.join("tap.log"), "output of an earlier run\n").unwrap();
    // The run process cannot record anything (events.jsonl is a directory, the
    // session directory is read-only), so it exits before reporting ready.
    fs::remove_file(dir.join("events.jsonl")).unwrap();
    fs::create_dir(dir.join("events.jsonl")).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let output = home.tap(&["start", "crash"]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("failed to start") && stderr.contains("--- tap start "),
        "{stderr}"
    );
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("tap: ") && !line.contains("failed to start")),
        "the run process's own error is shown: {stderr}"
    );
    assert!(!stderr.contains("earlier run"), "{stderr}");
    let metadata = home.metadata(&id);
    assert_eq!(metadata["status"], "stopped");
    assert!(metadata["pid"].is_null());
    assert!(TcpStream::connect("127.0.0.1:19151").is_err());
}

#[test]
fn start_rejects_bad_metadata_before_spawning() {
    let home = Home::new("badmeta");
    let id = home.create(&["19152", "--label", "edited"]);
    let original = home.metadata(&id);
    let mut cases = vec![
        ("tunnel", json!(["("]), "invalid --tunnel pattern"),
        (
            "upstream",
            json!("ftp://example.com"),
            "absolute http:// or https:// URL",
        ),
        ("port", json!("0"), "port must be a number"),
    ];
    let empty_hook = json!({"on_request": [{"mode": "sync", "command": []}]});
    let hooks = serde_json::from_value(empty_hook.clone()).unwrap();
    if tap::hooks::validate(&hooks).is_err() {
        cases.push(("hooks", empty_hook, "invalid hook"));
    }
    for (key, value, expected) in cases {
        let mut metadata = original.clone();
        metadata[key] = value;
        home.write_metadata(&id, &metadata);
        let error = home.fail(&["start", "edited"]);
        assert!(
            error.contains(expected) && error.contains("metadata.json"),
            "{key}: {error}"
        );
    }
    let log = fs::read_to_string(home.session_dir(&id).join("tap.log")).unwrap();
    assert!(
        !log.contains("--- tap start"),
        "a run process was spawned: {log}"
    );
    assert_eq!(home.metadata(&id)["status"], "stopped");
}

#[test]
fn stop_never_signals_another_session_whose_id_extends_this_one() {
    let home = Home::new("prefixpid");
    let id = home.create(&["19153", "--label", "real"]);
    let pid = home.start("real");
    // A session whose id is a prefix of the running one's, claiming its pid.
    let shorter = &id[..31];
    home.write_metadata(
        shorter,
        &json!({"id": shorter, "status": "running", "port": "19154", "pid": pid}),
    );
    let output = home.tap(&["stop", shorter]);
    assert!(output.status.success(), "{output:?}");
    let stopped: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stopped["stale"], true);
    thread::sleep(Duration::from_millis(100));
    assert!(
        is_run_process(pid, &id),
        "the other session's proxy was signalled"
    );
    assert_eq!(home.listed(&id)["status"], "running");
    home.ok(&["stop", "real"]);
    wait_dead(pid, &id);
}

#[test]
fn stop_kills_a_run_process_that_ignores_sigterm() {
    let home = Home::new("stubborn");
    let id = home.create(&["19155", "--label", "stubborn"]);
    // Its command line ends with `__run ID` like a real run process, but it ignores SIGTERM.
    let mut fake = Guard(
        Command::new("sh")
            .args([
                "-c",
                "trap '' TERM; while :; do sleep 0.1; done",
                "__run",
                &id,
            ])
            .spawn()
            .unwrap(),
    );
    let fake_pid = fake.0.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !is_run_process(fake_pid, &id) {
        assert!(Instant::now() < deadline, "fake run process did not start");
        thread::sleep(Duration::from_millis(20));
    }
    let mut metadata = home.metadata(&id);
    metadata["status"] = "running".into();
    metadata["pid"] = fake_pid.into();
    home.write_metadata(&id, &metadata);

    let started = Instant::now();
    let output = home.tap(&["stop", "stubborn"]);
    let elapsed = started.elapsed();
    assert!(output.status.success(), "{output:?}");
    let stopped: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stopped["stale"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("SIGKILL"));
    assert!(elapsed >= Duration::from_secs(3), "{elapsed:?}");
    assert_eq!(fake.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    let metadata = home.metadata(&id);
    assert_eq!(metadata["status"], "stopped");
    assert!(metadata["pid"].is_null());
}

#[test]
fn env_output_can_be_evaluated_when_paths_contain_quotes() {
    let home = Home::new("it's env");
    home.create(&["19156", "--label", "quoted"]);
    let exported = home.ok(&["env", "quoted"]);
    let vars = home.json(&["env", "quoted", "--json"]);
    let names = [
        "HTTPS_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
    ];
    assert!(vars["NODE_EXTRA_CA_CERTS"]
        .as_str()
        .unwrap()
        .contains("it's env"));
    let script = format!(
        "eval \"$1\" && printf '%s\\n' {}",
        names.map(|name| format!("\"${name}\"")).join(" ")
    );
    let output = Command::new("sh")
        .args(["-c", &script, "sh", &exported])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let expected = names
        .map(|name| format!("{}\n", vars[name].as_str().unwrap()))
        .concat();
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

#[cfg(target_os = "macos")]
#[test]
fn start_refuses_a_port_held_on_the_wildcard_address() {
    let home = Home::new("wildcard");
    let id = home.create(&["19157", "--label", "shadow"]);
    // Bound but never listening, so nothing is reachable from the network.
    let holder = tokio::net::TcpSocket::new_v4().unwrap();
    holder.bind("0.0.0.0:19157".parse().unwrap()).unwrap();
    let error = home.fail(&["start", "shadow"]);
    assert!(
        error.contains("127.0.0.1:19157") && error.contains("0.0.0.0"),
        "{error}"
    );
    assert_eq!(home.metadata(&id)["status"], "stopped");
    drop(holder);
    let pid = home.start("shadow");
    home.ok(&["stop", "shadow"]);
    wait_dead(pid, &id);
}

#[test]
fn run_process_records_a_clean_stop_on_sigint() {
    let home = Home::new("sigint");
    let id = home.create(&["19158", "--label", "interrupted"]);
    let pid = home.start("interrupted");
    kill(pid, libc::SIGINT);
    wait_dead(pid, &id);
    let metadata = home.metadata(&id);
    assert_eq!(metadata["status"], "stopped");
    assert!(metadata["pid"].is_null());
    let log = fs::read_to_string(home.session_dir(&id).join("tap.log")).unwrap();
    assert!(log.contains("TAP stopped (SIGINT)"), "{log}");
}

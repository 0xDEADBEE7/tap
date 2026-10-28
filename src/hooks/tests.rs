use super::*;
use crate::record::{RequestRecord, ResponseRecord};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

fn hook(mode: HookMode, command: &[&str]) -> HookSpec {
    HookSpec {
        mode,
        command: command.iter().map(|part| part.to_string()).collect(),
        timeout_ms: 20_000,
    }
}

fn sync(command: &[&str]) -> HookSpec {
    hook(HookMode::Sync, command)
}

fn python(script: &str) -> HookSpec {
    sync(&["python3", "-I", "-c", script])
}

fn request_hooks(hooks: Vec<HookSpec>) -> Hooks {
    Hooks::new(HookConfig {
        on_request: hooks,
        ..Default::default()
    })
}

fn context() -> HookContext {
    HookContext {
        session_id: "s1".into(),
        seq: 7,
        method: "POST".into(),
        url: "https://api.example.com/v1/messages?x=1".into(),
    }
}

fn request(body: impl Into<Bytes>) -> HookMessage {
    HookMessage {
        method: Some("POST".into()),
        path: Some("/v1/messages?x=1".into()),
        status: None,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("x-dup".into(), "1".into()),
            ("x-dup".into(), "2".into()),
        ],
        body: body.into(),
    }
}

fn response(body: impl Into<Bytes>) -> HookMessage {
    HookMessage {
        status: Some(200),
        headers: vec![("content-type".into(), "text/plain".into())],
        body: body.into(),
        ..Default::default()
    }
}

fn exchange() -> Exchange {
    Exchange {
        seq: 7,
        session_id: "s1".into(),
        started_at: "2026-10-28T06:29:42.123Z".into(),
        request: RequestRecord {
            method: "GET".into(),
            url: "http://example.com/".into(),
            headers: vec![("accept".into(), "*/*".into())],
            ..Default::default()
        },
        response: Some(ResponseRecord {
            status: 200,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn temp_path(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "tap-hooks-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn text_body(size: usize) -> Bytes {
    let pattern = "the quick brown fox jumps over the lazy dog \"quoted\" \\ é\n";
    Bytes::from(pattern.repeat(size / pattern.len() + 1)[..size].to_string())
}

/// A sync hook that saves its stdin to `path` and prints nothing.
fn save_stdin(path: &std::path::Path) -> HookSpec {
    sync(&["sh", "-c", "cat > \"$0\"", path.to_str().unwrap()])
}

async fn wait_for_json(path: &std::path::Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn hook_spec_reads_existing_metadata() {
    let spec: HookSpec =
        serde_json::from_str(r#"{"mode":"sync","command":["python3","h.py"]}"#).unwrap();
    assert_eq!(
        spec,
        HookSpec {
            mode: HookMode::Sync,
            command: vec!["python3".into(), "h.py".into()],
            timeout_ms: 5_000
        }
    );
    let spec: HookSpec =
        serde_json::from_str(r#"{"mode":"async","command":["x"],"timeout_ms":250}"#).unwrap();
    assert_eq!(spec.mode, HookMode::Async);
    assert_eq!(spec.timeout_ms, 250);
    assert_eq!(
        serde_json::to_string(&spec).unwrap(),
        r#"{"mode":"async","command":["x"],"timeout_ms":250}"#
    );
    let config: HookConfig =
        serde_json::from_str(r#"{"on_event":[{"mode":"sync","command":["x"]}]}"#).unwrap();
    assert!(config.on_request.is_empty() && config.on_response.is_empty());
    assert_eq!(config.on_event.len(), 1);
}

#[test]
fn validate_names_the_bad_hook() {
    let good = HookConfig {
        on_request: vec![sync(&["cat"])],
        ..Default::default()
    };
    assert_eq!(validate(&good), Ok(()));
    assert_eq!(validate(&HookConfig::default()), Ok(()));

    let empty = HookConfig {
        on_response: vec![sync(&["cat"]), sync(&[])],
        ..Default::default()
    };
    let error = validate(&empty).unwrap_err();
    assert!(
        error.starts_with("hooks.on_response[1]: command is empty"),
        "{error}"
    );

    let blank = HookConfig {
        on_event: vec![sync(&[" ", "x"])],
        ..Default::default()
    };
    let error = validate(&blank).unwrap_err();
    assert!(
        error.starts_with("hooks.on_event[0]: the program name"),
        "{error}"
    );

    for timeout_ms in [0, MAX_TIMEOUT_MS + 1] {
        let config = HookConfig {
            on_request: vec![HookSpec {
                timeout_ms,
                ..sync(&["cat"])
            }],
            ..Default::default()
        };
        let error = validate(&config).unwrap_err();
        assert!(
            error.starts_with(
                "hooks.on_request[0] (`cat`): timeout_ms must be between 1 and 600000"
            ),
            "{error}"
        );
    }
    let config = HookConfig {
        on_request: vec![HookSpec {
            timeout_ms: MAX_TIMEOUT_MS,
            ..sync(&["cat"])
        }],
        ..Default::default()
    };
    assert_eq!(validate(&config), Ok(()));
}

#[tokio::test]
async fn cat_round_trips_a_one_mib_body_quickly() {
    let hooks = Hooks::new(HookConfig {
        on_request: vec![sync(&["cat"])],
        on_response: vec![sync(&["cat"])],
        ..Default::default()
    });
    let original = request(text_body(1 << 20));
    let started = Instant::now();
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert!(notes.is_empty(), "{notes:?}");

    let original = response(text_body(1 << 20));
    let (message, notes) = hooks.on_response(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert!(notes.is_empty(), "{notes:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn python_hook_injects_a_header() {
    let hooks = request_hooks(vec![python(
        "import json, sys\n\
         m = json.load(sys.stdin)\n\
         m['headers'].append(['X-Injected', 'yes'])\n\
         print(json.dumps(m))",
    )]);
    let original = request("{\"a\":1}");
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    let mut expected = original.headers.clone();
    expected.push(("x-injected".into(), "yes".into()));
    assert_eq!(message.headers, expected);
    assert_eq!(message.body, original.body);
    assert_eq!(message.method, original.method);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("on_request hook `python3 -I -c import json, sys"),
        "{notes:?}"
    );
    assert!(notes[0].ends_with(": changed headers"), "{notes:?}");
}

#[tokio::test]
async fn request_input_matches_the_contract() {
    let saved = temp_path("request.json");
    let hooks = request_hooks(vec![save_stdin(&saved)]);
    let original = request("hello");
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert!(notes.is_empty(), "{notes:?}");
    let input = wait_for_json(&saved).await;
    let _ = std::fs::remove_file(&saved);
    let keys: Vec<&str> = input
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "type",
            "session_id",
            "seq",
            "method",
            "url",
            "scheme",
            "host",
            "port",
            "path",
            "headers",
            "body"
        ]
    );
    assert_eq!(
        input,
        serde_json::json!({
            "type": "request", "session_id": "s1", "seq": 7, "method": "POST",
            "url": "https://api.example.com/v1/messages?x=1", "scheme": "https",
            "host": "api.example.com", "port": 443, "path": "/v1/messages?x=1",
            "headers": [["content-type", "application/json"], ["x-dup", "1"], ["x-dup", "2"]],
            "body": "hello"
        })
    );
}

#[tokio::test]
async fn later_hooks_see_the_changed_path_in_the_url() {
    let saved = temp_path("rewritten.json");
    let hooks = request_hooks(vec![
        python(
            "import json, sys\nm = json.load(sys.stdin)\nprint(json.dumps({'path': '/v2/x?y=2'}))",
        ),
        save_stdin(&saved),
    ]);
    let original = HookMessage {
        method: None,
        path: None,
        ..request("")
    };
    let (message, _) = hooks.on_request(&context(), original).await;
    assert_eq!(message.path.as_deref(), Some("/v2/x?y=2"));
    assert_eq!(message.method, None);
    let input = wait_for_json(&saved).await;
    let _ = std::fs::remove_file(&saved);
    assert_eq!(input["url"], "https://api.example.com/v2/x?y=2");
    assert_eq!(input["path"], "/v2/x?y=2");
    assert_eq!(input["method"], "POST");
}

#[tokio::test]
async fn response_input_matches_the_contract() {
    let saved = temp_path("response.json");
    let hooks = Hooks::new(HookConfig {
        on_response: vec![save_stdin(&saved)],
        ..Default::default()
    });
    let (_, notes) = hooks
        .on_response(&context(), response(vec![0xff_u8, 0x00]))
        .await;
    assert!(notes.is_empty(), "{notes:?}");
    let input = wait_for_json(&saved).await;
    let _ = std::fs::remove_file(&saved);
    assert_eq!(
        input,
        serde_json::json!({
            "type": "response", "session_id": "s1", "seq": 7,
            "request": {"method": "POST", "url": "https://api.example.com/v1/messages?x=1"},
            "status": 200, "headers": [["content-type", "text/plain"]],
            "body": null, "body_base64": "/wA="
        })
    );
}

#[tokio::test]
async fn non_utf8_body_round_trips_via_base64() {
    let binary: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    let hooks = request_hooks(vec![sync(&["cat"])]);
    let original = request(binary.clone());
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert!(notes.is_empty(), "{notes:?}");

    let hooks = request_hooks(vec![python(
        "import base64, json, sys\n\
         m = json.load(sys.stdin)\n\
         assert m['body'] is None\n\
         data = base64.b64decode(m['body_base64'])\n\
         m['body_base64'] = base64.b64encode(data[::-1]).decode()\n\
         m['body'] = 'ignored because body_base64 wins'\n\
         print(json.dumps(m))",
    )]);
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    let reversed: Vec<u8> = binary.iter().rev().copied().collect();
    assert_eq!(message.body, Bytes::from(reversed));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].ends_with(": changed body"), "{notes:?}");
}

#[tokio::test]
async fn response_hook_changes_status_and_object_headers() {
    let hooks = Hooks::new(HookConfig {
        on_response: vec![python(
            "import json, sys\n\
             m = json.load(sys.stdin)\n\
             print(json.dumps({'status': 418, 'headers': {'X-Teapot': 'yes'}}))",
        )],
        ..Default::default()
    });
    let original = response("tea");
    let (message, notes) = hooks.on_response(&context(), original.clone()).await;
    assert_eq!(message.status, Some(418));
    assert_eq!(
        message.headers,
        vec![("x-teapot".to_string(), "yes".to_string())]
    );
    assert_eq!(message.body, original.body);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].ends_with(": changed status, headers"), "{notes:?}");
}

#[tokio::test]
async fn read_only_changes_are_ignored_with_a_note() {
    let hooks = request_hooks(vec![python(
        "import json, sys\n\
         m = json.load(sys.stdin)\n\
         m['host'] = 'evil.example'\n\
         m['port'] = 1\n\
         m['method'] = 'PUT'\n\
         m['path'] = '/v2'\n\
         print(json.dumps(m))",
    )]);
    let (message, notes) = hooks.on_request(&context(), request("x")).await;
    assert_eq!(message.method.as_deref(), Some("PUT"));
    assert_eq!(message.path.as_deref(), Some("/v2"));
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes[0].ends_with(": ignored changes to read-only host, port"),
        "{notes:?}"
    );
    assert!(notes[1].ends_with(": changed method, path"), "{notes:?}");
}

#[tokio::test]
async fn changed_body_updates_content_length() {
    let hooks = request_hooks(vec![python(
        "import json, sys\n\
         m = json.load(sys.stdin)\n\
         m['body'] = 'hello world'\n\
         print(json.dumps(m))",
    )]);
    let mut original = request("hello");
    original.headers.push(("content-length".into(), "5".into()));
    let (message, _) = hooks.on_request(&context(), original).await;
    assert_eq!(message.body, Bytes::from("hello world"));
    assert_eq!(
        crate::record::header(&message.headers, "content-length"),
        Some("11")
    );
}

#[tokio::test]
async fn invalid_fields_leave_the_message_unchanged() {
    let cases = [
        (
            "m['headers'].append(['x-a', 'v\\r\\nx-b: 1'])",
            "invalid value for header `x-a`",
        ),
        ("m['headers'] = 'nope'", "printed invalid headers"),
        ("m['method'] = 'GE T'", "invalid method `GE T`"),
        ("m['path'] = 'http://evil/'", "invalid path"),
        ("m['body_base64'] = '!!!'", "invalid body_base64"),
        ("m['body'] = 5", "`body` that is not a string"),
    ];
    for (change, expected) in cases {
        let script =
            format!("import json, sys\nm = json.load(sys.stdin)\n{change}\nprint(json.dumps(m))");
        let hooks = request_hooks(vec![python(&script)]);
        let original = request("x");
        let (message, notes) = hooks.on_request(&context(), original.clone()).await;
        assert_eq!(message, original, "{change}");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains(expected) && notes[0].ends_with("; unchanged"),
            "{notes:?}"
        );
    }
}

#[tokio::test]
async fn timeout_returns_promptly_and_unchanged() {
    let hooks = request_hooks(vec![HookSpec {
        timeout_ms: 200,
        ..sync(&["sleep", "5"])
    }]);
    let original = request("x");
    let started = Instant::now();
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(message, original);
    assert_eq!(
        notes,
        ["on_request hook `sleep 5`: timed out after 200ms; unchanged"]
    );
}

#[tokio::test]
async fn timeout_kills_processes_the_hook_started() {
    let pid_file = temp_path("grandchild.pid");
    let hooks = request_hooks(vec![HookSpec {
        timeout_ms: 1_000,
        ..sync(&[
            "sh",
            "-c",
            "sleep 30 & echo $! > \"$0\"",
            pid_file.to_str().unwrap(),
        ])
    }]);
    let started = Instant::now();
    let (_, notes) = hooks.on_request(&context(), request("x")).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].ends_with("timed out after 1000ms; unchanged"),
        "{notes:?}"
    );
    let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let _ = std::fs::remove_file(&pid_file);
    let deadline = Instant::now() + Duration::from_secs(10);
    // SAFETY: signal 0 only checks whether the process exists.
    while unsafe { libc::kill(pid, 0) } == 0 {
        assert!(
            Instant::now() < deadline,
            "background process {pid} survived the timeout"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn nonzero_exit_note_includes_stderr() {
    let hooks = request_hooks(vec![sync(&[
        "sh",
        "-c",
        "echo '{}'; echo; echo '  bad things happened  ' >&2; echo more >&2; exit 3",
    ])]);
    let original = request("x");
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].ends_with(": exited with status 3: bad things happened; unchanged"),
        "{notes:?}"
    );
}

#[tokio::test]
async fn heavy_stderr_does_not_block_the_hook() {
    let hooks = request_hooks(vec![sync(&[
        "sh",
        "-c",
        "head -c 1048576 /dev/zero | tr '\\0' e >&2; exit 1",
    ])]);
    let started = Instant::now();
    let (_, notes) = hooks.on_request(&context(), request("x")).await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("exited with status 1: eeee"), "{notes:?}");
    assert!(notes[0].len() < 400, "{notes:?}");
}

#[tokio::test]
async fn oversized_stdout_is_rejected() {
    let hooks = request_hooks(vec![sync(&["head", "-c", "67108865", "/dev/zero"])]);
    let original = request("x");
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert_eq!(
        notes,
        ["on_request hook `head -c 67108865 /dev/zero`: printed more than 64 MiB; unchanged"]
    );
}

#[tokio::test]
async fn invalid_json_gets_a_note() {
    let hooks = request_hooks(vec![sync(&["sh", "-c", "echo not json"])]);
    let original = request("x");
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("on_request hook `sh -c echo not json`: printed invalid JSON ("),
        "{notes:?}"
    );
    assert!(notes[0].ends_with("; unchanged"), "{notes:?}");

    let hooks = request_hooks(vec![sync(&["sh", "-c", "echo '[1, 2]'"])]);
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert_eq!(
        notes,
        ["on_request hook `sh -c echo '[1, 2]'`: printed JSON that is not an object; unchanged"]
    );
}

#[tokio::test]
async fn empty_stdout_means_unchanged() {
    for command in [
        &["true"][..],
        &["sh", "-c", "printf ' \\n\\t '"][..],
        &["sh", "-c", "cat > /dev/null"][..],
    ] {
        let hooks = request_hooks(vec![sync(command)]);
        let original = request(text_body(200_000));
        let (message, notes) = hooks.on_request(&context(), original.clone()).await;
        assert_eq!(message, original, "{command:?}");
        assert!(notes.is_empty(), "{command:?}: {notes:?}");
    }
}

#[tokio::test]
async fn sync_hooks_run_in_order_and_failures_do_not_stop_the_chain() {
    let append = "import json, sys\nm = json.load(sys.stdin)\nm['body'] += sys.argv[1]\nprint(json.dumps(m))";
    let hooks = request_hooks(vec![
        sync(&["python3", "-I", "-c", append, "A"]),
        hook(HookMode::Async, &["true"]),
        sync(&["sh", "-c", "exit 1"]),
        sync(&["python3", "-I", "-c", append, "B"]),
    ]);
    let (message, notes) = hooks.on_request(&context(), request("start-")).await;
    assert_eq!(message.body, Bytes::from("start-AB"));
    assert_eq!(notes.len(), 3, "{notes:?}");
    assert!(notes[0].ends_with(" A`: changed body"), "{notes:?}");
    assert_eq!(
        notes[1],
        "on_request hook `sh -c exit 1`: exited with status 1; unchanged"
    );
    assert!(notes[2].ends_with(" B`: changed body"), "{notes:?}");
}

#[tokio::test]
async fn async_hook_never_delays_the_caller() {
    let hooks = request_hooks(vec![hook(HookMode::Async, &["sleep", "2"])]);
    let original = request(text_body(1 << 20));
    let started = Instant::now();
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(message, original);
    assert!(notes.is_empty(), "{notes:?}");
    // Let the task start the process and block writing to it; it must not affect us.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn async_hook_sees_the_final_message() {
    let saved = temp_path("async.json");
    let saved_arg = saved.to_str().unwrap();
    let hooks = request_hooks(vec![
        hook(HookMode::Async, &["sh", "-c", "cat > \"$0.tmp\" && mv \"$0.tmp\" \"$0\"", saved_arg]),
        python("import json, sys\nm = json.load(sys.stdin)\nm['body'] = 'changed'\nprint(json.dumps(m))"),
    ]);
    let (message, _) = hooks.on_request(&context(), request("original")).await;
    assert_eq!(message.body, Bytes::from("changed"));
    let input = wait_for_json(&saved).await;
    let _ = std::fs::remove_file(&saved);
    assert_eq!(input["type"], "request");
    assert_eq!(input["body"], "changed");
}

#[tokio::test]
async fn missing_program_is_a_note_not_a_panic() {
    let hooks = Hooks::new(HookConfig {
        on_request: vec![sync(&["tap-hooks-test-no-such-program"])],
        on_response: vec![hook(HookMode::Async, &["tap-hooks-test-no-such-program"])],
        on_event: vec![sync(&["./tap-hooks-test-no-such-program"])],
    });
    let original = request("x");
    let (message, notes) = hooks.on_request(&context(), original.clone()).await;
    assert_eq!(message, original);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("on_request hook `tap-hooks-test-no-such-program`: could not start: No such file or directory"),
        "{notes:?}"
    );
    let (_, notes) = hooks.on_response(&context(), response("x")).await;
    assert!(notes.is_empty(), "{notes:?}");
    let (event, notes) = hooks.on_event(exchange()).await;
    assert_eq!(event, exchange());
    assert!(notes[0].contains("could not start"), "{notes:?}");
}

#[tokio::test]
async fn event_hook_gets_the_record_and_may_change_it() {
    let saved = temp_path("event.json");
    let hooks = Hooks::new(HookConfig {
        on_event: vec![
            save_stdin(&saved),
            python(
                "import json, sys\n\
                 e = json.load(sys.stdin)\n\
                 assert e['type'] == 'exchange'\n\
                 e['error'] = 'flagged'\n\
                 print(json.dumps(e))",
            ),
            python(
                "import json, sys\n\
                 e = json.load(sys.stdin)\n\
                 del e['type']\n\
                 e['notes'] = e.get('notes', []) + ['checked']\n\
                 print(json.dumps(e))",
            ),
            python("print('{\"duration_ms\": 42}')"),
        ],
        ..Default::default()
    });
    let (event, notes) = hooks.on_event(exchange()).await;
    let input = wait_for_json(&saved).await;
    let _ = std::fs::remove_file(&saved);
    assert_eq!(
        input,
        serde_json::to_value(crate::record::Event::Exchange(exchange())).unwrap()
    );
    assert_eq!(event.error.as_deref(), Some("flagged"));
    assert_eq!(event.notes, ["checked"]);
    assert_eq!(event.duration_ms, Some(42));
    assert_eq!(event.request, exchange().request);
    assert_eq!(notes.len(), 3, "{notes:?}");
    assert!(notes[0].ends_with(": changed error"), "{notes:?}");
    assert!(notes[1].ends_with(": changed notes"), "{notes:?}");
    assert!(notes[2].ends_with(": changed duration_ms"), "{notes:?}");
}

#[tokio::test]
async fn event_hook_cannot_change_identity() {
    let cases = [
        ("e['seq'] = 99", "tried to change seq from 7 to 99"),
        (
            "e['session_id'] = 'other'",
            "tried to change session_id to `other`",
        ),
        ("e['type'] = 'session_start'", "not an exchange"),
        ("e['mode'] = 'bogus'", "printed an invalid exchange"),
    ];
    for (change, expected) in cases {
        let script = format!("import json, sys\ne = json.load(sys.stdin)\n{change}\ne['error'] = 'x'\nprint(json.dumps(e))");
        let hooks = Hooks::new(HookConfig {
            on_event: vec![python(&script)],
            ..Default::default()
        });
        let (event, notes) = hooks.on_event(exchange()).await;
        assert_eq!(event, exchange(), "{change}");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains(expected) && notes[0].ends_with("; unchanged"),
            "{notes:?}"
        );
    }
}

#[test]
fn long_commands_are_shortened_in_notes() {
    let script = format!("import sys\n{}", "x".repeat(200));
    let command: Vec<String> = vec!["python3".into(), "-c".into(), script.clone(), "arg".into()];
    let shown = display(&command);
    assert_eq!(
        shown,
        format!("python3 -c import sys {}... arg", "x".repeat(26))
    );
    let many: Vec<String> = (0..20).map(|_| script.clone()).collect();
    assert_eq!(display(&many).chars().count(), 120);
    assert_eq!(display(&["python3".into(), "h.py".into()]), "python3 h.py");
}

#[test]
fn hook_futures_are_send() {
    // The proxy runs hooks inside spawned tasks.
    fn assert_send<T: Send>(_: &T) {}
    let hooks = request_hooks(Vec::new());
    let context = context();
    assert_send(&hooks.on_request(&context, request("x")));
    assert_send(&hooks.on_response(&context, response("x")));
    assert_send(&hooks.on_event(exchange()));
}

#[tokio::test]
async fn hook_that_ignores_most_of_its_input_still_applies() {
    let hooks = request_hooks(vec![sync(&[
        "sh",
        "-c",
        "head -c 10 > /dev/null; printf '{\"body\": \"short\"}'",
    ])]);
    let (message, notes) = hooks
        .on_request(&context(), request(text_body(4 << 20)))
        .await;
    assert_eq!(message.body, Bytes::from("short"));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].ends_with(": changed body"), "{notes:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hooks_keep_their_payloads_apart() {
    let hooks = std::sync::Arc::new(Hooks::new(HookConfig {
        on_request: vec![sync(&["cat"])],
        on_response: vec![sync(&["cat"])],
        ..Default::default()
    }));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..16u8 {
        let hooks = hooks.clone();
        tasks.spawn(async move {
            let body = vec![index; 256 << 10];
            let context = HookContext {
                seq: u64::from(index),
                ..context()
            };
            let (sent, notes) = hooks.on_request(&context, request(body.clone())).await;
            assert!(notes.is_empty(), "{notes:?}");
            let (received, notes) = hooks.on_response(&context, response(body.clone())).await;
            assert!(notes.is_empty(), "{notes:?}");
            (sent.body == body, received.body == body)
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), (true, true));
    }
}

#[tokio::test]
async fn echoing_the_input_back_is_never_a_change_or_a_failure() {
    let echo = python("import json, sys\nprint(json.dumps(json.load(sys.stdin)))");
    let hooks = Hooks::new(HookConfig {
        on_request: vec![echo.clone()],
        on_response: vec![echo.clone()],
        on_event: vec![echo, sync(&["cat"])],
    });
    let (message, notes) = hooks
        .on_request(&context(), request(vec![0x80_u8, 0xff]))
        .await;
    assert_eq!(message, request(vec![0x80_u8, 0xff]));
    assert!(notes.is_empty(), "{notes:?}");
    // A context the request input cannot be built faithfully from (method/url unknown).
    let odd = HookContext {
        method: String::new(),
        url: "not a url".into(),
        ..context()
    };
    let bare = HookMessage {
        method: None,
        path: None,
        ..request("x")
    };
    let (message, notes) = hooks.on_request(&odd, bare.clone()).await;
    assert_eq!(message, bare);
    assert!(notes.is_empty(), "{notes:?}");
    let (message, notes) = hooks.on_response(&context(), response("ok")).await;
    assert_eq!(message, response("ok"));
    assert!(notes.is_empty(), "{notes:?}");
    let mut record = exchange();
    record.notes = vec!["redacted x-api-key".into()];
    record.request.body.file = Some("bodies/7.req".into());
    let (event, notes) = hooks.on_event(record.clone()).await;
    assert_eq!(event, record);
    assert!(notes.is_empty(), "{notes:?}");
}

#[tokio::test]
async fn response_hook_rejects_bad_status_and_keeps_request_read_only() {
    for status in ["99", "1000", "'200'", "200.5", "-1", "True"] {
        let script = format!("import json, sys\nm = json.load(sys.stdin)\nm['status'] = {status}\nprint(json.dumps(m))");
        let hooks = Hooks::new(HookConfig {
            on_response: vec![python(&script)],
            ..Default::default()
        });
        let (message, notes) = hooks.on_response(&context(), response("x")).await;
        assert_eq!(message, response("x"), "{status}");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("invalid status") && notes[0].ends_with("; unchanged"),
            "{notes:?}"
        );
    }
    let hooks = Hooks::new(HookConfig {
        on_response: vec![python(
            "import json, sys\nm = json.load(sys.stdin)\nm['request']['url'] = 'http://evil/'\nm['seq'] = 1\nm['body'] = 'new'\nprint(json.dumps(m))",
        )],
        ..Default::default()
    });
    let (message, notes) = hooks.on_response(&context(), response("x")).await;
    assert_eq!(message.body, Bytes::from("new"));
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes[0].ends_with(": ignored changes to read-only seq, request"),
        "{notes:?}"
    );
    assert!(notes[1].ends_with(": changed body"), "{notes:?}");
}

#[tokio::test]
async fn malformed_headers_and_paths_are_rejected() {
    let cases = [
        ("m['headers'] = [['a']]", "printed invalid headers"),
        (
            "m['headers'] = [['a', 'b', 'c']]",
            "printed invalid headers",
        ),
        ("m['headers'] = [['a', None]]", "printed invalid headers"),
        ("m['headers'] = {'a': 1}", "printed invalid headers"),
        (
            "m['headers'] = [['bad name', 'v']]",
            "invalid header name `bad name`",
        ),
        (
            "m['headers'] = [[':authority', 'evil']]",
            "invalid header name `:authority`",
        ),
        ("m['path'] = '/a#frag'", "invalid path `/a#frag`"),
        ("m['path'] = '/a b'", "invalid path"),
        ("m['path'] = ''", "invalid path"),
        ("m['method'] = ''", "invalid method"),
        ("m['body_base64'] = 5", "`body_base64` that is not a string"),
    ];
    for (change, expected) in cases {
        let script =
            format!("import json, sys\nm = json.load(sys.stdin)\n{change}\nprint(json.dumps(m))");
        let hooks = request_hooks(vec![python(&script)]);
        let (message, notes) = hooks.on_request(&context(), request("x")).await;
        assert_eq!(message, request("x"), "{change}");
        assert_eq!(notes.len(), 1, "{change}: {notes:?}");
        assert!(
            notes[0].contains(expected) && notes[0].ends_with("; unchanged"),
            "{change}: {notes:?}"
        );
    }
}

#[tokio::test]
async fn trailing_output_after_the_object_is_invalid_json() {
    let hooks = request_hooks(vec![sync(&[
        "sh",
        "-c",
        "echo '{\"body\": \"a\"}'; echo debug",
    ])]);
    let (message, notes) = hooks.on_request(&context(), request("x")).await;
    assert_eq!(message, request("x"));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("printed invalid JSON (trailing characters"),
        "{notes:?}"
    );
}

#[tokio::test]
async fn failure_notes_hold_no_control_characters() {
    let hooks = request_hooks(vec![sync(&[
        "sh",
        "-c",
        "printf '\\033[31mboom\\033[0m\\a\\n' >&2; exit 2",
    ])]);
    let (_, notes) = hooks.on_request(&context(), request("x")).await;
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].ends_with(": exited with status 2: [31mboom[0m; unchanged"),
        "{notes:?}"
    );
}

#[tokio::test]
async fn async_hook_timeout_kills_its_processes() {
    let pid_file = temp_path("async-grandchild.pid");
    let hooks = request_hooks(vec![HookSpec {
        timeout_ms: 1_000,
        ..hook(
            HookMode::Async,
            &[
                "sh",
                "-c",
                "sleep 30 & echo $! > \"$0\"; wait",
                pid_file.to_str().unwrap(),
            ],
        )
    }]);
    let (_, notes) = hooks
        .on_request(&context(), request(text_body(1 << 20)))
        .await;
    assert!(notes.is_empty(), "{notes:?}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid: libc::pid_t = loop {
        if let Some(pid) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the async hook never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let _ = std::fs::remove_file(&pid_file);
    // SAFETY: signal 0 only checks whether the process exists.
    while unsafe { libc::kill(pid, 0) } == 0 {
        assert!(
            Instant::now() < deadline,
            "background process {pid} survived the async timeout"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

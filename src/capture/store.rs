//! The append-only event store of one session: `events.jsonl` plus raw body files.

use crate::paths;
use crate::record::{self, Event, Exchange, SessionStart};
use bytes::Bytes;
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

/// Append-only capture store for one session directory.
///
/// Layout: `<dir>/events.jsonl` (one `record::Event` per line) and
/// `<dir>/bodies/<seq>.req` / `<seq>.res` (raw captured body bytes).
/// All writes go through one writer thread so lines never interleave.
pub struct Store {
    session_id: String,
    dir: PathBuf,
    seq: AtomicU64,
    writer: mpsc::Sender<Message>,
}

enum Message {
    Record(Box<Exchange>, Bytes, Bytes),
    Flush(mpsc::SyncSender<()>),
}

impl Store {
    /// Opens or creates the store, continues numbering after the highest `seq`
    /// already in `events.jsonl`, starts the writer thread, and appends a
    /// `SessionStart` event. Files are created 0600, `bodies/` 0700.
    pub fn open(session_dir: &Path, session_id: &str) -> io::Result<Arc<Store>> {
        paths::create_private_dir(session_dir)?;
        paths::create_private_dir(&session_dir.join("bodies"))?;
        let events_path = session_dir.join("events.jsonl");
        let (last_seq, ends_mid_line) = scan(&events_path)?;

        let mut events = paths::open_private_append(&events_path)?;
        let _ = events.set_permissions(fs::Permissions::from_mode(0o600));
        let start = Event::SessionStart(SessionStart {
            session_id: session_id.into(),
            at: record::rfc3339(record::unix_ms_now()),
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
        });
        let mut line = if ends_mid_line {
            "\n".to_string()
        } else {
            String::new()
        };
        line.push_str(&serde_json::to_string(&start).map_err(io::Error::other)?);
        line.push('\n');
        events.write_all(line.as_bytes())?;

        let (sender, receiver) = mpsc::channel();
        let dir = session_dir.to_path_buf();
        thread::Builder::new()
            .name("tap-store".into())
            .spawn(move || write_loop(&dir, events, receiver))?;

        Ok(Arc::new(Store {
            session_id: session_id.into(),
            dir: session_dir.into(),
            seq: AtomicU64::new(last_seq),
            writer: sender,
        }))
    }

    /// Allocates the next exchange number (first call after a fresh store returns 1).
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Queues `exchange` for writing. Non-empty bodies are written to
    /// `bodies/<seq>.req|res` first and the matching `BodyRecord.file` is set.
    /// Never blocks on disk I/O; errors are reported on stderr (the session log).
    pub fn record(&self, exchange: Exchange, request_body: Bytes, response_body: Bytes) {
        let seq = exchange.seq;
        let message = Message::Record(Box::new(exchange), request_body, response_body);
        if self.writer.send(message).is_err() {
            report(format_args!(
                "event writer is gone; exchange {seq} was not recorded"
            ));
        }
    }

    /// Blocks until everything queued so far is on disk.
    pub fn flush(&self) {
        let (ack, done) = mpsc::sync_channel(1);
        if self.writer.send(Message::Flush(ack)).is_ok() {
            let _ = done.recv();
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.flush();
    }
}

#[derive(Deserialize)]
struct SeqOnly {
    #[serde(default)]
    seq: Option<u64>,
}

/// Highest `seq` in an existing events file (0 if none), and whether the file
/// ends without a newline (a line cut short by a crash).
fn scan(path: &Path) -> io::Result<(u64, bool)> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((0, false)),
        Err(error) => return Err(error),
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut last_seq = 0;
    let mut ends_mid_line = false;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        ends_mid_line = line.last() != Some(&b'\n');
        if let Ok(SeqOnly { seq: Some(seq) }) = serde_json::from_slice(&line) {
            last_seq = last_seq.max(seq);
        }
    }
    Ok((last_seq, ends_mid_line))
}

fn write_loop(dir: &Path, mut events: File, receiver: mpsc::Receiver<Message>) {
    // Set after a failed append, which may have left part of a line behind.
    let mut torn = false;
    for message in receiver {
        match message {
            Message::Record(exchange, request_body, response_body) => {
                let seq = exchange.seq;
                let written = panic::catch_unwind(AssertUnwindSafe(|| {
                    let exchange = *exchange;
                    write_exchange(
                        dir,
                        &mut events,
                        &mut torn,
                        exchange,
                        &request_body,
                        &response_body,
                    )
                }));
                if written.is_err() {
                    report(format_args!(
                        "internal error while recording exchange {seq}; continuing"
                    ));
                }
            }
            Message::Flush(ack) => {
                let _ = events.flush();
                let _ = ack.send(());
            }
        }
    }
}

fn write_exchange(
    dir: &Path,
    events: &mut File,
    torn: &mut bool,
    mut exchange: Exchange,
    request: &[u8],
    response: &[u8],
) {
    let seq = exchange.seq;
    exchange.request.body.file = save_body(dir, seq, "req", request, &mut exchange.notes);
    if let Some(record) = exchange.response.as_mut() {
        record.body.file = save_body(dir, seq, "res", response, &mut exchange.notes);
    }
    let encoded = match serde_json::to_string(&Event::Exchange(exchange)) {
        Ok(encoded) => encoded,
        Err(error) => {
            report(format_args!("could not encode exchange {seq}: {error}"));
            return;
        }
    };
    let mut line = String::with_capacity(encoded.len() + 2);
    if *torn && !ends_with_newline(&dir.join("events.jsonl")) {
        line.push('\n');
    }
    line.push_str(&encoded);
    line.push('\n');
    match events.write_all(line.as_bytes()) {
        Ok(()) => *torn = false,
        Err(error) => {
            *torn = true;
            report(format_args!(
                "could not append exchange {seq} to events.jsonl: {error}"
            ));
        }
    }
}

/// Whether the file is empty or ends with a newline; false when it cannot be read.
fn ends_with_newline(path: &Path) -> bool {
    let mut last = [0u8];
    File::open(path)
        .and_then(|file| match file.metadata()?.len() {
            0 => Ok(true),
            len => file
                .read_exact_at(&mut last, len - 1)
                .map(|()| last[0] == b'\n'),
        })
        .unwrap_or(false)
}

/// Prints `tap: <message>` on stderr (the session log). Unlike `eprintln!` it does not
/// panic when that write fails too, as it will when the disk is full.
fn report(message: std::fmt::Arguments) {
    let _ = writeln!(io::stderr(), "tap: {message}");
}

/// Writes `bytes` to `bodies/<seq>.<extension>` and returns that relative path,
/// or None when there is nothing to save or saving failed.
fn save_body(
    dir: &Path,
    seq: u64,
    extension: &str,
    bytes: &[u8],
    notes: &mut Vec<String>,
) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let relative = format!("bodies/{seq}.{extension}");
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join(&relative))
        .and_then(|mut file| {
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            file.write_all(bytes)
        });
    match written {
        Ok(()) => Some(relative),
        Err(error) => {
            report(format_args!("could not save {relative}: {error}"));
            notes.push(format!("{relative} could not be saved: {error}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{BodyRecord, RequestRecord, ResponseRecord};
    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let unique = format!(
                "tap-store-{name}-{}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
                record::unix_ms_now()
            );
            TempDir(std::env::temp_dir().join(unique))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn events(dir: &Path) -> Vec<Event> {
        fs::read_to_string(dir.join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}"))
            })
            .collect()
    }

    fn exchanges(dir: &Path) -> Vec<Exchange> {
        events(dir)
            .into_iter()
            .filter_map(|event| match event {
                Event::Exchange(exchange) => Some(exchange),
                Event::SessionStart(_) => None,
            })
            .collect()
    }

    fn exchange(store: &Store, with_response: bool) -> Exchange {
        Exchange {
            seq: store.next_seq(),
            session_id: store.session_id().into(),
            request: RequestRecord {
                method: "POST".into(),
                url: "http://example.test/x".into(),
                body: BodyRecord {
                    size: 3,
                    captured: 3,
                    complete: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            response: with_response.then(|| ResponseRecord {
                status: 200,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn open_creates_private_layout_and_session_start() {
        let temp = TempDir::new("layout");
        let dir = temp.0.join("nested/session");
        let store = Store::open(&dir, "abc123").unwrap();
        store.flush();
        assert_eq!(store.dir(), dir.as_path());
        assert_eq!(store.session_id(), "abc123");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("bodies")), 0o700);
        assert_eq!(mode(&dir.join("events.jsonl")), 0o600);

        let events = events(&dir);
        assert_eq!(events.len(), 1);
        let Event::SessionStart(start) = &events[0] else {
            panic!("{events:?}")
        };
        assert_eq!(start.session_id, "abc123");
        assert_eq!(start.pid, std::process::id());
        assert_eq!(start.version, env!("CARGO_PKG_VERSION"));
        assert!(
            start.at.ends_with('Z') && start.at.len() == 24,
            "{}",
            start.at
        );
        assert_eq!(store.next_seq(), 1);
        assert_eq!(store.next_seq(), 2);
    }

    #[test]
    fn concurrent_records_are_whole_lines_with_unique_seqs() {
        let temp = TempDir::new("concurrent");
        let store = Store::open(&temp.0, "s").unwrap();
        let threads: Vec<_> = (0..50)
            .map(|worker| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    for index in 0..20 {
                        let mut record = exchange(&store, index % 2 == 0);
                        record
                            .notes
                            .push(format!("worker {worker} item {index} {}", "x".repeat(4000)));
                        let body = if index % 5 == 0 {
                            Bytes::from(vec![b'a'; 3])
                        } else {
                            Bytes::new()
                        };
                        store.record(record, body.clone(), body);
                    }
                })
            })
            .collect();
        for handle in threads {
            handle.join().unwrap();
        }
        store.flush();

        let events = events(&temp.0);
        let starts = events
            .iter()
            .filter(|event| matches!(event, Event::SessionStart(_)))
            .count();
        assert_eq!(starts, 1);
        let seqs: HashSet<u64> = exchanges(&temp.0)
            .iter()
            .map(|exchange| exchange.seq)
            .collect();
        assert_eq!(events.len(), 1001);
        assert_eq!(seqs, (1..=1000).collect());
    }

    #[test]
    fn seq_continues_across_reopen() {
        let temp = TempDir::new("reopen");
        {
            let store = Store::open(&temp.0, "s").unwrap();
            for _ in 0..3 {
                store.record(exchange(&store, true), Bytes::new(), Bytes::new());
            }
        }
        // Junk and older lines without a seq are ignored, and a line cut short by a crash
        // does not swallow the next SessionStart.
        let mut file = paths::open_private_append(&temp.0.join("events.jsonl")).unwrap();
        file.write_all(b"not json\n{\"type\":\"exchange\",\"method\":\"GET\"}\n\xff\xfe\n{\"seq\":\"9\"}\n{\"type\":\"exch")
            .unwrap();
        drop(file);

        let store = Store::open(&temp.0, "s").unwrap();
        assert_eq!(store.next_seq(), 4);
        store.record(exchange(&store, true), Bytes::new(), Bytes::new());
        store.flush();
        drop(store);

        let store = Store::open(&temp.0, "s").unwrap();
        assert_eq!(store.next_seq(), 6);
        store.flush();

        let text =
            String::from_utf8_lossy(&fs::read(temp.0.join("events.jsonl")).unwrap()).into_owned();
        let lines: Vec<&str> = text.lines().collect();
        let parsed: Vec<Event> = lines
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let starts = parsed
            .iter()
            .filter(|event| matches!(event, Event::SessionStart(_)))
            .count();
        assert_eq!(starts, 3, "one SessionStart per open");
        let seqs: Vec<u64> = parsed
            .iter()
            .filter_map(|event| match event {
                Event::Exchange(exchange) => Some(exchange.seq),
                Event::SessionStart(_) => None,
            })
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 5]);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn bodies_are_saved_byte_exact_and_private() {
        let temp = TempDir::new("bodies");
        let store = Store::open(&temp.0, "s").unwrap();
        let request: &[u8] = b"\x00\xff\xfe binary \x80 request";
        let response: &[u8] = b"\x1f\x8b\x08 gzip-ish \xc3\x28";
        let first = exchange(&store, true);
        store.record(
            first,
            Bytes::from_static(request),
            Bytes::from_static(response),
        );
        store.flush();

        assert_eq!(fs::read(temp.0.join("bodies/1.req")).unwrap(), request);
        assert_eq!(fs::read(temp.0.join("bodies/1.res")).unwrap(), response);
        assert_eq!(mode(&temp.0.join("bodies/1.req")), 0o600);
        assert_eq!(mode(&temp.0.join("bodies/1.res")), 0o600);
        let recorded = exchanges(&temp.0);
        assert_eq!(
            recorded[0].request.body.file.as_deref(),
            Some("bodies/1.req")
        );
        assert_eq!(
            recorded[0].response.as_ref().unwrap().body.file.as_deref(),
            Some("bodies/1.res")
        );
        assert_eq!(
            recorded[0].request.body.size, 3,
            "other BodyRecord fields are kept"
        );
    }

    #[test]
    fn empty_bodies_and_missing_responses_write_no_files() {
        let temp = TempDir::new("empty");
        let store = Store::open(&temp.0, "s").unwrap();
        let mut stale = exchange(&store, true);
        stale.request.body.file = Some("bodies/stale.req".into());
        store.record(stale, Bytes::new(), Bytes::new());
        // No response record: a response body has nowhere to be referenced from.
        store.record(
            exchange(&store, false),
            Bytes::from_static(b"req"),
            Bytes::from_static(b"res"),
        );
        store.flush();

        let recorded = exchanges(&temp.0);
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].request.body.file, None);
        assert_eq!(recorded[0].response.as_ref().unwrap().body.file, None);
        assert_eq!(
            recorded[1].request.body.file.as_deref(),
            Some("bodies/2.req")
        );
        assert!(recorded[1].response.is_none());
        let mut files: Vec<_> = fs::read_dir(temp.0.join("bodies"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        assert_eq!(files, vec!["2.req"]);
    }

    #[test]
    fn body_write_failure_is_noted_and_the_line_still_written() {
        let temp = TempDir::new("failure");
        let store = Store::open(&temp.0, "s").unwrap();
        fs::remove_dir_all(temp.0.join("bodies")).unwrap();
        store.record(
            exchange(&store, true),
            Bytes::from_static(b"req"),
            Bytes::new(),
        );
        store.flush();
        let recorded = exchanges(&temp.0);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].request.body.file, None);
        assert!(
            recorded[0].notes[0].starts_with("bodies/1.req could not be saved"),
            "{:?}",
            recorded[0].notes
        );
    }

    #[test]
    fn a_torn_append_does_not_swallow_the_next_line() {
        let temp = TempDir::new("torn");
        paths::create_private_dir(&temp.0.join("bodies")).unwrap();
        let path = temp.0.join("events.jsonl");
        let template = Exchange {
            session_id: "s".into(),
            ..Default::default()
        };

        // A failing append (here: a read-only handle) marks the file as possibly torn.
        fs::write(&path, b"").unwrap();
        let mut read_only = File::open(&path).unwrap();
        let mut torn = false;
        let first = Exchange {
            seq: 1,
            ..template.clone()
        };
        write_exchange(&temp.0, &mut read_only, &mut torn, first, b"", b"");
        assert!(torn);

        // What a full disk can leave behind: part of a line.
        fs::write(
            &path,
            b"{\"type\":\"session_start\"}\n{\"type\":\"exchange\",\"se",
        )
        .unwrap();
        let mut events = paths::open_private_append(&path).unwrap();
        let second = Exchange {
            seq: 2,
            ..template.clone()
        };
        write_exchange(&temp.0, &mut events, &mut torn, second, b"", b"");
        assert!(!torn);
        let third = Exchange {
            seq: 3,
            ..template.clone()
        };
        write_exchange(&temp.0, &mut events, &mut torn, third, b"", b"");

        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "no blank lines: {text:?}");
        let seqs: Vec<u64> = lines[2..]
            .iter()
            .map(|line| match serde_json::from_str(line).unwrap() {
                Event::Exchange(exchange) => exchange.seq,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(seqs, vec![2, 3]);

        // A torn flag on a file that already ends cleanly adds no blank line.
        let mut torn = true;
        let fourth = Exchange { seq: 4, ..template };
        write_exchange(&temp.0, &mut events, &mut torn, fourth, b"", b"");
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 5);
        assert!(!fs::read_to_string(&path).unwrap().contains("\n\n"));
    }

    #[test]
    fn open_reports_unusable_paths_as_errors() {
        let temp = TempDir::new("unusable");
        fs::create_dir_all(temp.0.join("events.jsonl")).unwrap();
        assert!(
            Store::open(&temp.0, "s").is_err(),
            "events.jsonl is a directory"
        );

        let file = TempDir::new("file");
        fs::write(&file.0, b"not a directory").unwrap();
        assert!(Store::open(&file.0, "s").is_err(), "session dir is a file");
        let _ = fs::remove_file(&file.0);
    }

    #[test]
    fn store_is_shareable_across_threads_and_tasks() {
        fn assert_shareable<T: Send + Sync + 'static>() {}
        assert_shareable::<Store>();
        assert_shareable::<Arc<Store>>();
    }

    #[test]
    fn reopening_a_file_without_seqs_starts_at_one() {
        let temp = TempDir::new("old");
        paths::create_private_dir(&temp.0).unwrap();
        // v0.1 lines and session starts carry no top-level seq; nested ones do not count.
        let old = b"{\"type\":\"session_start\",\"session_id\":\"s\"}\n{\"method\":\"GET\",\"meta\":{\"seq\":99}}\n";
        fs::write(temp.0.join("events.jsonl"), old).unwrap();
        let store = Store::open(&temp.0, "s").unwrap();
        assert_eq!(store.next_seq(), 1);
        store.record(exchange(&store, true), Bytes::new(), Bytes::new());
        store.flush();
        let text = fs::read_to_string(temp.0.join("events.jsonl")).unwrap();
        assert!(
            text.starts_with(std::str::from_utf8(old).unwrap()),
            "existing lines are kept"
        );
        let parsed: Vec<Event> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        assert!(
            matches!(&parsed[..], [Event::SessionStart(_), Event::Exchange(exchange)] if exchange.seq == 2),
            "{text}"
        );
    }

    #[test]
    fn dropping_the_store_writes_what_was_queued() {
        let temp = TempDir::new("drop");
        let store = Store::open(&temp.0, "s").unwrap();
        for _ in 0..10 {
            store.record(exchange(&store, true), Bytes::new(), Bytes::new());
        }
        drop(store);
        assert_eq!(exchanges(&temp.0).len(), 10);
    }
}

//! Reading a session's capture back: `events.jsonl` and the raw bodies it points to.

use crate::record::{BodyRecord, Exchange};
use std::fs;
use std::io;
use std::path::{Component, Path};

/// Everything readable in a session's `events.jsonl`.
#[derive(Debug, Default)]
pub struct Loaded {
    /// Exchanges in file order.
    pub exchanges: Vec<Exchange>,
    /// Lines that were not valid events (corrupt, or written by an older TAP).
    pub skipped: usize,
}

/// How one `events.jsonl` line was understood.
#[derive(Debug)]
pub enum Line {
    Exchange(Box<Exchange>),
    /// A `session_start` event or a blank line: valid, but not an exchange.
    Ignored,
    /// Corrupt JSON, an unknown event type, or a line written by an older TAP.
    Unreadable,
}

/// Classifies one line of `events.jsonl` (without its trailing newline).
pub fn parse_line(line: &[u8]) -> Line {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Line::Ignored;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
        return Line::Unreadable;
    };
    match value.get("type").and_then(|kind| kind.as_str()) {
        Some("exchange") => match serde_json::from_value::<Exchange>(value) {
            Ok(exchange) => Line::Exchange(Box::new(exchange)),
            Err(_) => Line::Unreadable,
        },
        Some("session_start") => Line::Ignored,
        _ => Line::Unreadable,
    }
}

/// Reads `<session_dir>/events.jsonl`. A missing file is an empty capture. A last line
/// without its newline may still be being written: it is used if it parses, never skipped.
pub fn load(session_dir: &Path) -> io::Result<Loaded> {
    let data = match fs::read(session_dir.join("events.jsonl")) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Loaded::default()),
        Err(error) => return Err(error),
    };
    let end = data
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |end| end + 1);
    let (whole, unfinished) = data.split_at(end);
    let mut loaded = Loaded::default();
    for line in whole.split(|byte| *byte == b'\n') {
        match parse_line(line) {
            Line::Exchange(exchange) => loaded.exchanges.push(*exchange),
            Line::Ignored => {}
            Line::Unreadable => loaded.skipped += 1,
        }
    }
    if let Line::Exchange(exchange) = parse_line(unfinished) {
        loaded.exchanges.push(*exchange);
    }
    Ok(loaded)
}

/// Reads the captured bytes for `body`, or None if nothing was captured.
pub fn body(session_dir: &Path, body: &BodyRecord) -> io::Result<Option<Vec<u8>>> {
    let Some(file) = &body.file else {
        return Ok(None);
    };
    let relative = Path::new(file);
    if !relative
        .components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("body path {file:?} is not inside the session directory"),
        ));
    }
    fs::read(session_dir.join(relative)).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Event, SessionStart};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tap-read-{name}-{}-{}",
            std::process::id(),
            crate::record::unix_ms_now()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bodies")).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = temp_dir("missing");
        let loaded = load(&dir).unwrap();
        assert!(loaded.exchanges.is_empty());
        assert_eq!(loaded.skipped, 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keeps_exchanges_ignores_session_start_and_counts_the_rest() {
        let dir = temp_dir("lines");
        let start = Event::SessionStart(SessionStart {
            session_id: "s".into(),
            at: "2026-10-28T06:29:42.123Z".into(),
            pid: 1,
            version: "0.2.0".into(),
        });
        let exchange = |seq| {
            serde_json::to_string(&Event::Exchange(Exchange {
                seq,
                ..Default::default()
            }))
            .unwrap()
        };
        let lines = [
            serde_json::to_string(&start).unwrap(),
            exchange(1),
            r#"{"type":"request","method":"GET","host":"a","path":"/"}"#.to_string(),
            r#"{"type":"response","method":"GET","host":"a","path":"/","status":200}"#.to_string(),
            r#"{"type":"exchange","seq":"#.to_string(),
            r#"{"type":"exchange","seq":"three"}"#.to_string(),
            "not json".to_string(),
            String::new(),
            exchange(2),
            r#"{"type":"session_start","odd":true}"#.to_string(),
        ];
        fs::write(dir.join("events.jsonl"), lines.join("\n") + "\n").unwrap();
        let loaded = load(&dir).unwrap();
        let seqs: Vec<u64> = loaded.exchanges.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [1, 2]);
        assert_eq!(loaded.skipped, 5);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_line_still_being_written_is_not_counted_as_unreadable() {
        let dir = temp_dir("unfinished");
        let whole = serde_json::to_string(&Event::Exchange(Exchange {
            seq: 1,
            ..Default::default()
        }))
        .unwrap();
        fs::write(
            dir.join("events.jsonl"),
            format!("{whole}\n{}", &whole[..whole.len() / 2]),
        )
        .unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.exchanges.len(), 1);
        assert_eq!(loaded.skipped, 0);

        fs::write(dir.join("events.jsonl"), format!("{whole}\n{whole}")).unwrap();
        assert_eq!(load(&dir).unwrap().exchanges.len(), 2);
        fs::write(dir.join("events.jsonl"), format!("{{\"type\n{whole}\n")).unwrap();
        assert_eq!(load(&dir).unwrap().skipped, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reads_bodies_inside_the_session_only() {
        let dir = temp_dir("body");
        fs::write(dir.join("bodies/1.res"), b"\x00\xffraw").unwrap();
        let record = |file: Option<&str>| BodyRecord {
            file: file.map(String::from),
            ..Default::default()
        };
        assert_eq!(
            body(&dir, &record(Some("bodies/1.res"))).unwrap().unwrap(),
            b"\x00\xffraw"
        );
        assert!(body(&dir, &record(None)).unwrap().is_none());
        assert!(body(&dir, &record(Some("../x"))).is_err());
        assert!(body(&dir, &record(Some("/etc/hosts"))).is_err());
        assert!(body(&dir, &record(Some("bodies/2.res"))).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}

//! Following `events.jsonl` as it grows.

use crate::capture::read::{parse_line, Line};
use crate::record::Exchange;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// Reads whole new lines appended to a file since the last poll.
pub struct Tailer {
    path: PathBuf,
    offset: u64,
    inode: Option<u64>,
    pending: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Polled {
    pub exchanges: Vec<Exchange>,
    pub skipped: usize,
    /// The file shrank or was replaced, so reading started over from the beginning.
    pub restarted: bool,
}

impl Tailer {
    /// Starts at the beginning (`from_start`) or after the last complete line already written.
    pub fn new(path: PathBuf, from_start: bool) -> io::Result<Tailer> {
        let mut tailer = Tailer {
            path,
            offset: 0,
            inode: None,
            pending: Vec::new(),
        };
        if !from_start {
            match File::open(&tailer.path) {
                Ok(mut file) => {
                    let metadata = file.metadata()?;
                    tailer.inode = Some(metadata.ino());
                    tailer.offset = end_of_last_line(&mut file, metadata.len())?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(tailer)
    }

    pub fn poll(&mut self) -> io::Result<Polled> {
        let mut polled = Polled::default();
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.offset > 0 || !self.pending.is_empty() {
                    self.reset();
                    polled.restarted = true;
                }
                return Ok(polled);
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        let replaced = self.inode.is_some_and(|inode| inode != metadata.ino());
        if replaced || metadata.len() < self.offset {
            self.reset();
            polled.restarted = true;
        }
        self.inode = Some(metadata.ino());
        if metadata.len() == self.offset {
            return Ok(polled);
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let read = file.read_to_end(&mut self.pending)?;
        self.offset += read as u64;
        let Some(last_newline) = self.pending.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(polled);
        };
        let rest = self.pending.split_off(last_newline + 1);
        for line in self.pending.split(|byte| *byte == b'\n') {
            match parse_line(line) {
                Line::Exchange(exchange) => polled.exchanges.push(*exchange),
                Line::Ignored => {}
                Line::Unreadable => polled.skipped += 1,
            }
        }
        self.pending = rest;
        Ok(polled)
    }

    fn reset(&mut self) {
        self.offset = 0;
        self.inode = None;
        self.pending.clear();
    }
}

/// Offset just after the last `\n` in the file (0 if the file holds no complete line).
fn end_of_last_line(file: &mut File, len: u64) -> io::Result<u64> {
    const CHUNK: u64 = 64 * 1024;
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let mut buffer = vec![0; (end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buffer)?;
        if let Some(position) = buffer.iter().rposition(|byte| *byte == b'\n') {
            return Ok(start + position as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Event;
    use std::fs;
    use std::io::Write;

    fn line(seq: u64) -> String {
        serde_json::to_string(&Event::Exchange(Exchange {
            seq,
            ..Default::default()
        }))
        .unwrap()
            + "\n"
    }

    fn seqs(polled: &Polled) -> Vec<u64> {
        polled.exchanges.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn follows_appends_partial_lines_and_truncation() {
        let dir = std::env::temp_dir().join(format!(
            "tap-tail-{}-{}",
            std::process::id(),
            crate::record::unix_ms_now()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let first = line(1);
        let second = line(2);
        fs::write(&path, format!("{first}{}", &second[..10])).unwrap();

        let mut fresh = Tailer::new(path.clone(), false).unwrap();
        let mut all = Tailer::new(path.clone(), true).unwrap();
        assert_eq!(seqs(&all.poll().unwrap()), [1]);
        assert!(fresh.poll().unwrap().exchanges.is_empty());

        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&second.as_bytes()[10..]).unwrap();
        file.write_all(b"garbage\n").unwrap();
        let polled = fresh.poll().unwrap();
        assert_eq!(seqs(&polled), [2]);
        assert_eq!(polled.skipped, 1);
        assert_eq!(seqs(&all.poll().unwrap()), [2]);
        assert!(all.poll().unwrap().exchanges.is_empty());

        fs::write(&path, line(7)).unwrap();
        let polled = fresh.poll().unwrap();
        assert!(polled.restarted);
        assert_eq!(seqs(&polled), [7]);

        fs::remove_file(&path).unwrap();
        assert!(fresh.poll().unwrap().restarted);
        fs::write(&path, line(8)).unwrap();
        assert_eq!(seqs(&fresh.poll().unwrap()), [8]);

        let replacement = dir.join("events.new");
        fs::write(
            &replacement,
            format!("{}{}{}", line(20), line(21), line(22)),
        )
        .unwrap();
        fs::rename(&replacement, &path).unwrap();
        let polled = fresh.poll().unwrap();
        assert!(polled.restarted);
        assert_eq!(seqs(&polled), [20, 21, 22]);
        assert_eq!(polled.skipped, 0);
        fs::remove_dir_all(dir).unwrap();
    }
}

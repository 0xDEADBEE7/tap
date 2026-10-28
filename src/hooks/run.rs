//! Runs one hook process: JSON on stdin, stdout and stderr collected, all under a deadline.

use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStderr, ChildStdout, Command};
use tokio::task::JoinHandle;

/// Most a sync hook may print on stdout.
pub const STDOUT_LIMIT: usize = 64 << 20;
/// Stderr kept for failure notes; the rest is drained and dropped.
pub const STDERR_LIMIT: usize = 4 << 10;

/// Runs `command` (argv, no shell) with `input` on stdin and returns its stdout, or a
/// short description of why it failed. With `capture` false, stdout is discarded.
/// Spawning, writing, reading and waiting all happen within `timeout_ms`; when it runs
/// out, the process and anything it started in its process group are killed.
pub async fn run(
    command: &[String],
    timeout_ms: u64,
    input: Vec<u8>,
    capture: bool,
) -> Result<Vec<u8>, String> {
    let deadline = Duration::from_millis(timeout_ms);
    tokio::time::timeout(deadline, run_to_end(command, input, capture))
        .await
        .unwrap_or_else(|_| Err(format!("timed out after {timeout_ms}ms")))
}

async fn run_to_end(command: &[String], input: Vec<u8>, capture: bool) -> Result<Vec<u8>, String> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| "has an empty command".to_string())?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("could not start: {error}"))?;
    // Locals drop in reverse order: the writer is aborted, then the group is killed
    // (while the child is still unreaped, so its pid cannot have been reused), then
    // the child itself is killed.
    let mut group = KillGroup(child.id());
    let _writer = child.stdin.take().map(|mut stdin| {
        AbortOnDrop(tokio::spawn(async move {
            // A hook may exit without reading its input; the broken pipe is not an error.
            let _ = stdin.write_all(&input).await;
        }))
    });
    let (stdout, stderr) = tokio::try_join!(
        read_stdout(child.stdout.take()),
        read_stderr(child.stderr.take())
    )?;
    let status = child
        .wait()
        .await
        .map_err(|error| format!("could not wait for it: {error}"))?;
    group.0 = None;
    if status.success() {
        Ok(stdout)
    } else {
        Err(exit_failure(status, &stderr))
    }
}

async fn read_stdout(pipe: Option<ChildStdout>) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    if let Some(pipe) = pipe {
        pipe.take(STDOUT_LIMIT as u64 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|error| format!("could not read its output: {error}"))?;
    }
    if output.len() > STDOUT_LIMIT {
        return Err(format!("printed more than {} MiB", STDOUT_LIMIT >> 20));
    }
    Ok(output)
}

async fn read_stderr(pipe: Option<ChildStderr>) -> Result<Vec<u8>, String> {
    let mut kept = Vec::new();
    if let Some(mut pipe) = pipe {
        let _ = (&mut pipe)
            .take(STDERR_LIMIT as u64)
            .read_to_end(&mut kept)
            .await;
        let _ = tokio::io::copy(&mut pipe, &mut tokio::io::sink()).await;
    }
    Ok(kept)
}

fn exit_failure(status: ExitStatus, stderr: &[u8]) -> String {
    let mut reason = match (status.code(), status.signal()) {
        (Some(code), _) => format!("exited with status {code}"),
        (None, Some(signal)) => format!("was killed by signal {signal}"),
        (None, None) => format!("failed ({status})"),
    };
    let stderr = String::from_utf8_lossy(stderr);
    if let Some(line) = stderr.lines().map(str::trim).find(|line| !line.is_empty()) {
        reason.push_str(": ");
        // Notes end up on terminals (`tap show`), so escape sequences are dropped.
        reason.extend(line.chars().filter(|c| !c.is_control()).take(200));
    }
    reason
}

/// Kills the hook's process group on drop unless the hook was waited for.
struct KillGroup(Option<u32>);

impl Drop for KillGroup {
    fn drop(&mut self) {
        if let Some(pgid) = self.0.and_then(|pid| libc::pid_t::try_from(pid).ok()) {
            // SAFETY: killpg only sends a signal. The group id is the pid of our own
            // child, which has not been reaped, so it still names that group.
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

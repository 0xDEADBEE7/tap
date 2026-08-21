use std::io;
use std::process::Command;

pub fn list() -> io::Result<()> {
    println!("PID\tADDRESS");
    let output = Command::new("ps")
        .args(["-ax", "-o", "pid=", "-o", "command="])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("ps failed"));
    }

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((pid, command)) = line.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        if !is_proxy_command(command) {
            continue;
        }
        let address = listen_address(command).unwrap_or("127.0.0.1:8080");
        println!("{}\t{address}", pid.trim());
    }
    Ok(())
}

fn is_proxy_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    words
        .next()
        .is_some_and(|executable| executable.rsplit('/').next() == Some("tap"))
        && words.next() == Some("proxy")
}

fn listen_address(command: &str) -> Option<&str> {
    let mut words = command.split_whitespace();
    while let Some(word) = words.next() {
        if word == "--listen" {
            return words.next();
        }
    }
    None
}

fn process_matches(pid: i32) -> io::Result<bool> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(is_proxy_command))
}

pub fn kill(args: Vec<String>) -> io::Result<()> {
    let pid = args
        .first()
        .ok_or_else(|| invalid("usage: tap kill PID"))?
        .parse::<i32>()
        .map_err(|_| invalid("PID must be a number"))?;
    if pid <= 0 {
        return Err(invalid("PID must be positive"));
    }
    if !process_matches(pid)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no TAP proxy found for PID {pid}"),
        ));
    }
    let status = unsafe { libc_kill(pid) };
    if status == 0 {
        println!("killed {pid}");
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
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

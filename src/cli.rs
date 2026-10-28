//! Command-line parsing. Each command checks its arguments and hands off to `session`.

use crate::session::{self, CreateOptions};
use std::env;
use std::io;

pub fn run() -> io::Result<()> {
    let args = env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|arg| invalid(format!("argument {arg:?} is not valid UTF-8")))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let Some((command, rest)) = args.split_first() else {
        print_usage();
        return Ok(());
    };
    match command.as_str() {
        "create" => session::create(parse_create(rest)?),
        "start" => match rest {
            [selector] => session::start(selector),
            [] => Err(invalid(
                "start requires a SESSION (id, label or id prefix); see tap list",
            )),
            _ => Err(too_many("start")),
        },
        "stop" => session::stop(optional_selector(rest, "stop")?),
        "list" => {
            let mut table = false;
            for arg in rest {
                match arg.as_str() {
                    "--table" => table = true,
                    "--json" => table = false,
                    other => return Err(unknown_option("list", other)),
                }
            }
            session::list(table)
        }
        "delete" => {
            let mut force = false;
            let mut selectors = Vec::new();
            for arg in rest {
                match arg.as_str() {
                    "--force" | "-f" => force = true,
                    other if other.starts_with("--") => {
                        return Err(unknown_option("delete", other))
                    }
                    other => selectors.push(other),
                }
            }
            match selectors.as_slice() {
                [selector] => session::delete(selector, force),
                [] => Err(invalid(
                    "delete requires a SESSION (id, label or id prefix); see tap list",
                )),
                _ => Err(too_many("delete")),
            }
        }
        "show" => session::show(rest),
        "tail" => session::tail(rest),
        "env" => {
            let mut as_json = false;
            let mut selectors = Vec::new();
            for arg in rest {
                match arg.as_str() {
                    "--json" => as_json = true,
                    other if other.starts_with("--") => return Err(unknown_option("env", other)),
                    other => selectors.push(other.to_string()),
                }
            }
            session::env(optional_selector(&selectors, "env")?, as_json)
        }
        "exec" => {
            let Some(separator) = rest.iter().position(|arg| arg == "--") else {
                return Err(invalid(
                    "usage: tap exec [SESSION] -- CMD [ARGS...] (the -- is required)",
                ));
            };
            let selector = optional_selector(&rest[..separator], "exec")?;
            let command = &rest[separator + 1..];
            if command.is_empty() {
                return Err(invalid(
                    "usage: tap exec [SESSION] -- CMD [ARGS...]: CMD is missing",
                ));
            }
            let code = session::exec(selector, command)?;
            std::process::exit(code)
        }
        "ca" => match rest {
            [] => session::ca(false),
            [flag] if flag == "--path" => session::ca(true),
            [other] => Err(unknown_option("ca", other)),
            _ => Err(too_many("ca")),
        },
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "__run" => match rest {
            [id] => session::run(id.clone()),
            _ => Err(invalid("__run requires exactly one session id")),
        },
        other => Err(invalid(format!("unknown command '{other}'; run tap help"))),
    }
}

fn parse_create(args: &[String]) -> io::Result<CreateOptions> {
    let mut options = CreateOptions::default();
    let mut port = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") {
            if port.replace(arg.clone()).is_some() {
                return Err(invalid("create takes one PORT; run tap help"));
            }
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_string())),
            None => (arg.as_str(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| args.next().cloned())
                .ok_or_else(|| invalid(format!("{flag} requires a value")))
        };
        match flag {
            "--label" => set_once(&mut options.label, value()?, flag)?,
            "--upstream" => set_once(&mut options.upstream, value()?, flag)?,
            "--filter" => options.filters.push(value()?),
            "--tunnel" => options.tunnel.push(value()?),
            "--max-body" => {
                let size = parse_size(&value()?)?;
                set_once(&mut options.max_body, size, flag)?;
            }
            "--no-intercept" if inline.is_none() => options.no_intercept = true,
            "--no-intercept" => return Err(invalid("--no-intercept takes no value")),
            other => return Err(unknown_option("create", other)),
        }
    }
    options.port = port.ok_or_else(|| invalid("create requires a PORT, e.g. tap create 8080"))?;
    Ok(options)
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> io::Result<()> {
    if slot.replace(value).is_some() {
        return Err(invalid(format!("{flag} given more than once")));
    }
    Ok(())
}

/// Parses a byte count: `1048576`, `512KB`, `10MB`, `1GB` (K/M/G = 1024-based; `KiB` etc. accepted).
fn parse_size(text: &str) -> io::Result<u64> {
    let bad = || {
        invalid(format!(
            "invalid size '{text}'; use bytes or a KB/MB/GB suffix, e.g. 512KB or 10MB"
        ))
    };
    let trimmed = text.trim();
    let digits = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let number = trimmed[..digits].parse::<u64>().map_err(|_| bad())?;
    let multiplier: u64 = match trimmed[digits..].trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => return Err(bad()),
    };
    number.checked_mul(multiplier).ok_or_else(bad)
}

fn optional_selector<'a>(args: &'a [String], command: &str) -> io::Result<Option<&'a str>> {
    match args {
        [] => Ok(None),
        [selector] if selector.starts_with("--") => Err(unknown_option(command, selector)),
        [selector] => Ok(Some(selector)),
        _ => Err(too_many(command)),
    }
}

fn print_usage() {
    println!(
        "\
tap - Traffic Access Proxy: see exactly what software on this machine sends over HTTP(S).

usage:
  tap create PORT [--label NAME] [--upstream URL] [--filter SPEC]... [--tunnel HOST]...
                  [--no-intercept] [--max-body BYTES]
  tap start  SESSION                 start the session's proxy in the background
  tap stop   [SESSION]               stop it (SIGTERM, then SIGKILL after 5s)
  tap list   [--table]               all sessions (JSON, or a table)
  tap delete SESSION [--force]       remove a session and its captures (--force stops it first)
  tap show   [SESSION] [N | FILTER...] [options]   inspect recorded exchanges
  tap tail   [SESSION] [FILTER...] [options]       follow new exchanges
  tap env    [SESSION] [--json]      print `export ...` lines that route a shell through the session
  tap exec   [SESSION] -- CMD [ARGS...]   run CMD routed through the session
  tap ca     [--path]                create/show the local CA and how clients trust it
  tap help

SESSION is a full id, a label, or a unique id prefix of at least 4 characters. When it is
omitted, the single running session is used. create/start/stop/list/delete print JSON.

create options:
  --label NAME      a unique name to use instead of the id
  --upstream URL    forward origin-form requests (POST /v1/messages) to this base URL, so a
                    client can point its base URL at http://127.0.0.1:PORT
  --filter SPEC     record only matching exchanges (repeatable; specs are OR-ed); filters
                    never block traffic
  --tunnel HOST     host regex whose CONNECT tunnels are relayed without decrypting (repeatable)
  --no-intercept    never decrypt HTTPS; every CONNECT is relayed as an opaque tunnel
  --max-body BYTES  per-body capture limit (default 16MB; accepts KB/MB/GB suffixes)

filters:
  SPEC is condition[,condition...] (AND-ed); a condition is [!]KEY=VALUE.
  KEY: method scheme host port path url mode status header:NAME (case-insensitive).
  Values are literal unless they contain a regex metacharacter (^$|?*+()[]{{}}\\) or start with ~.
  host matches subdomains, path is a prefix, url a substring, status accepts 4xx/50x.
  e.g. host=anthropic.com,path=/v1/messages   !host=telemetry.example.com   status=5xx

examples:
  tap create 8080 --label claude
  tap start claude
  tap exec claude -- curl https://api.anthropic.com/v1/models
  eval \"$(tap env claude)\"
  tap show claude
  tap create 8081 --label api --upstream https://api.anthropic.com
"
    );
    let viewer = crate::view::usage();
    if !viewer.trim().is_empty() {
        println!("show/tail:\n{}", viewer.trim_end());
    }
}

fn too_many(command: &str) -> io::Error {
    invalid(format!("too many arguments for {command}; run tap help"))
}

fn unknown_option(command: &str, option: &str) -> io::Error {
    invalid(format!(
        "unknown option '{option}' for {command}; run tap help"
    ))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("512KB").unwrap(), 512 * 1024);
        assert_eq!(parse_size("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("10mb").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("2 GiB").unwrap(), 2 << 30);
        for bad in ["", "MB", "10XB", "1.5MB", "-1", "99999999999999999999GB"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_create_flags() {
        let options = parse_create(&strings(&[
            "--label=api",
            "8080",
            "--filter",
            "host=a.com",
            "--filter",
            "status=5xx",
            "--tunnel",
            "apple\\.com$",
            "--no-intercept",
            "--max-body",
            "1MB",
            "--upstream",
            "https://api.anthropic.com",
        ]))
        .unwrap();
        assert_eq!(options.port, "8080");
        assert_eq!(options.label.as_deref(), Some("api"));
        assert_eq!(options.filters, ["host=a.com", "status=5xx"]);
        assert_eq!(options.tunnel, ["apple\\.com$"]);
        assert!(options.no_intercept);
        assert_eq!(options.max_body, Some(1 << 20));
        assert_eq!(
            options.upstream.as_deref(),
            Some("https://api.anthropic.com")
        );
    }

    #[test]
    fn rejects_bad_create_arguments() {
        for args in [
            &[][..],
            &["8080", "8081"][..],
            &["8080", "--label"][..],
            &["8080", "--bogus"][..],
            &["8080", "--label", "a", "--label", "b"][..],
            &["8080", "--no-intercept=yes"][..],
        ] {
            assert!(parse_create(&strings(args)).is_err(), "{args:?}");
        }
    }
}

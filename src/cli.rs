use crate::intercept::HookSpec;
use std::env;
use std::io;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub filters: Vec<String>,
    pub on_request: Vec<HookSpec>,
    pub on_response: Vec<HookSpec>,
    pub on_event: Vec<HookSpec>,
    pub session_id: Option<String>,
    pub events_path: Option<PathBuf>,
    pub json: bool,
}

pub fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("create") => {
            let port = next_arg(&mut args, "port")?;
            no_extra_args(&mut args)?;
            crate::session::create(port)
        }
        Some("start") => {
            let id = next_arg(&mut args, "id")?;
            no_extra_args(&mut args)?;
            crate::session::start(id)
        }
        Some("stop") => {
            let id = next_arg(&mut args, "id")?;
            no_extra_args(&mut args)?;
            crate::session::stop(id)
        }
        Some("list") => {
            let table = match args.next().as_deref() {
                None => false,
                Some("--table") => true,
                Some(_) => return Err(invalid("list accepts only --table")),
            };
            no_extra_args(&mut args)?;
            crate::session::list(table)
        }
        Some("__run") => crate::session::run(next_arg(&mut args, "id")?),
        Some("help") | None => {
            print_usage();
            Ok(())
        }
        Some(command) => Err(invalid(&format!("unknown command: {command}"))),
    }
}

fn print_usage() {
    println!("usage: tap create PORT | start ID | stop ID | list [--table]");
}

fn no_extra_args(args: &mut impl Iterator<Item = String>) -> io::Result<()> {
    if args.next().is_some() {
        return Err(invalid("too many arguments"));
    }
    Ok(())
}

fn next_arg(args: &mut impl Iterator<Item = String>, name: &str) -> io::Result<String> {
    args.next()
        .ok_or_else(|| invalid(&format!("{name} requires a value")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

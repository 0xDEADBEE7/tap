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
        Some("create") => crate::session::create(next_arg(&mut args, "port")?),
        Some("start") => crate::session::start(next_arg(&mut args, "id")?),
        Some("stop") => crate::session::stop(next_arg(&mut args, "id")?),
        Some("list") => crate::session::list(),
        Some("__run") => crate::session::run(next_arg(&mut args, "id")?),
        Some("proxy") => crate::proxy::listener::run(parse_proxy(args)?),
        Some("cert") => cert(args.collect()),
        _ => {
            eprintln!("usage: tap create PORT | start ID | stop ID | list");
            Ok(())
        }
    }
}

fn parse_proxy(mut args: impl Iterator<Item = String>) -> io::Result<Config> {
    let mut config = Config {
        listen: "127.0.0.1:8080".into(),
        filters: Vec::new(),
        on_request: Vec::new(),
        on_response: Vec::new(),
        on_event: Vec::new(),
        session_id: None,
        events_path: None,
        json: false,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => config.listen = next_arg(&mut args, "--listen")?,
            "--filter" => config.filters.push(next_arg(&mut args, "--filter")?),
            "--host" => config.filters.push(format!("host={}", next_arg(&mut args, "--host")?)),
            "--match" => config.filters.push(format!("path={}", next_arg(&mut args, "--match")?)),
            "--json" => config.json = true,
            _ => return Err(invalid("unknown proxy option")),
        }
    }
    Ok(config)
}

fn cert(args: Vec<String>) -> io::Result<()> {
    let ca = crate::tls::Ca::from_home()?;
    match args.first().map(String::as_str) {
        Some("path") => println!("{}", ca.path().display()),
        Some("init") => {
            ca.init()?;
            println!("created {}", ca.path().display());
        }
        _ => return Err(invalid("usage: tap cert init|path")),
    };
    Ok(())
}
fn next_arg(args: &mut impl Iterator<Item = String>, name: &str) -> io::Result<String> {
    args.next()
        .ok_or_else(|| invalid(&format!("{name} requires a value")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

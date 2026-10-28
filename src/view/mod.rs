//! The human viewer: `tap show` (list, one exchange, raw bodies, curl) and `tap tail`.

pub mod args;
pub mod detail;
pub mod list;
pub mod render;
pub mod tail;
pub mod term;

#[cfg(test)]
mod tests;

use crate::capture::read;
use crate::filter::{Facts, FilterSet};
use crate::record::{Event, Exchange};
use args::{ShowArgs, TailArgs};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use term::Style;

/// How output should look on this stdout.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Term {
    pub style: Style,
    /// Terminal width; None means never truncate.
    pub width: Option<usize>,
}

impl Term {
    fn detect(no_color: bool) -> Term {
        Term {
            style: Style::detect(no_color),
            width: term::terminal_width(),
        }
    }
}

/// `tap show SESSION [ARGS...]`. `session` is the name suggested commands use (the
/// label, or the id); `args` are everything after the session selector, and the
/// viewer owns their syntax (see [`usage`]).
pub fn show_command(session_dir: &Path, session: &str, args: &[String]) -> io::Result<()> {
    let args = args::parse_show(args).map_err(usage_error)?;
    if args.help {
        println!("{}", usage());
        return Ok(());
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    quiet_broken_pipe(show(
        session_dir,
        session,
        &args,
        &mut out,
        Term::detect(args.no_color),
    ))
}

/// `tap tail SESSION [ARGS...]`: prints new exchanges as they are recorded until interrupted.
pub fn tail_command(session_dir: &Path, args: &[String]) -> io::Result<()> {
    let args = args::parse_tail(args).map_err(usage_error)?;
    if args.help {
        println!("{}", usage());
        return Ok(());
    }
    quiet_broken_pipe(follow(session_dir, &args))
}

/// Help text for the show/tail arguments, included in `tap help`.
pub fn usage() -> &'static str {
    "\
tap show [SESSION] [FILTER...] [--last K] [--json] [--no-color]
    list recorded exchanges: # TIME METHOD STATUS DURATION SIZE URL
tap show [SESSION] N [--full | --json | --body req|res | --curl] [--no-color]
    exchange #N: headers and bodies, decoded (gzip/deflate/br) and pretty-printed;
    event streams are listed event by event with the streamed text assembled
  FILTER          key=value[,key=value...]   comma = AND, several filters = OR
                  keys: method scheme host port path url mode status header:NAME
                  !key=value negates; ~value (or a value with regex characters) is a regex
  --last K        only the last K matching exchanges
  --json          records as JSON: one line each, or pretty-printed for one exchange
  --full          do not cut long bodies (over 200 lines, or lines over 2000 characters)
  --body req|res  write the raw captured body bytes to stdout (not decoded)
  --curl          print a curl command that sends the request again
  --no-color      no colour (also when NO_COLOR is set or stdout is not a terminal)
tap tail [SESSION] [FILTER...] [--all] [--json] [--no-color]
    print exchanges as they are recorded, until Ctrl-C; --all prints earlier ones first

examples:
  tap show work host=anthropic.com,status=4xx
  tap show work 12
  tap show work 12 --body res > response.bin
  tap tail work host=api.openai.com"
}

fn usage_error(message: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{message}\n\n{}", usage()),
    )
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn quiet_broken_pipe(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

fn matching<'a>(filters: &FilterSet, exchanges: &'a [Exchange]) -> Vec<&'a Exchange> {
    exchanges
        .iter()
        .filter(|exchange| filters.matches(&Facts::exchange(exchange)))
        .collect()
}

pub(crate) fn show(
    session_dir: &Path,
    session: &str,
    args: &ShowArgs,
    out: &mut dyn Write,
    term: Term,
) -> io::Result<()> {
    let filters = FilterSet::parse(&args.filters).map_err(invalid)?;
    let mut loaded = read::load(session_dir)?;
    loaded.exchanges.sort_by_key(|exchange| exchange.seq);
    match args.seq {
        Some(seq) => show_one(session_dir, session, &loaded, seq, args, out, term),
        None => show_list(session_dir, session, &loaded, &filters, args, out, term),
    }
}

fn show_list(
    session_dir: &Path,
    session: &str,
    loaded: &read::Loaded,
    filters: &FilterSet,
    args: &ShowArgs,
    out: &mut dyn Write,
    term: Term,
) -> io::Result<()> {
    let mut shown = matching(filters, &loaded.exchanges);
    if let Some(last) = args.last {
        shown.drain(..shown.len().saturating_sub(last));
    }
    if args.json {
        for exchange in &shown {
            writeln!(out, "{}", to_json_line(exchange)?)?;
        }
        if loaded.skipped > 0 {
            eprintln!(
                "tap: {} unreadable line{} skipped",
                loaded.skipped,
                if loaded.skipped == 1 { "" } else { "s" }
            );
        }
        return Ok(());
    }
    if loaded.exchanges.is_empty() {
        writeln!(
            out,
            "{}",
            list::empty_message(session, session_dir, loaded.skipped)
        )?;
        return Ok(());
    }
    if shown.is_empty() {
        writeln!(out, "No exchange matches {}.", args.filters.join(" or "))?;
    } else {
        for line in list::table(&shown, term.width, term.style) {
            writeln!(out, "{line}")?;
        }
    }
    writeln!(
        out,
        "{}",
        term.style.dim(&list::footer(
            shown.len(),
            loaded.exchanges.len(),
            loaded.skipped
        ))
    )?;
    Ok(())
}

fn show_one(
    session_dir: &Path,
    session: &str,
    loaded: &read::Loaded,
    seq: u64,
    args: &ShowArgs,
    out: &mut dyn Write,
    term: Term,
) -> io::Result<()> {
    let Some(exchange) = loaded
        .exchanges
        .iter()
        .rev()
        .find(|exchange| exchange.seq == seq)
    else {
        let known = match (loaded.exchanges.first(), loaded.exchanges.last()) {
            (Some(first), Some(last)) if (first.seq..last.seq).contains(&seq) => format!(
                "#{seq} was not recorded: it was outside the session's filters or has not finished yet"
            ),
            (Some(first), Some(last)) if first.seq == last.seq => {
                format!("it has only #{}", first.seq)
            }
            (Some(first), Some(last)) => format!("it has #{} to #{}", first.seq, last.seq),
            _ => "nothing has been recorded yet".to_string(),
        };
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no exchange #{seq} in session {session} ({known}; list them: tap show {session})"
            ),
        ));
    };
    if let Some(side) = args.body {
        let refuse_binary = term.width.is_some();
        if let Some(note) =
            detail::write_raw_body(session_dir, session, exchange, side, refuse_binary, out)?
        {
            eprintln!("{note}");
        }
        return Ok(());
    }
    if args.curl {
        let command = detail::curl(session_dir, exchange).map_err(invalid)?;
        return writeln!(out, "{command}");
    }
    if args.json {
        let event = Event::Exchange(exchange.clone());
        let text = serde_json::to_string_pretty(&event).map_err(io::Error::other)?;
        return writeln!(out, "{text}");
    }
    let options = detail::DetailOptions {
        session,
        full: args.full,
        style: term.style,
    };
    writeln!(out, "{}", detail::detail(session_dir, exchange, &options))
}

fn to_json_line(exchange: &Exchange) -> io::Result<String> {
    serde_json::to_string(&Event::Exchange(exchange.clone())).map_err(io::Error::other)
}

fn follow(session_dir: &Path, args: &TailArgs) -> io::Result<()> {
    let filters = FilterSet::parse(&args.filters).map_err(invalid)?;
    let style = Style::detect(args.no_color);
    let columns = list::Columns::streaming();
    let mut tailer = tail::Tailer::new(session_dir.join("events.jsonl"), args.all)?;
    eprintln!("watching {} — Ctrl-C to stop", session_dir.display());
    if !args.json {
        eprintln!("{}", list::header_line(&columns, style));
    }
    let stdout = io::stdout();
    let mut first = true;
    loop {
        let mut polled = tailer.poll()?;
        if polled.restarted && !first {
            eprintln!("tap: events.jsonl was truncated or replaced; reading it from the start");
        }
        if first {
            polled.exchanges.sort_by_key(|exchange| exchange.seq);
            first = false;
        }
        if polled.skipped > 0 {
            eprintln!(
                "tap: skipped {} unreadable line{}",
                polled.skipped,
                if polled.skipped == 1 { "" } else { "s" }
            );
        }
        let width = term::terminal_width();
        let mut out = stdout.lock();
        for exchange in polled
            .exchanges
            .iter()
            .filter(|exchange| filters.matches(&Facts::exchange(exchange)))
        {
            if args.json {
                writeln!(out, "{}", to_json_line(exchange)?)?;
            } else {
                let cells = list::Cells::of(exchange, false);
                writeln!(
                    out,
                    "{}",
                    list::row_line(&cells, exchange, &columns, width, style)
                )?;
            }
            out.flush()?;
        }
        drop(out);
        if !session_dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} was removed; stopped watching", session_dir.display()),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

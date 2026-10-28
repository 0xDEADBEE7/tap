//! The one-row-per-exchange list used by `tap show S` and `tap tail`.

use super::term::{duration, sanitize_line, size, truncate, LocalTime, Style};
use crate::record::{Exchange, Mode};

const GAP: &str = "  ";
const HEADERS: [&str; 7] = ["#", "TIME", "METHOD", "STATUS", "DURATION", "SIZE", "URL"];
const ERROR_WIDTH: usize = 60;

/// The text of one row, before padding and colour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cells {
    pub seq: String,
    pub time: String,
    pub method: String,
    pub status: String,
    pub duration: String,
    pub size: String,
    pub url: String,
    /// Already shortened; shown after the URL as ` — <error>`.
    pub error: Option<String>,
}

impl Cells {
    pub fn of(exchange: &Exchange, with_date: bool) -> Cells {
        let local = LocalTime::from_unix_ms(exchange.started_unix_ms);
        let time = if with_date {
            format!("{} {}", local.date(), local.time())
        } else {
            local.time()
        };
        let tunnel = exchange.mode == Mode::Tunnel || exchange.tunnel.is_some();
        let status = match exchange.status() {
            _ if exchange.error.is_some() => "ERR".to_string(),
            _ if exchange.mode == Mode::Tunnel => "TUN".to_string(),
            Some(status) => status.to_string(),
            None if tunnel => "TUN".to_string(),
            None => "-".to_string(),
        };
        let body_size = match (&exchange.tunnel, &exchange.response) {
            (Some(stats), _) => format!(
                "↑{} ↓{}",
                size(stats.bytes_up, ""),
                size(stats.bytes_down, "")
            ),
            (None, Some(response)) => size(response.body.size, ""),
            (None, None) => "-".to_string(),
        };
        let method = if exchange.request.method.is_empty() && tunnel {
            "CONNECT".to_string()
        } else {
            sanitize_line(&exchange.request.method)
        };
        Cells {
            seq: exchange.seq.to_string(),
            time,
            method,
            status,
            duration: exchange
                .duration_ms
                .map_or_else(|| "-".to_string(), duration),
            size: body_size,
            url: sanitize_line(&exchange.request.url),
            error: exchange.error.as_deref().map(short_error),
        }
    }
}

/// First line of an error, whitespace collapsed, at most 60 characters.
pub fn short_error(error: &str) -> String {
    let first = error
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let collapsed = first.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate(&sanitize_line(&collapsed), ERROR_WIDTH)
}

/// Column widths (characters) for every column but the last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Columns {
    pub seq: usize,
    pub time: usize,
    pub method: usize,
    pub status: usize,
    pub duration: usize,
    pub size: usize,
}

impl Columns {
    /// Fixed widths for rows printed one at a time (`tap tail`).
    pub fn streaming() -> Columns {
        Columns {
            seq: 4,
            time: 12,
            method: 7,
            status: 6,
            duration: 8,
            // Wide enough for a tunnel's "↑4.2KB ↓18.5KB".
            size: 14,
        }
    }

    /// Widths that fit the header and every row.
    pub fn fit(rows: &[Cells]) -> Columns {
        let width = |header: &str, cell: fn(&Cells) -> &str| {
            rows.iter()
                .map(|row| cell(row).chars().count())
                .chain([header.chars().count()])
                .max()
                .unwrap_or(0)
        };
        Columns {
            seq: width(HEADERS[0], |row| &row.seq),
            time: width(HEADERS[1], |row| &row.time),
            method: width(HEADERS[2], |row| &row.method),
            status: width(HEADERS[3], |row| &row.status),
            duration: width(HEADERS[4], |row| &row.duration),
            size: width(HEADERS[5], |row| &row.size),
        }
    }

    fn prefix_width(&self) -> usize {
        self.seq + self.time + self.method + self.status + self.duration + self.size + GAP.len() * 6
    }
}

fn pad_left(text: &str, width: usize) -> String {
    let fill = width.saturating_sub(text.chars().count());
    format!("{}{text}", " ".repeat(fill))
}

fn pad_right(text: &str, width: usize) -> String {
    let fill = width.saturating_sub(text.chars().count());
    format!("{text}{}", " ".repeat(fill))
}

/// The column titles, aligned like the rows.
pub fn header_line(columns: &Columns, style: Style) -> String {
    let line = [
        pad_left(HEADERS[0], columns.seq),
        pad_right(HEADERS[1], columns.time),
        pad_right(HEADERS[2], columns.method),
        pad_right(HEADERS[3], columns.status),
        pad_left(HEADERS[4], columns.duration),
        pad_left(HEADERS[5], columns.size),
        HEADERS[6].to_string(),
    ]
    .join(GAP);
    style.dim(&line)
}

/// One aligned row. `width` is the terminal width; None means never truncate.
pub fn row_line(
    cells: &Cells,
    exchange: &Exchange,
    columns: &Columns,
    width: Option<usize>,
    style: Style,
) -> String {
    let suffix = cells
        .error
        .as_ref()
        .map(|error| format!(" — {error}"))
        .unwrap_or_default();
    let (url, suffix) = match width {
        Some(width) => fit_url(
            &cells.url,
            &suffix,
            width.saturating_sub(columns.prefix_width()),
        ),
        None => (cells.url.clone(), suffix),
    };
    let status = pad_right(&cells.status, columns.status);
    [
        pad_left(&cells.seq, columns.seq),
        pad_right(&cells.time, columns.time),
        pad_right(&cells.method, columns.method),
        style.status(exchange.status(), exchange.error.is_some(), &status),
        pad_left(&cells.duration, columns.duration),
        pad_left(&cells.size, columns.size),
        format!("{url}{}", style.red(&suffix)),
    ]
    .join(GAP)
    .trim_end()
    .to_string()
}

/// Shortens `url` + `suffix` to `available` characters, keeping room for the error when possible.
fn fit_url(url: &str, suffix: &str, available: usize) -> (String, String) {
    let available = available.max(20);
    let url_len = url.chars().count();
    let suffix_len = suffix.chars().count();
    if url_len + suffix_len <= available {
        return (url.to_string(), suffix.to_string());
    }
    let url_room = available
        .saturating_sub(suffix_len)
        .max(available / 2)
        .min(url_len);
    let url = truncate(url, url_room);
    let suffix = truncate(suffix, available.saturating_sub(url.chars().count()));
    (url, suffix)
}

/// True when the exchanges were recorded on more than one local date.
pub fn spans_days(exchanges: &[&Exchange]) -> bool {
    let mut dates = exchanges
        .iter()
        .map(|exchange| LocalTime::from_unix_ms(exchange.started_unix_ms).date());
    let Some(first) = dates.next() else {
        return false;
    };
    dates.any(|date| date != first)
}

/// Header, rows and nothing else (the caller adds the footer).
pub fn table(exchanges: &[&Exchange], width: Option<usize>, style: Style) -> Vec<String> {
    let with_date = spans_days(exchanges);
    let cells: Vec<Cells> = exchanges
        .iter()
        .map(|exchange| Cells::of(exchange, with_date))
        .collect();
    let columns = Columns::fit(&cells);
    let mut lines = vec![header_line(&columns, style)];
    lines.extend(
        cells
            .iter()
            .zip(exchanges)
            .map(|(cells, exchange)| row_line(cells, exchange, &columns, width, style)),
    );
    lines
}

/// `3 of 12 exchanges (2 unreadable lines skipped)`
pub fn footer(shown: usize, total: usize, skipped: usize) -> String {
    let mut line = format!(
        "{shown} of {total} exchange{}",
        if total == 1 { "" } else { "s" }
    );
    if skipped > 0 {
        line.push_str(&format!(
            " ({skipped} unreadable line{} skipped)",
            if skipped == 1 { "" } else { "s" }
        ));
    }
    line
}

/// What to say when a session has recorded nothing yet.
pub fn empty_message(session: &str, session_dir: &std::path::Path, skipped: usize) -> String {
    let mut message = format!(
        "No exchanges recorded yet in {}.\n\
         \n\
         \x20 Is the session running?          tap list   (start it: tap start {session})\n\
         \x20 Is the client using the proxy?   tap exec {session} -- curl https://example.com\n\
         \x20                                  or, in the client's shell: eval \"$(tap env {session})\"\n\
         \x20 Watch traffic arrive:            tap tail {session}",
        session_dir.display()
    );
    if skipped > 0 {
        message.push_str(&format!(
            "\n\n({skipped} unreadable line{} skipped: corrupt, or written by an older TAP)",
            if skipped == 1 { "" } else { "s" }
        ));
    }
    message
}

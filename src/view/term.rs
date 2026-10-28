//! Terminal facts (colour, width), local time and the small formatters shared by the views.

use std::io::{self, IsTerminal};

/// ANSI styling, or none at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn plain() -> Style {
        Style { color: false }
    }

    /// Colour only when stdout is a terminal, `NO_COLOR` is unset or empty (no-color.org)
    /// and `--no-color` was not given.
    pub fn detect(no_color: bool) -> Style {
        Style {
            color: !no_color
                && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
                && io::stdout().is_terminal(),
        }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color && !text.is_empty() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    pub fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    pub fn red(self, text: &str) -> String {
        self.paint("31", text)
    }

    /// Green 2xx, cyan 3xx, yellow 4xx, red 5xx and errors.
    pub fn status(self, status: Option<u16>, failed: bool, text: &str) -> String {
        let code = match (failed, status) {
            (true, _) => "31",
            (false, Some(200..=299)) => "32",
            (false, Some(300..=399)) => "36",
            (false, Some(400..=499)) => "33",
            (false, Some(500..)) => "31",
            _ => return text.to_string(),
        };
        self.paint(code, text)
    }
}

/// Columns available on stdout, or None when stdout is not a terminal (never truncate then).
pub fn terminal_width() -> Option<usize> {
    if !io::stdout().is_terminal() {
        return None;
    }
    // SAFETY: TIOCGWINSZ fills a winsize struct we own; a failure leaves it zeroed.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    if ok && size.ws_col > 0 {
        return Some(usize::from(size.ws_col));
    }
    let columns = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|columns| *columns > 0);
    Some(columns.unwrap_or(120))
}

/// A wall-clock time in the local time zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub millis: u32,
}

impl LocalTime {
    pub fn from_unix_ms(unix_ms: u64) -> LocalTime {
        let seconds = (unix_ms / 1000) as libc::time_t;
        let millis = (unix_ms % 1000) as u32;
        // SAFETY: localtime_r writes only into the tm we pass and returns null on failure.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let converted = unsafe { !libc::localtime_r(&seconds, &mut tm).is_null() };
        if converted {
            return LocalTime {
                year: tm.tm_year + 1900,
                month: (tm.tm_mon + 1) as u32,
                day: tm.tm_mday as u32,
                hour: tm.tm_hour as u32,
                minute: tm.tm_min as u32,
                second: tm.tm_sec as u32,
                millis,
            };
        }
        let utc = crate::record::rfc3339(unix_ms);
        let field = |range: std::ops::Range<usize>| {
            utc.get(range)
                .and_then(|text| text.parse().ok())
                .unwrap_or(0)
        };
        LocalTime {
            year: field(0..4) as i32,
            month: field(5..7),
            day: field(8..10),
            hour: field(11..13),
            minute: field(14..16),
            second: field(17..19),
            millis,
        }
    }

    /// `YYYY-MM-DD`
    pub fn date(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `HH:MM:SS.mmm`
    pub fn time(&self) -> String {
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            self.hour, self.minute, self.second, self.millis
        )
    }
}

/// `271ms`, `2.4s`, `3m05s`, `1h02m`.
pub fn duration(ms: u64) -> String {
    match ms {
        0..=999 => format!("{ms}ms"),
        1_000..=59_999 => format!("{:.1}s", ms as f64 / 1000.0),
        60_000..=3_599_999 => format!("{}m{:02}s", ms / 60_000, ms % 60_000 / 1000),
        _ => format!("{}h{:02}m", ms / 3_600_000, ms % 3_600_000 / 60_000),
    }
}

/// `512B`, `1.2KB`, `4.0MB` (1024-based); `separator` goes between number and unit.
pub fn size(bytes: u64, separator: &str) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes}{separator}B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1}{separator}{}", UNITS[unit])
}

/// Replaces control characters (other than newline and tab) with visible escapes so captured
/// text cannot move the cursor or recolour the terminal.
pub fn sanitize(text: &str) -> String {
    if !text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            '\r' => out.push_str("\\r"),
            '\n' | '\t' => out.push(c),
            c if c.is_control() && (c as u32) < 0x80 => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if c.is_control() => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `sanitize` for single-line fields: newlines and tabs are escaped too.
pub fn sanitize_line(text: &str) -> String {
    sanitize(text).replace('\n', "\\n").replace('\t', " ")
}

/// Cuts `text` to at most `width` characters, ending with `…` when cut.
pub fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_durations_and_sizes() {
        assert_eq!(duration(0), "0ms");
        assert_eq!(duration(271), "271ms");
        assert_eq!(duration(2_400), "2.4s");
        assert_eq!(duration(185_000), "3m05s");
        assert_eq!(duration(3_720_000), "1h02m");
        assert_eq!(size(0, ""), "0B");
        assert_eq!(size(1023, ""), "1023B");
        assert_eq!(size(1229, ""), "1.2KB");
        assert_eq!(size(4 * 1024 * 1024, " "), "4.0 MB");
    }

    #[test]
    fn sanitizes_control_characters() {
        assert_eq!(
            sanitize("a\r\nb\x1b[31mc\rd\u{85}"),
            "a\nb\\x1b[31mc\\rd\\u{0085}"
        );
        assert_eq!(sanitize_line("a\nb\tc"), "a\\nb c");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }

    #[test]
    fn styles_only_when_coloured() {
        assert_eq!(Style::plain().status(Some(500), false, "500"), "500");
        let color = Style { color: true };
        assert_eq!(color.status(Some(201), false, "201"), "\x1b[32m201\x1b[0m");
        assert_eq!(color.status(Some(302), false, "302"), "\x1b[36m302\x1b[0m");
        assert_eq!(color.status(Some(404), false, "404"), "\x1b[33m404\x1b[0m");
        assert_eq!(color.status(None, true, "ERR"), "\x1b[31mERR\x1b[0m");
        assert_eq!(color.status(None, false, "-"), "-");
    }

    #[test]
    fn local_time_has_sane_fields() {
        let time = LocalTime::from_unix_ms(1_761_632_982_123);
        assert_eq!(time.millis, 123);
        assert_eq!(time.second, 42);
        assert!(time.time().ends_with(":42.123"));
        assert_eq!(time.date().len(), 10);
    }
}

//! Arguments of `tap show` and `tap tail` (everything after the session selector).

/// Which body `--body` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Request,
    Response,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShowArgs {
    /// Exchange number: show one exchange instead of the list.
    pub seq: Option<u64>,
    pub filters: Vec<String>,
    pub json: bool,
    pub body: Option<Side>,
    pub curl: bool,
    pub full: bool,
    pub last: Option<usize>,
    pub no_color: bool,
    pub help: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TailArgs {
    pub filters: Vec<String>,
    pub json: bool,
    pub no_color: bool,
    pub all: bool,
    pub help: bool,
}

/// Splits `--name=value` into its parts.
fn split_flag(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((name, value)) if name.starts_with("--") => (name, Some(value)),
        _ => (arg, None),
    }
}

fn value<'a>(
    name: &str,
    inline: Option<&'a str>,
    rest: &mut impl Iterator<Item = &'a String>,
) -> Result<&'a str, String> {
    inline
        .or_else(|| rest.next().map(String::as_str))
        .ok_or_else(|| format!("{name} needs a value"))
}

fn no_value(name: &str, inline: Option<&str>) -> Result<(), String> {
    match inline {
        Some(_) => Err(format!("{name} does not take a value")),
        None => Ok(()),
    }
}

fn is_seq(arg: &str) -> bool {
    !arg.is_empty() && arg.bytes().all(|byte| byte.is_ascii_digit())
}

fn unexpected(arg: &str) -> String {
    format!(
        "unexpected argument `{arg}`: expected an exchange number (e.g. 12) or a filter such as host=api.anthropic.com"
    )
}

pub fn parse_show(args: &[String]) -> Result<ShowArgs, String> {
    let mut parsed = ShowArgs::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (name, inline) = split_flag(arg);
        match name {
            "-h" | "--help" => parsed.help = true,
            "--json" => {
                no_value(name, inline)?;
                parsed.json = true
            }
            "--curl" => {
                no_value(name, inline)?;
                parsed.curl = true
            }
            "--full" => {
                no_value(name, inline)?;
                parsed.full = true
            }
            "--no-color" | "--no-colour" => {
                no_value(name, inline)?;
                parsed.no_color = true
            }
            "--body" => {
                parsed.body = Some(match value(name, inline, &mut rest)? {
                    "req" | "request" => Side::Request,
                    "res" | "response" => Side::Response,
                    other => return Err(format!("--body takes req or res, not `{other}`")),
                })
            }
            "--last" => {
                let text = value(name, inline, &mut rest)?;
                match text.parse::<usize>() {
                    Ok(count) if count > 0 => parsed.last = Some(count),
                    _ => return Err(format!("--last takes a positive number, not `{text}`")),
                }
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option {name}")),
            _ if is_seq(arg) => {
                let seq = arg
                    .parse::<u64>()
                    .map_err(|_| format!("exchange number {arg} is too large"))?;
                if let Some(previous) = parsed.seq {
                    return Err(format!(
                        "give one exchange number, not two ({previous} and {seq})"
                    ));
                }
                parsed.seq = Some(seq);
            }
            _ if arg.contains('=') => parsed.filters.push(arg.clone()),
            _ => return Err(unexpected(arg)),
        }
    }
    if parsed.help {
        return Ok(parsed);
    }
    match parsed.seq {
        None => {
            for (given, flag) in [
                (parsed.body.is_some(), "--body"),
                (parsed.curl, "--curl"),
                (parsed.full, "--full"),
            ] {
                if given {
                    return Err(format!(
                        "{flag} needs an exchange number, e.g. tap show SESSION 12 {flag}{}",
                        if flag == "--body" { " res" } else { "" }
                    ));
                }
            }
        }
        Some(seq) => {
            if !parsed.filters.is_empty() {
                return Err(format!(
                    "give an exchange number or filters, not both (got {seq} and {})",
                    parsed.filters.join(" ")
                ));
            }
            if parsed.last.is_some() {
                return Err("--last applies to the list; drop the exchange number".to_string());
            }
            let outputs = [parsed.json, parsed.body.is_some(), parsed.curl];
            if outputs.iter().filter(|given| **given).count() > 1 {
                return Err("choose one of --json, --body and --curl".to_string());
            }
        }
    }
    Ok(parsed)
}

pub fn parse_tail(args: &[String]) -> Result<TailArgs, String> {
    let mut parsed = TailArgs::default();
    for arg in args {
        let (name, inline) = split_flag(arg);
        match name {
            "-h" | "--help" => parsed.help = true,
            "--json" => {
                no_value(name, inline)?;
                parsed.json = true
            }
            "--no-color" | "--no-colour" => {
                no_value(name, inline)?;
                parsed.no_color = true
            }
            "--all" => {
                no_value(name, inline)?;
                parsed.all = true
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option {name}")),
            _ if arg.contains('=') => parsed.filters.push(arg.clone()),
            _ if is_seq(arg) => {
                return Err(format!(
                    "tail does not take an exchange number; to see #{arg}: tap show SESSION {arg}"
                ))
            }
            _ => {
                return Err(format!(
                    "unexpected argument `{arg}`: expected a filter such as host=api.anthropic.com"
                ))
            }
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    fn show(args: &[&str]) -> Result<ShowArgs, String> {
        parse_show(&strings(args))
    }

    #[test]
    fn show_positionals_are_seq_or_filters() {
        let parsed = show(&[
            "host=anthropic.com",
            "!status=2xx",
            "--last",
            "5",
            "--no-color",
        ])
        .unwrap();
        assert_eq!(parsed.filters, ["host=anthropic.com", "!status=2xx"]);
        assert_eq!(parsed.last, Some(5));
        assert!(parsed.no_color);
        assert_eq!(parsed.seq, None);

        let parsed = show(&["12", "--body=res", "--full"]).unwrap();
        assert_eq!(parsed.seq, Some(12));
        assert_eq!(parsed.body, Some(Side::Response));
        assert!(parsed.full);
        assert_eq!(
            show(&["3", "--body", "req"]).unwrap().body,
            Some(Side::Request)
        );
        assert!(show(&["3", "--curl"]).unwrap().curl);
        assert!(show(&["3", "--json"]).unwrap().json);
        assert!(show(&["--json"]).unwrap().json);
    }

    #[test]
    fn show_rejects_bad_combinations() {
        let error = |args: &[&str]| show(args).unwrap_err();
        assert_eq!(error(&["--frobnicate"]), "unknown option --frobnicate");
        assert!(error(&["--body", "res"]).starts_with("--body needs an exchange number"));
        assert!(error(&["--curl"]).starts_with("--curl needs an exchange number"));
        assert!(error(&["--full"]).starts_with("--full needs an exchange number"));
        assert!(error(&["3", "--body", "both"]).contains("req or res"));
        assert!(error(&["3", "--body"]).contains("needs a value"));
        assert!(error(&["3", "4"]).contains("not two"));
        assert!(error(&["3", "host=x"]).contains("not both"));
        assert!(error(&["3", "--last", "2"]).contains("--last applies to the list"));
        assert!(error(&["--last", "0"]).contains("positive"));
        assert!(error(&["3", "--curl", "--json"]).contains("choose one"));
        assert!(error(&["anthropic"]).contains("unexpected argument `anthropic`"));
        assert!(show(&["--help", "--curl"]).unwrap().help);
    }

    #[test]
    fn tail_arguments() {
        let parsed = parse_tail(&strings(&["host=x", "--all", "--json"])).unwrap();
        assert_eq!(parsed.filters, ["host=x"]);
        assert!(parsed.all && parsed.json && !parsed.no_color);
        assert!(parse_tail(&strings(&["--full"]))
            .unwrap_err()
            .contains("unknown option"));
        assert!(parse_tail(&strings(&["7"]))
            .unwrap_err()
            .contains("tap show SESSION 7"));
    }
}

//! One filter language is used both to scope what a session records and to
//! select what `tap show` / `tap tail` display. Filters never block traffic.
//!
//! ```text
//! filters   := spec*                       specs are OR-ed; no specs = match everything
//! spec      := condition ("," condition)*  conditions are AND-ed
//! condition := ["!"] key "=" value         "!" negates
//! ```
//! Values are literal unless they contain one of `^$|?*+()[]{}\`, or start with
//! `~` (always a regex; the `~` is dropped). Regexes are unanchored.

use crate::record::{Exchange, RequestRecord};
use regex::Regex;

const VALID_KEYS: &str = "method, scheme, host, port, path, url, mode, status, header:NAME";
const REGEX_CHARS: &[char] = &[
    '^', '$', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}', '\\',
];

#[derive(Clone, Debug, Default)]
pub struct FilterSet {
    specs: Vec<Spec>,
}

#[derive(Clone, Debug)]
struct Spec {
    conditions: Vec<Condition>,
}

#[derive(Clone, Debug)]
struct Condition {
    negate: bool,
    field: Field,
    test: Test,
}

#[derive(Clone, Debug, PartialEq)]
enum Field {
    Method,
    Scheme,
    Host,
    Port,
    Path,
    Url,
    Mode,
    Status,
    /// Lowercase header name.
    Header(String),
}

#[derive(Clone, Debug)]
enum Test {
    Regex(Regex),
    /// Case-insensitive equality.
    Equals(String),
    /// The host itself or any subdomain (lowercase, no trailing dot).
    Domain(String),
    Number(u16),
    /// Three status digits; None is an `x` wildcard (so `404` is an exact match).
    StatusPattern([Option<u8>; 3]),
    Prefix(String),
    Contains(String),
    Present,
}

/// The values a filter is evaluated against.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// Path plus query.
    pub path: &'a str,
    pub url: &'a str,
    /// `forward` | `mitm` | `reverse` | `tunnel`.
    pub mode: &'a str,
    /// Request headers.
    pub headers: &'a [(String, String)],
    /// None while the response is not yet known, or when there never was one.
    pub status: Option<u16>,
    /// True once the exchange is over: a missing status then means "none", not "not yet".
    pub finished: bool,
}

impl<'a> Facts<'a> {
    pub fn request(request: &'a RequestRecord, mode: &'a str) -> Self {
        Facts {
            method: &request.method,
            scheme: &request.scheme,
            host: &request.host,
            port: request.port,
            path: &request.path,
            url: &request.url,
            mode,
            headers: &request.headers,
            status: None,
            finished: false,
        }
    }

    /// Facts for a finished exchange. One that failed inside TAP (no upstream
    /// response) counts as `502`, the status its client was given.
    pub fn exchange(exchange: &'a Exchange) -> Self {
        let failed = exchange.error.as_ref().map(|_| 502);
        Facts {
            status: exchange.status().or(failed),
            finished: true,
            ..Facts::request(&exchange.request, exchange.mode.as_str())
        }
    }
}

impl FilterSet {
    /// Parses filter specs; each spec is a comma-separated AND of conditions and
    /// the specs are OR-ed. Returns a message naming the bad spec on error.
    pub fn parse(specs: &[String]) -> Result<FilterSet, String> {
        let mut parsed = Vec::new();
        for spec in specs {
            let mut conditions = Vec::new();
            for text in split_conditions(spec) {
                let text = text.trim();
                if text.is_empty() {
                    continue;
                }
                let condition = parse_condition(text).map_err(|problem| {
                    format!("invalid filter {spec:?}: {problem} (valid keys: {VALID_KEYS})")
                })?;
                conditions.push(condition);
            }
            // A spec of only commas and spaces says nothing; it is ignored like an empty condition.
            if !conditions.is_empty() {
                parsed.push(Spec { conditions });
            }
        }
        Ok(FilterSet { specs: parsed })
    }

    /// True when no filters are configured (everything matches).
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Whether `facts` match. Conditions on `status` (negated or not) count as
    /// satisfied while `facts.status` is None, so a request can be provisionally
    /// in scope and decided finally once the response is known.
    pub fn matches(&self, facts: &Facts) -> bool {
        self.specs.is_empty()
            || self.specs.iter().any(|spec| {
                spec.conditions
                    .iter()
                    .all(|condition| condition.matches(facts))
            })
    }
}

/// Splits at commas that start a new condition: what follows (after spaces and
/// further commas) is the end of the spec or `[!]key=`. Other commas belong to the value.
fn split_conditions(spec: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, ch) in spec.char_indices() {
        if ch == ',' && separates(&spec[index + 1..]) {
            parts.push(&spec[start..index]);
            start = index + 1;
        }
    }
    parts.push(&spec[start..]);
    parts
}

fn separates(rest: &str) -> bool {
    let rest = rest.trim_start_matches(|ch: char| ch == ',' || ch.is_whitespace());
    if rest.is_empty() {
        return true;
    }
    let rest = rest.strip_prefix('!').unwrap_or(rest);
    match rest.split_once('=') {
        Some((key, _)) => looks_like_key(key.trim()),
        None => false,
    }
}

/// A known key, or `header:` followed by header-name characters (possibly none,
/// so that `header:=x` is split off and reported rather than swallowed).
fn looks_like_key(key: &str) -> bool {
    match split_header_key(key) {
        Some(name) => name.chars().all(is_token_char),
        None => simple_field(key).is_some(),
    }
}

fn split_header_key(key: &str) -> Option<&str> {
    let prefix = key.get(..7)?;
    prefix.eq_ignore_ascii_case("header:").then(|| &key[7..])
}

fn simple_field(key: &str) -> Option<Field> {
    let field = match key.to_ascii_lowercase().as_str() {
        "method" => Field::Method,
        "scheme" => Field::Scheme,
        "host" => Field::Host,
        "port" => Field::Port,
        "path" => Field::Path,
        "url" => Field::Url,
        "mode" => Field::Mode,
        "status" => Field::Status,
        _ => return None,
    };
    Some(field)
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(ch)
}

fn parse_condition(text: &str) -> Result<Condition, String> {
    let (negate, body) = match text.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, text),
    };
    let Some((key, value)) = body.split_once('=') else {
        return Err(format!(
            "missing \"=\" in condition {text:?} (expected key=value)"
        ));
    };
    let field =
        parse_field(key.trim()).map_err(|problem| format!("{problem} in condition {text:?}"))?;
    let test = parse_test(&field, value.trim())
        .map_err(|problem| format!("{problem} in condition {text:?}"))?;
    Ok(Condition {
        negate,
        field,
        test,
    })
}

fn parse_field(key: &str) -> Result<Field, String> {
    if let Some(name) = split_header_key(key) {
        if name.is_empty() {
            return Err("empty header name after \"header:\"".into());
        }
        if !name.chars().all(is_token_char) {
            return Err(format!("invalid header name {name:?}"));
        }
        return Ok(Field::Header(name.to_ascii_lowercase()));
    }
    if key.is_empty() {
        return Err("missing key before \"=\"".into());
    }
    simple_field(key).ok_or_else(|| format!("unknown key {key:?}"))
}

fn parse_test(field: &Field, value: &str) -> Result<Test, String> {
    if let Some(pattern) = value.strip_prefix('~') {
        return regex(pattern);
    }
    if value.contains(REGEX_CHARS) {
        return regex(value);
    }
    let test = match field {
        Field::Method | Field::Scheme | Field::Mode => {
            Test::Equals(single_word(field, value)?.into())
        }
        Field::Host => {
            let host = single_word(field, value)?;
            Test::Domain(host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase())
        }
        Field::Port => Test::Number(value.parse().map_err(|_| {
            format!("port must be a number from 0 to 65535, got {value:?} (use ~ for a regex)")
        })?),
        Field::Status => parse_status(value)?,
        Field::Path => Test::Prefix(value.into()),
        Field::Url => Test::Contains(value.into()),
        Field::Header(_) if value.is_empty() => Test::Present,
        Field::Header(_) => Test::Contains(value.into()),
    };
    Ok(test)
}

fn regex(pattern: &str) -> Result<Test, String> {
    Regex::new(pattern)
        .map(Test::Regex)
        .map_err(|error| format!("invalid regex {pattern:?}: {error}"))
}

/// Methods, schemes, modes and hosts never contain commas, so a comma here is
/// almost certainly a mistyped key (`host=a.com,paht=/v1`) or an attempted OR.
fn single_word<'v>(field: &Field, value: &'v str) -> Result<&'v str, String> {
    if value.contains(',') {
        let key = format!("{field:?}").to_ascii_lowercase();
        return Err(format!(
            "unexpected \",\" in {key} value {value:?}: a comma starts a new condition only before a valid key, \
             and alternatives are separate filters or a ~regex"
        ));
    }
    Ok(value)
}

/// Status codes are three digits, so `status=5` (likely meant as `5xx`) is an error, not a silent miss.
fn parse_status(value: &str) -> Result<Test, String> {
    let bytes = value.as_bytes();
    let wildcard = |byte: u8| byte.is_ascii_digit() || byte.eq_ignore_ascii_case(&b'x');
    if bytes.len() == 3 && bytes.iter().all(|&byte| wildcard(byte)) {
        let digit = |byte: u8| byte.is_ascii_digit().then_some(byte - b'0');
        return Ok(Test::StatusPattern([
            digit(bytes[0]),
            digit(bytes[1]),
            digit(bytes[2]),
        ]));
    }
    Err(format!(
        "status must be a 3-digit code or a pattern like 4xx or 50x, got {value:?} (use ~ for a regex)"
    ))
}

impl Condition {
    fn matches(&self, facts: &Facts) -> bool {
        let hit = match &self.field {
            Field::Method => self.test.text(facts.method),
            Field::Scheme => self.test.text(facts.scheme),
            Field::Host => self.test.text(facts.host),
            Field::Port => self.test.number(facts.port),
            Field::Path => self.test.text(facts.path),
            Field::Url => self.test.text(facts.url),
            Field::Mode => self.test.text(facts.mode),
            Field::Status => match facts.status {
                Some(status) => self.test.number(status),
                None if facts.finished => false,
                None => return true,
            },
            Field::Header(name) => {
                let mut values = facts
                    .headers
                    .iter()
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.as_str());
                match self.test {
                    Test::Present => values.next().is_some(),
                    _ => values.any(|value| self.test.text(value)),
                }
            }
        };
        hit != self.negate
    }
}

impl Test {
    fn text(&self, value: &str) -> bool {
        match self {
            Test::Regex(regex) => regex.is_match(value),
            Test::Equals(expected) => value.eq_ignore_ascii_case(expected),
            Test::Domain(domain) => is_host_or_subdomain(value, domain),
            Test::Prefix(prefix) => value.starts_with(prefix.as_str()),
            Test::Contains(needle) => value.contains(needle.as_str()),
            Test::Present => true,
            Test::Number(_) | Test::StatusPattern(_) => false,
        }
    }

    fn number(&self, value: u16) -> bool {
        match self {
            Test::Regex(regex) => regex.is_match(&value.to_string()),
            Test::Number(expected) => value == *expected,
            Test::StatusPattern(digits) => {
                let text = value.to_string();
                text.len() == 3
                    && text
                        .bytes()
                        .zip(digits)
                        .all(|(byte, digit)| digit.is_none_or(|digit| byte - b'0' == digit))
            }
            _ => false,
        }
    }
}

fn is_host_or_subdomain(host: &str, domain: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.eq_ignore_ascii_case(domain) {
        return true;
    }
    let Some(split) = host
        .len()
        .checked_sub(domain.len())
        .filter(|&split| split > 0)
    else {
        return false;
    };
    host.as_bytes()[split - 1] == b'.'
        && host.is_char_boundary(split)
        && host[split..].eq_ignore_ascii_case(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Mode, ResponseRecord};

    struct Sample {
        method: String,
        scheme: String,
        host: String,
        port: u16,
        path: String,
        url: String,
        mode: String,
        headers: Vec<(String, String)>,
        status: Option<u16>,
    }

    impl Sample {
        fn facts(&self) -> Facts<'_> {
            Facts {
                method: &self.method,
                scheme: &self.scheme,
                host: &self.host,
                port: self.port,
                path: &self.path,
                url: &self.url,
                mode: &self.mode,
                headers: &self.headers,
                status: self.status,
                finished: false,
            }
        }

        fn host(mut self, host: &str) -> Sample {
            self.host = host.into();
            self
        }

        fn status(mut self, status: Option<u16>) -> Sample {
            self.status = status;
            self
        }
    }

    fn sample() -> Sample {
        Sample {
            method: "POST".into(),
            scheme: "https".into(),
            host: "api.anthropic.com".into(),
            port: 443,
            path: "/v1/messages?beta=true".into(),
            url: "https://api.anthropic.com/v1/messages?beta=true".into(),
            mode: "mitm".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("x-stainless-lang".into(), "python".into()),
                ("x-empty".into(), "".into()),
                ("accept".into(), "text/plain".into()),
                ("accept".into(), "application/json".into()),
                ("cache-control".into(), "no-cache,max-age=0".into()),
            ],
            status: Some(200),
        }
    }

    fn parse(specs: &[&str]) -> FilterSet {
        let specs: Vec<String> = specs.iter().map(|spec| spec.to_string()).collect();
        FilterSet::parse(&specs).unwrap_or_else(|error| panic!("{specs:?}: {error}"))
    }

    fn error(spec: &str) -> String {
        match FilterSet::parse(&[spec.to_string()]) {
            Ok(filters) => panic!("{spec:?} should not parse: {filters:?}"),
            Err(error) => error,
        }
    }

    fn assert_table(sample: &Sample, table: &[(&str, bool)]) {
        for &(spec, expected) in table {
            let actual = parse(&[spec]).matches(&sample.facts());
            assert_eq!(
                actual, expected,
                "{spec:?} against host={} status={:?}",
                sample.host, sample.status
            );
        }
    }

    fn conditions(spec: &str) -> usize {
        parse(&[spec])
            .specs
            .first()
            .map_or(0, |spec| spec.conditions.len())
    }

    #[test]
    fn method_scheme_mode_are_case_insensitive_exact() {
        assert_table(
            &sample(),
            &[
                ("method=POST", true),
                ("method=post", true),
                ("method=GET", false),
                ("method=PO", false),
                ("method=POSTS", false),
                ("!method=GET", true),
                ("!method=post", false),
                ("method=~^P", true),
                ("scheme=https", true),
                ("scheme=HTTPS", true),
                ("scheme=http", false),
                ("mode=mitm", true),
                ("mode=MITM", true),
                ("mode=mit", false),
                ("mode=forward", false),
                ("!mode=tunnel", true),
            ],
        );
    }

    #[test]
    fn host_matches_exact_or_subdomain() {
        assert_table(
            &sample(),
            &[
                ("host=api.anthropic.com", true),
                ("host=anthropic.com", true),
                ("host=ANTHROPIC.COM", true),
                ("host=anthropic.com.", true),
                ("host=com", true),
                ("host=thropic.com", false),
                ("host=pi.anthropic.com", false),
                ("host=anthropic.co", false),
                ("host=api.anthropic.com.evil.net", false),
                ("!host=telemetry.example.com", true),
                ("!host=anthropic.com", false),
                ("host=~anthropic", true),
                ("host=~^anthropic", false),
            ],
        );
        let table = [
            ("anthropic.com", true),
            ("API.Anthropic.COM", true),
            ("api.anthropic.com.", true),
            ("notanthropic.com", false),
            ("anthropic.com.evil.net", false),
            ("anthropic.co", false),
            ("", false),
        ];
        for (host, expected) in table {
            let host_sample = sample().host(host);
            assert_eq!(
                parse(&["host=anthropic.com"]).matches(&host_sample.facts()),
                expected,
                "{host:?}"
            );
        }
    }

    #[test]
    fn port_is_an_exact_number() {
        assert_table(
            &sample(),
            &[
                ("port=443", true),
                ("port=44", false),
                ("port=4433", false),
                ("!port=80", true),
                ("port=~^4", true),
            ],
        );
        let mut high = sample();
        high.port = 18701;
        assert_table(
            &high,
            &[
                ("port=70", false),
                ("port=187", false),
                ("port=18701", true),
                ("port=018701", true),
                ("!port=70", true),
                ("port=~70", true),
                ("port=~^70$", false),
            ],
        );
    }

    #[test]
    fn path_is_a_prefix_and_url_a_substring() {
        assert_table(
            &sample(),
            &[
                ("path=/v1", true),
                ("path=/v1/messages", true),
                ("path=/", true),
                ("path=v1", false),
                ("path=/V1", false),
                ("path=/v2", false),
                ("path=~messages", true),
                // `?` makes the value a regex; escape it to match the query literally.
                (r"path=/v1/messages\?beta", true),
                ("path=/v1/messages?beta=true", false),
                ("url=anthropic.com/v1", true),
                ("url=https://api", true),
                ("url=openai", false),
                ("url=ANTHROPIC", false),
                ("url=~/v1/(messages|complete)", true),
                ("url=~^http://", false),
                ("!url=openai", true),
            ],
        );
        let mut complete = sample();
        complete.url = "https://api.anthropic.com/v1/complete".into();
        assert_table(&complete, &[("url=~/v1/(messages|complete)", true)]);
        complete.url = "https://api.anthropic.com/v1/models".into();
        assert_table(&complete, &[("url=~/v1/(messages|complete)", false)]);
    }

    #[test]
    fn dot_is_literal_not_a_regex() {
        let mut dotted = sample();
        dotted.url = "https://apixanthropic.com/".into();
        dotted.host = "apixanthropic.com".into();
        assert_table(
            &dotted,
            &[
                ("url=api.anthropic", false),
                ("host=api.anthropic.com", false),
            ],
        );
    }

    #[test]
    fn status_numbers_and_wildcards() {
        assert_table(
            &sample(),
            &[
                ("status=200", true),
                ("status=201", false),
                ("status=2xx", true),
                ("status=2XX", true),
                ("status=20x", true),
                ("status=x0x", true),
                ("status=xxx", true),
                ("status=21x", false),
                ("status=5xx", false),
                ("!status=5xx", true),
                ("!status=200", false),
                ("status=~^2", true),
                ("status=~^5", false),
            ],
        );
        assert_table(
            &sample().status(Some(503)),
            &[
                ("status=5xx", true),
                ("status=50x", true),
                ("status=503", true),
                ("!status=5xx", false),
            ],
        );
    }

    #[test]
    fn status_is_satisfied_while_unknown() {
        assert_table(
            &sample().status(None),
            &[
                ("status=5xx", true),
                ("!status=5xx", true),
                ("status=200", true),
                ("!status=200", true),
                ("status=~^5", true),
                ("host=anthropic.com,status=4xx", true),
                ("host=api.openai.com,status=4xx", false),
                ("!status=5xx,method=GET", false),
            ],
        );
    }

    #[test]
    fn headers_by_name_with_substring_presence_and_regex() {
        assert_table(
            &sample(),
            &[
                ("header:x-stainless-lang=python", true),
                ("header:X-Stainless-Lang=python", true),
                ("HEADER:x-stainless-lang=pyth", true),
                ("header:x-stainless-lang=ytho", true),
                ("header:x-stainless-lang=Python", false),
                ("header:x-stainless-lang=node", false),
                ("header:x-stainless-lang=", true),
                ("header:x-stainless=", false),
                ("header:x-missing=", false),
                ("!header:x-missing=", true),
                ("!header:x-stainless-lang=", false),
                ("header:x-empty=", true),
                ("header:x-empty=a", false),
                ("header:accept=text/plain", true),
                ("header:accept=application/json", true),
                ("!header:accept=text/html", true),
                ("header:content-type=~^application/", true),
                ("header:content-type=~^text/", false),
                ("header:x-missing=~", false),
                ("header:x-empty=~", true),
                ("header:cache-control=no-cache,max-age=0", true),
            ],
        );
    }

    #[test]
    fn spec_examples() {
        let mut openai = sample().host("api.openai.com").status(Some(429));
        openai.url = "https://api.openai.com/v1/chat/completions".into();
        openai.path = "/v1/chat/completions".into();
        let telemetry = sample().host("telemetry.example.com").status(Some(500));
        let anthropic = sample();
        let table = [
            ("host=anthropic.com", [true, false, false]),
            ("host=anthropic.com,path=/v1/messages", [true, false, false]),
            ("!host=telemetry.example.com", [true, true, false]),
            ("status=5xx", [false, false, true]),
            ("host=api.openai.com,status=4xx", [false, true, false]),
            ("header:x-stainless-lang=python", [true, true, true]),
            ("url=~/v1/(messages|complete)", [true, false, true]),
        ];
        for (spec, expected) in table {
            let filters = parse(&[spec]);
            let actual =
                [&anthropic, &openai, &telemetry].map(|sample| filters.matches(&sample.facts()));
            assert_eq!(actual, expected, "{spec:?}");
        }
    }

    #[test]
    fn conditions_are_anded_and_specs_ored() {
        let facts = sample();
        assert!(parse(&["host=anthropic.com,method=POST"]).matches(&facts.facts()));
        assert!(!parse(&["host=anthropic.com,method=GET"]).matches(&facts.facts()));
        assert!(parse(&["host=openai.com", "host=anthropic.com"]).matches(&facts.facts()));
        assert!(!parse(&["host=openai.com", "method=GET"]).matches(&facts.facts()));
        assert!(
            parse(&["host=openai.com", "method=GET", "status=2xx,port=443"])
                .matches(&facts.facts())
        );
    }

    #[test]
    fn empty_filters_match_everything() {
        let cases: [&[&str]; 4] = [&[], &[""], &[" , ,"], &[",", "  "]];
        for specs in cases {
            let filters = parse(specs);
            assert!(filters.is_empty(), "{specs:?}");
            assert!(filters.matches(&sample().facts()));
        }
        assert!(FilterSet::default().is_empty());
        assert!(FilterSet::default().matches(&sample().facts()));
        assert!(!parse(&["host=x.com"]).is_empty());
        // An empty spec next to a real one adds nothing.
        assert!(!parse(&["", "host=x.com"]).matches(&sample().facts()));
    }

    #[test]
    fn smart_comma_splitting_and_trimming() {
        assert_eq!(conditions(r"url=~\d{1,3}"), 1);
        assert_eq!(conditions(r"path=~^/v\d{1,3}/x,host=a.com"), 2);
        assert_eq!(conditions("header:cache-control=no-cache,max-age=0"), 1);
        assert_eq!(conditions("url=a,b"), 1);
        assert_eq!(conditions("host=a.com, path=/x"), 2);
        assert_eq!(conditions("host=a.com,!path=/x"), 2);
        assert_eq!(conditions("host=a.com, ! path=/x"), 2);
        assert_eq!(conditions("host=a.com,HEADER:X-Y=1"), 2);
        assert_eq!(conditions("host=a.com,"), 1);
        assert_eq!(conditions(",,host=a.com,, ,path=/x,"), 2);

        let mut digits = sample();
        digits.url = "https://10.0.0.1/".into();
        assert_table(
            &digits,
            &[(r"url=~\d{1,3}\.\d{1,3}", true), (r"url=~^\d{1,3}", false)],
        );

        let mut small = sample().host("a.com");
        small.path = "/x/y".into();
        assert_table(
            &small,
            &[
                ("host=a.com, path=/x", true),
                ("host=a.com,path=/x", true),
                ("  host=a.com ,  path=/x  ", true),
                ("host=a.com,path=/x,", true),
                ("host = a.com , path = /x", true),
                ("Host=a.com", true),
                ("HOST=A.COM,Path=/x", true),
                ("host=a.com, path=/z", false),
            ],
        );
    }

    #[test]
    fn errors_name_the_spec_and_list_valid_keys() {
        let cases = [
            ("host", "missing \"=\""),
            ("host=a.com,path", "unexpected \",\""),
            ("hots=a.com", "unknown key \"hots\""),
            ("host=a.com,foo=1", "unexpected \",\""),
            ("=a", "missing key"),
            ("url=~(", "invalid regex"),
            ("path=/v1/[", "invalid regex"),
            ("header:=x", "empty header name"),
            ("host=a.com,header:=x", "empty header name"),
            ("header:bad name=x", "invalid header name"),
            ("port=abc", "port must be a number"),
            ("port=70000", "port must be a number"),
            ("port=", "port must be a number"),
            ("status=5x", "status must be"),
            ("status=5xxx", "status must be"),
            ("status=abc", "status must be"),
            ("status=5..", "status must be"),
            ("status=", "status must be"),
            ("status=99999", "status must be"),
            ("status=5", "status must be"),
            ("status=50", "status must be"),
            ("status=0200", "status must be"),
            ("status=1000", "status must be"),
            ("status=4xx,5xx", "status must be"),
            ("method=GET,POST", "unexpected \",\""),
        ];
        for (spec, expected) in cases {
            let message = error(spec);
            assert!(message.contains(expected), "{spec:?}: {message}");
            assert!(
                message.contains(&format!("{spec:?}")),
                "{spec:?}: {message}"
            );
            assert!(message.contains(VALID_KEYS), "{spec:?}: {message}");
        }
        let message = error("host=a.com,hots=b");
        assert!(message.contains("\"host=a.com,hots=b\""), "{message}");
        let specs = vec!["host=a.com".to_string(), "nope".to_string()];
        let message = FilterSet::parse(&specs).unwrap_err();
        assert!(message.contains("\"nope\""), "{message}");
    }

    #[test]
    fn status_filters_parse_and_never_reject_at_request_phase() {
        for spec in [
            "status=5xx",
            "!status=5xx",
            "status=404",
            "status=~^5",
            "host=anthropic.com,status=5xx",
        ] {
            let filters = parse(&[spec]);
            assert!(filters.matches(&sample().status(None).facts()), "{spec}");
        }
    }

    #[test]
    fn facts_from_records() {
        let mut exchange = Exchange {
            mode: Mode::Reverse,
            request: RequestRecord {
                method: "GET".into(),
                url: "https://example.com:8443/a?b=1".into(),
                scheme: "https".into(),
                host: "example.com".into(),
                port: 8443,
                path: "/a?b=1".into(),
                headers: vec![("user-agent".into(), "curl/8".into())],
                ..Default::default()
            },
            ..Default::default()
        };
        let filters = parse(&["mode=reverse,port=8443,path=/a,header:user-agent=curl,status=5xx"]);
        let request = Facts::request(&exchange.request, "reverse");
        assert_eq!(request.status, None);
        assert!(filters.matches(&request));
        // Finished without a response or an error (a tunnel): there is no status to match.
        assert!(!filters.matches(&Facts::exchange(&exchange)));
        assert!(parse(&["!status=5xx"]).matches(&Facts::exchange(&exchange)));
        // Failed inside TAP: the client was given a 502.
        exchange.error = Some("upstream refused".into());
        assert!(filters.matches(&Facts::exchange(&exchange)));
        assert!(!parse(&["status=200"]).matches(&Facts::exchange(&exchange)));
        exchange.error = None;
        exchange.response = Some(ResponseRecord {
            status: 200,
            ..Default::default()
        });
        assert!(!filters.matches(&Facts::exchange(&exchange)));
        exchange.response = Some(ResponseRecord {
            status: 502,
            ..Default::default()
        });
        assert!(filters.matches(&Facts::exchange(&exchange)));
    }

    #[test]
    fn every_metacharacter_makes_a_regex() {
        let mut sample = sample();
        sample.url = "https://api.anthropic.com/v1/messages".into();
        assert_table(
            &sample,
            &[
                ("url=openai|anthropic", true),
                ("url=^https://api", true),
                ("url=messages$", true),
                ("url=mess?ages", true),
                ("url=/v1/.*ages", true),
                ("url=/v1/m+essages", true),
                ("url=/v(1|2)/", true),
                ("url=/v[0-9]/", true),
                ("url=/v1{1}/", true),
                (r"url=\.com", true),
                ("url=api~anthropic", false),
                ("url=a=b", false),
            ],
        );
        assert!(
            matches!(parse(&["url=a=b"]).specs[0].conditions[0].test, Test::Contains(ref text) if text == "a=b")
        );
    }

    #[test]
    fn multibyte_hosts_and_values_are_safe() {
        let table = [
            ("bücher.de", "bücher.de", true),
            ("shop.bücher.de", "bücher.de", true),
            ("xbücher.de", "bücher.de", false),
            ("é.com", "com", true),
            ("aé.com", "é.com", false),
            ("ü", "é", false),
        ];
        for (host, filter, expected) in table {
            let facts = sample().host(host);
            let spec = format!("host={filter}");
            assert_eq!(
                parse(&[&spec]).matches(&facts.facts()),
                expected,
                "{spec} vs {host}"
            );
        }
    }

    #[test]
    fn odd_input_never_panics() {
        let keys = [
            "host",
            "Header:x-y",
            "header:é",
            "header:",
            "status",
            "port",
            "url",
            "PATH",
            "mode",
            "é",
            "",
            "!",
        ];
        let values = [
            "", "x", "5", "5xx", "é", "ü=", "(", "{1,3}", "\\", " ", "a.com", "~", "=", ",", "!",
            "\u{0}", ":", "443",
        ];
        let separators = [",", ", ", ",,", " ,! ", ""];
        let mut odd = sample();
        odd.host = "é.ü".into();
        odd.headers.push(("é".into(), "ü".into()));
        let facts = [sample(), sample().status(None), odd];
        let mut state = 0x2545_f491_u64;
        let mut pick = |len: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize % len
        };
        let (mut parsed, mut rejected) = (0, 0);
        for _ in 0..3000 {
            let mut spec = String::new();
            for _ in 0..=pick(3) {
                if pick(4) == 0 {
                    spec.push('!');
                }
                spec.push_str(keys[pick(keys.len())]);
                if pick(8) != 0 {
                    spec.push('=');
                }
                for _ in 0..pick(3) {
                    spec.push_str(values[pick(values.len())]);
                }
                spec.push_str(separators[pick(separators.len())]);
            }
            match FilterSet::parse(&[spec.clone()]) {
                Ok(filters) => {
                    parsed += usize::from(!filters.is_empty());
                    facts.iter().for_each(|sample| {
                        filters.matches(&sample.facts());
                    });
                }
                Err(message) => {
                    rejected += 1;
                    assert!(message.contains(VALID_KEYS), "{spec:?}: {message}");
                }
            }
        }
        assert!(
            parsed > 300 && rejected > 300,
            "parsed {parsed}, rejected {rejected}"
        );
    }

    #[test]
    fn commas_split_only_before_valid_keys() {
        // Inside a regex, a comma followed by a valid key still starts a new condition.
        assert!(error("url=~(a,host=b)").contains("invalid regex"));
        assert_eq!(conditions("url=~(a,b)"), 1);
        assert_eq!(conditions("url=a,!host=b"), 2);
        assert_eq!(conditions("url=a,!b"), 1);
        assert_eq!(conditions("url=a,=b"), 1);
        assert_eq!(conditions("header:accept=text/html, application/json"), 1);
        assert_eq!(conditions("header:cookie=a=1, b=2"), 1);
        assert_eq!(conditions("header:x-y = v , status = 5xx"), 2);
    }

    #[test]
    fn filter_set_is_clone_debug_default() {
        let filters = parse(&["host=a.com"]);
        let copy = filters.clone();
        assert!(format!("{copy:?}").contains("a.com"));
        let _ = FilterSet::default();
    }
}

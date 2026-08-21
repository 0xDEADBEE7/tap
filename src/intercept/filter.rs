use regex::Regex;
use std::io;

#[derive(Clone, Default)]
pub struct FilterSet {
    filters: Vec<Filter>,
}

#[derive(Clone, Default)]
pub struct Filter {
    conditions: Vec<Condition>,
}

#[derive(Clone)]
enum Condition {
    Field { name: Field, pattern: Regex },
    Header { key: Regex, value: Regex },
}

#[derive(Clone, Copy)]
enum Field {
    Method,
    Scheme,
    Host,
    Port,
    Path,
    Status,
}

impl FilterSet {
    pub fn from_specs(specs: &[String]) -> io::Result<Self> {
        let mut filters = Vec::new();
        for spec in specs {
            let mut conditions = Vec::new();
            for item in spec.split(',') {
                let (key, pattern) = item.split_once('=').ok_or_else(|| invalid(
                    "filter must be FIELD=REGEX or header:KEY=REGEX",
                ))?;
                let regex = Regex::new(pattern)
                    .map_err(|error| invalid(&format!("invalid filter regex: {error}")))?;
                let condition = if let Some(header_key) = key.strip_prefix("header:") {
                    Condition::Header {
                        key: regex_case_insensitive(header_key)?,
                        value: regex,
                    }
                } else {
                    Condition::Field {
                        name: field(key)?,
                        pattern: regex,
                    }
                };
                conditions.push(condition);
            }
            filters.push(Filter { conditions });
        }
        Ok(Self { filters })
    }

    pub fn allows_request(
        &self,
        method: &str,
        scheme: &str,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(String, String)],
    ) -> bool {
        self.filters.is_empty() || self.filters.iter().any(|filter| {
            filter.conditions.iter().all(|condition| match condition {
                Condition::Field { name, pattern } => match name {
                    Field::Method => pattern.is_match(method),
                    Field::Scheme => pattern.is_match(scheme),
                    Field::Host => pattern.is_match(host),
                    Field::Port => pattern.is_match(&port.to_string()),
                    Field::Path => pattern.is_match(path),
                    Field::Status => false,
                },
                Condition::Header { key, value } => headers
                    .iter()
                    .any(|(header_key, header_value)| key.is_match(header_key) && value.is_match(header_value)),
            })
        })
    }

    pub fn allows_response(&self, status: u16) -> bool {
        self.filters.is_empty() || self.filters.iter().any(|filter| {
            filter.conditions.iter().all(|condition| match condition {
                Condition::Field { name: Field::Status, pattern } => pattern.is_match(&status.to_string()),
                Condition::Field { .. } | Condition::Header { .. } => true,
            })
        })
    }
}

fn regex_case_insensitive(pattern: &str) -> io::Result<Regex> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|error| invalid(&format!("invalid header key regex: {error}")))
}

fn field(value: &str) -> io::Result<Field> {
    match value {
        "method" => Ok(Field::Method),
        "scheme" => Ok(Field::Scheme),
        "host" => Ok(Field::Host),
        "port" => Ok(Field::Port),
        "path" => Ok(Field::Path),
        "status" => Ok(Field::Status),
        _ => Err(invalid("unknown filter field")),
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::FilterSet;

    #[test]
    fn filters_or_across_specs_and_and_within_spec() {
        let filters = FilterSet::from_specs(&[
            "method=GET,host=example\\.com".into(),
            "status=^500$".into(),
        ])
        .unwrap();
        assert!(filters.allows_request(
            "GET", "http", "example.com", 80, "/", &[]
        ));
        assert!(!filters.allows_request(
            "POST", "http", "example.com", 80, "/", &[]
        ));
        assert!(filters.allows_response(500));
    }

    #[test]
    fn matches_header_key_and_value() {
        let filters = FilterSet::from_specs(&["header:^x-tenant$=^acme$".into()]).unwrap();
        assert!(filters.allows_request(
            "GET",
            "http",
            "example.com",
            80,
            "/",
            &[("X-Tenant".into(), "acme".into())],
        ));
    }
}

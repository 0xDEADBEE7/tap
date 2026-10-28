# Filters

One small language selects exchanges everywhere in TAP:

- **What a session records:** `tap create ... --filter SPEC` (repeatable), or the `filters` list in
  its `metadata.json`. Filters never block traffic: an exchange that does not match is forwarded as
  usual, but it is not recorded and hooks do not run for it.
- **What you look at:** `tap show SESSION SPEC...` and `tap tail SESSION SPEC...`.

## Syntax

```text
filters   := spec*                        specs are OR-ed; no specs = match everything
spec      := condition ("," condition)*   conditions are AND-ed
condition := ["!"] key "=" value          "!" negates
```

So `--filter host=anthropic.com --filter host=openai.com` records either host, and
`host=anthropic.com,path=/v1/messages` needs both. Keys are case-insensitive; spaces around
conditions are ignored.

| Key | Literal value matches |
|---|---|
| `method`, `scheme`, `mode` | the exact value, any case (`mode` is `forward`, `mitm`, `reverse` or `tunnel`) |
| `host` | the host or any subdomain, any case: `anthropic.com` matches `api.anthropic.com`, not `notanthropic.com` |
| `port` | the exact number |
| `status` | the exact code, or `x` as a digit wildcard: `4xx`, `50x` |
| `path` | a prefix of path plus query: `/v1` matches `/v1/messages?beta=true` |
| `url` | a substring of the full URL |
| `header:NAME` | a substring of any value of the request header NAME (NAME in any case); an empty value means "header present" |

## Literal or regex

A value is literal unless it contains one of `^ $ | ? * + ( ) [ ] { } \`. The dot is literal, so
`host=api.openai.com` means what it says. Start a value with `~` to force a regex (the `~` is
dropped). Regexes are unanchored and case-sensitive; add `(?i)` to ignore case. Watch for `?` in
query strings: `path=/v1/messages?beta=true` is a regex in which `s?` means "an optional `s`", so
it does not match that path; write `path=^/v1/messages\?beta=true`.

A comma starts a new condition only when what follows is a valid `key=` or `!key=`; otherwise it is
part of the value, so `path=~^/v\d{1,3}/` works.

## Status, errors and tunnels

A session's filters are checked twice. When a request arrives its status is unknown, so every
`status` condition (negated or not) counts as satisfied; when the exchange finishes it is checked
again with the real status and dropped if it no longer matches. So `--filter status=5xx` records
only failing calls, while `on_request`/`on_response` hooks still run for every call that matches
apart from its status (`on_event` hooks only see recorded ones).

An exchange that failed inside TAP (upstream unreachable, TLS failure, timeout) counts as status
`502`, the status its client received. An opaque tunnel has no status: `status=...` never matches
it and `!status=...` always does.

## Examples

```text
host=anthropic.com                           everything to Anthropic's API
host=anthropic.com,path=/v1/messages         just the Messages API
!host=telemetry.example.com                  everything except one host
status=5xx                                   server errors, including TAP's own 502s
host=api.openai.com,status=4xx               rejected OpenAI calls
!status=2xx                                  anything that did not succeed (and tunnels)
method=POST,header:content-type=json         JSON posts
header:x-stainless-lang=python               calls made by the Python SDKs
header:authorization=                        requests that carry an Authorization header
url=~/v1/(messages|complete)                 a regex over the URL
mode=tunnel                                  connections relayed without decrypting
```

In bash and zsh, quote anything starting with `!` (`'!status=2xx'`) so the shell leaves it alone.

`tap show` matches the stored records, where redacted header values are replaced (see the user
guide); match those headers by presence (`header:x-api-key=`), not by value.

A mistake is an error that names the spec and lists the valid keys:

```text
$ tap show llm status=5
tap: invalid filter "status=5": status must be a 3-digit code or a pattern like 4xx or 50x, got "5" (use ~ for a regex) in condition "status=5" (valid keys: method, scheme, host, port, path, url, mode, status, header:NAME)
```

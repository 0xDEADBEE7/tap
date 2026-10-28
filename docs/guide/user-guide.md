# User guide

## Sessions

A session is a local port plus a directory that holds its settings and captures. Its proxy runs in
the background, one process per session, and only listens on `127.0.0.1`.

```bash
tap create 8080 --label llm     # {"id":"e143...","label":"llm","port":"8080"}
tap start llm                   # {"id":"e143...","status":"running","port":"8080","proxy":"http://127.0.0.1:8080","pid":4242}
tap list --table                # STATUS LABEL PORT [UPSTREAM] EXCHANGES ID (plain tap list prints JSON)
tap stop llm
tap delete llm                  # removes the session and its captures; --force stops it first
```

Name a session by its label, its full id, or a unique id prefix of at least 4 characters. When you
leave it out, TAP uses the one running session. Labels use letters, digits, `-`, `_` and `.`, do
not start with `-`, and need at least one non-digit (numbers select exchanges in `tap show`). Each
port belongs to one session.

A session's settings live in its `metadata.json` (see [Settings](#settings)). `tap start` reads and
checks them; edit the file while the session is stopped, or restart it afterwards.

## Routing traffic

**One command.** `tap exec` runs a command with the session's proxy and CA variables set:

```bash
tap exec llm -- python3 my_agent.py
tap exec llm -- claude -p "hello"
```

It exits with the command's exit code. The session must be running.

**A whole shell.** `tap env` prints the same variables as `export` lines:

```bash
eval "$(tap env llm)"
python3 my_agent.py
```

`tap env llm --json` prints them as one JSON object, for scripts and other launchers.

What gets set: `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` = `http://127.0.0.1:PORT`
and `NODE_USE_ENV_PROXY=1`; for sessions that decrypt HTTPS also `NODE_EXTRA_CA_CERTS=ca.pem` and
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` = `bundle.pem` (the system roots plus the
TAP CA). What each client reads:

| Client | Proxy from | Trusts TAP via |
|---|---|---|
| curl | `HTTPS_PROXY`, lowercase `http_proxy` | `CURL_CA_BUNDLE` |
| Python requests | `HTTPS_PROXY` / `HTTP_PROXY` | `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` (not `SSL_CERT_FILE`) |
| Python httpx (Anthropic, OpenAI SDKs) | `HTTPS_PROXY` / `HTTP_PROXY` | `SSL_CERT_FILE` |
| Node fetch/undici, JS SDKs | `HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1` | `NODE_EXTRA_CA_CERTS` |
| Claude Code | `HTTPS_PROXY` | `NODE_EXTRA_CA_CERTS` |

`tap ca` prints the file paths and this table. A client not listed here needs its own proxy and CA
options: point them at `http://127.0.0.1:PORT` and at `ca.pem` (`tap ca --path`), or at `bundle.pem`
if the option replaces the trusted roots rather than adding to them.

## Base-URL mode (`--upstream`)

Many LLM clients let you change the API base URL. Point it at TAP and give the session the real
API as `--upstream`: the client then talks plain HTTP to TAP, TAP forwards over HTTPS, and no proxy
variables or CA are involved. Exchanges are recorded with mode `reverse`.

```bash
tap create 8081 --label claude-api --upstream https://api.anthropic.com
tap start claude-api
ANTHROPIC_BASE_URL=http://127.0.0.1:8081 claude -p "hello"

tap create 8082 --label openai --upstream https://api.openai.com/v1
tap start openai
OPENAI_BASE_URL=http://127.0.0.1:8082 python3 my_agent.py
```

TAP appends the request's path to the upstream URL: above, the OpenAI SDK asks TAP for
`/chat/completions` and TAP sends it to `https://api.openai.com/v1/chat/completions`. So put the
API's base path in one place only: `--upstream https://api.openai.com` with
`OPENAI_BASE_URL=http://127.0.0.1:8082/v1` works too, but `/v1` in both sends `/v1/v1/...`.

A session without `--upstream` answers such requests with `400` and an explanation. A session with
it still works as a normal proxy too.

## Reading captures

An exchange is recorded when it finishes, and numbered per session: `#1`, `#2`, ... Numbers keep
increasing across restarts; a gap is an exchange outside the session's filters or still running.

```bash
tap show llm                          # list: # TIME METHOD STATUS DURATION SIZE URL
tap show llm host=anthropic.com       # only matching exchanges (see filters.md)
tap show llm --last 5
tap show llm 12                       # one exchange in full
tap show llm 12 --full                # without cutting long bodies
tap show llm 12 --body res > res.bin  # the raw captured response bytes (req for the request)
tap show llm 12 --curl                # a curl command that sends the request again
tap show llm 12 --json                # the record, pretty-printed
tap show llm --json                   # one JSON line per exchange, for jq and scripts
tap tail llm                          # print new exchanges as they arrive, until Ctrl-C
tap tail llm --all status=4xx         # earlier ones first; filters work here too
```

In the list, STATUS is `ERR` when the exchange failed and `TUN` for an opaque tunnel; a failed
exchange shows its error after the URL.

The detail view decodes gzip, deflate and brotli bodies and pretty-prints JSON. Event streams
(SSE, as used by streaming LLM APIs) are listed event by event, followed by the assembled text.
Headers whose values were redacted appear as `[REDACTED len=N sha256=xxxxxxxx]`; `--curl` turns them
into shell variables you export first. `--body` writes the bytes exactly as stored (still
compressed if the response was), and refuses to print binary data to a terminal.

Colour is off with `--no-color`, when `NO_COLOR` is set, or when stdout is not a terminal.

## Choosing what is recorded

By default a session records everything that passes through it. Filters narrow that down:

```bash
tap create 8080 --label llm --filter host=anthropic.com --filter host=openai.com
```

Filters only decide what is recorded (and what hooks see). Traffic that does not match is still
forwarded, just not stored. See [filters.md](filters.md).

## Tunnel-only hosts

Some programs pin certificates (many Apple services do): they reject TAP's certificate even when
the CA is trusted. Relay those hosts without decrypting:

```bash
tap create 8080 --label llm --tunnel 'apple\.com$' --tunnel '^telemetry\.example\.com$'
```

`--tunnel` takes a regex matched against the `CONNECT` host (repeat it for more; for an existing
session edit its `tunnel` list and restart). A tunnelled connection is recorded with mode `tunnel`:
host, port, bytes each way and duration, no content. `--no-intercept` tunnels every `CONNECT`; such
a session needs no CA, and `tap env` then sets only the proxy variables.

## Redaction

By default records do not contain the values of these headers: `authorization`, `proxy-authorization`,
`x-api-key`, `api-key`, `x-goog-api-key`, `cookie`, `set-cookie`. Each value is replaced by
`[REDACTED len=108 sha256=b9d171cc]`: the length and the first 8 hex digits of its SHA-256, so you
can tell two keys apart without storing either. Upstream always receives the real value.

To change the list, edit `redact` in the session's `metadata.json` and restart it, e.g.
`"redact": ["authorization", "x-api-key", "openai-organization"]`; `[]` turns redaction off.
Only headers are redacted: secrets in URLs or bodies are recorded as they are.

## Body size limit

Each request and response body is stored up to 16 MiB. Larger bodies still pass through in full;
the record says `truncated: true` and keeps the first 16 MiB. Change it with `--max-body 64MB`
(`KB`/`MB`/`GB` are 1024-based) or `max_body` (bytes) in `metadata.json`.

## Settings

`tap create` writes `metadata.json`; you can edit it afterwards. `id`, `status` and `pid` are managed
by TAP.

| Field | Default | Meaning |
|---|---|---|
| `label` | `""` | name to use instead of the id |
| `port` | | local port, `127.0.0.1` only |
| `filters` | `[]` | capture scope ([filters.md](filters.md)); empty records everything |
| `hooks` | empty | programs to run per exchange ([hooks.md](hooks.md)) |
| `upstream` | `null` | base URL for base-URL mode |
| `intercept` | `true` | decrypt HTTPS; `false` = `--no-intercept` |
| `tunnel` | `[]` | host regexes relayed without decrypting |
| `redact` | see above | header names redacted in records |
| `max_body` | `16777216` | per-body capture limit in bytes |

## Where files live

```text
~/.config/tap/                 ($XDG_CONFIG_HOME/tap/ when set)
├── ca/
│   ├── ca.pem                 the TAP CA certificate (NODE_EXTRA_CA_CERTS)
│   ├── ca.key                 its private key, mode 0600: keep it private
│   └── bundle.pem             system roots + ca.pem (SSL_CERT_FILE and friends)
└── sessions/<id>/
    ├── metadata.json          settings and state
    ├── events.jsonl           the capture, one JSON event per line
    ├── bodies/<seq>.req|res   raw request and response bodies
    └── tap.log                the proxy's own log (starts, stops, async hook failures)
```

Directories are created mode 0700 and files 0600. Captures contain whatever your tools sent,
including prompts and any secret outside the redacted headers. The format is described in
[capture-format.md](capture-format.md).

## Troubleshooting

**Nothing is recorded.**
- `tap list --table`: is the session running? `tap show` on an empty session prints a checklist.
- The client may ignore proxy variables. Node's built-in `fetch` (and the JS SDKs built on it)
  only uses them with `NODE_USE_ENV_PROXY=1`, which `tap exec`/`tap env` set but older Node
  versions ignore; use base-URL mode for those.
- Apps started from a desktop launcher never see your shell's variables; start them with
  `tap exec`.
- The session's filters may exclude it: check `filters` in `metadata.json`.
- Exchanges appear when they finish; a long stream shows up once it ends. `tap tail` shows each one
  as soon as it is recorded.

**TLS or certificate errors in the client.** The client does not trust the TAP CA. `tap show`
lists the failed handshake as an `ERR` exchange (`CONNECT host:443`) saying so. Route the client
with `tap exec`/`tap env`, or set its own CA option to `tap ca --path`. If it still fails, the host
probably pins certificates: add it to the session's `tunnel` list. A client that trusts an older
TAP CA (after `ca/` was deleted, or with a different `XDG_CONFIG_HOME`) fails the same way.

**The client gets `502`.** TAP could not reach the upstream (DNS, refused connection, upstream TLS,
timeout). The response body and the `x-tap-error` header say why, and `tap show` has the same
error. TAP connects to upstreams directly (never through another proxy) and trusts the system
roots; to trust another CA for upstream TLS as well: `TAP_UPSTREAM_CA=/path/corp.pem tap start llm`.

**`tap start` fails.** It says why: the port is in use (with the `lsof` command that finds the
owner), or a setting in `metadata.json` is invalid (it names the field and the file). If the proxy
process itself dies on startup, it also prints the end of `tap.log`.

**"no session matches" a label you just used.** `metadata.json` no longer parses (a JSON typo, or
a missing required field such as a hook's `mode`), so the label cannot be read. `tap list --table`
shows the session as `INVALID` with the parse error; fix the file, or use the session's id.

**A session shows `running` but is not.** If its process died (reboot, `kill -9`), TAP notices the
next time it checks (`tap list`, `tap stop`, `tap exec`, ...) and marks it stopped (`tap stop`
reports `"stale": true`); `tap start` simply starts it again. `tap delete SESSION --force` removes
a session in any state.

# TAP

TAP (Traffic Access Proxy) shows you exactly what software on your machine sends and receives over
HTTP(S): the request your tool makes to an LLM API, the telemetry an app phones home with, the
response that made an SDK call fail. Run a command through a TAP session and every exchange is
recorded with full headers and bodies, including HTTPS, which TAP decrypts with a local CA. TAP
records what was on the wire and never changes traffic unless one of your hooks asks it to.

## Install

TAP needs a Rust toolchain and runs on macOS and Linux.

```bash
make build                     # release binary at bin/tap (cargo build: target/debug/tap)
export PATH="$PWD/bin:$PATH"
```

## Quickstart

```bash
tap create 8080 --label llm                # a session: a local port plus a capture directory
tap start llm                              # its proxy runs in the background
tap exec llm -- curl https://example.com   # run any command through the session
tap show llm                               # list what was recorded
tap show llm 1                             # exchange #1, decrypted: headers and bodies
tap stop llm                               # the capture stays until: tap delete llm
```

```text
$ tap show llm
#  TIME          METHOD  STATUS  DURATION   SIZE  URL
1  20:14:07.512  GET     200        183ms  1.2KB  https://example.com/
1 of 1 exchange
$ tap show llm 1
#1  GET https://example.com/
mitm · 2026-10-28 20:14:07.512 · ttfb 181ms · total 183ms · client 127.0.0.1:53422

Request
GET / HTTP/2
user-agent: curl/8.7.1
accept:     */*
...
```

## HTTPS and trust

To read HTTPS, TAP presents certificates signed by its own CA, created on first use in
`~/.config/tap/ca/` (`$XDG_CONFIG_HOME/tap/ca/` when set). `tap exec` and `tap env` make what they
route trust it, through the proxy and CA variables that curl, Python (requests, httpx, the
Anthropic and OpenAI SDKs), Node and Claude Code read ([details](guide/user-guide.md#routing-traffic)).
TAP never touches system trust stores; `tap ca` shows the files and how to trust the CA elsewhere.

Hosts that pin certificates can be relayed without decrypting (`--tunnel HOST`), and
`--no-intercept` turns decryption off for a whole session.

## Commands

```text
tap create PORT [--label NAME] [--upstream URL] [--filter SPEC]... [--tunnel HOST]...
                [--no-intercept] [--max-body BYTES]
tap start  SESSION                 start the session's proxy in the background
tap stop   [SESSION]               stop it (SIGTERM, then SIGKILL after 5s)
tap list   [--table]               all sessions (JSON, or a table)
tap delete SESSION [--force]       remove a session and its captures (--force stops it first)
tap show   [SESSION] [N | FILTER...] [options]   inspect recorded exchanges
tap tail   [SESSION] [FILTER...] [options]       follow new exchanges
tap env    [SESSION] [--json]      print `export ...` lines that route a shell through the session
tap exec   [SESSION] -- CMD [ARGS...]   run CMD routed through the session
tap ca     [--path]                create/show the local CA and how clients trust it
tap help
```

SESSION is a full id, a label, or a unique id prefix of at least 4 characters. When it is omitted,
the single running session is used. `create`, `start`, `stop`, `list` and `delete` print JSON;
the others print for humans. `tap help` has every option.

## Guides

- [User guide](guide/user-guide.md): sessions, routing traffic, base-URL mode, reading captures,
  tunnels, redaction, troubleshooting.
- [Filters](guide/filters.md): choose what a session records and what `tap show` lists.
- [Hooks](guide/hooks.md): run your own programs on requests, responses and finished exchanges.
- [Capture format](guide/capture-format.md): `events.jsonl` and `bodies/`, for your own tooling.

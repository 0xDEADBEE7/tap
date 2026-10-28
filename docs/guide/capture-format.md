# Capture format

Everything TAP records is in plain files, so you can build your own tools on top of it. A session
directory (`~/.config/tap/sessions/<id>/`) holds:

```text
events.jsonl        one JSON event per line, appended as exchanges finish
bodies/12.req       raw request body of exchange #12 (only when it had one)
bodies/12.res       raw response body of exchange #12
```

Lines are only ever appended. Exchanges are written when they finish, so with concurrent requests
`seq` is not always in file order. `tap show S --json` and `tap tail S --json` print the
same lines (exchanges only, filtered), which is often the easiest way in:

```bash
tap show llm --json host=anthropic.com | jq -r '.request.body.file'
```

## Events

Each line has a `type`:

- `session_start`: written each time the session's proxy starts:
  `{"type":"session_start","session_id":"9f1c...","at":"2026-10-28T06:29:42.123Z","pid":4242,"version":"0.2.0"}`
- `exchange`: one finished request and response (or tunnel), described below.

Skip lines you cannot parse (a crash can cut the last one short) or whose type you do not know.

## Exchange

```json
{"type":"exchange","seq":12,"session_id":"9f1c2e7a4b6d4e0f8a3b5c7d9e1f2a3b","started_at":"2026-10-28T06:29:42.123Z","started_unix_ms":1793168982123,"ttfb_ms":842,"duration_ms":845,"mode":"mitm","client_addr":"127.0.0.1:53422","request":{"method":"POST","url":"https://api.anthropic.com/v1/messages","scheme":"https","host":"api.anthropic.com","port":443,"path":"/v1/messages","version":"HTTP/1.1","headers":[["host","api.anthropic.com"],["accept","application/json"],["anthropic-version","2023-06-01"],["content-type","application/json"],["user-agent","Anthropic/Python 0.69.0"],["x-api-key","[REDACTED len=108 sha256=b9d171cc]"],["content-length","93"]],"body":{"size":93,"captured":93,"truncated":false,"complete":true,"file":"bodies/12.req"}},"response":{"status":200,"reason":"OK","version":"HTTP/1.1","headers":[["content-type","application/json"],["request-id","req_011CUZ8kQ3vZ"],["content-length","213"]],"body":{"size":213,"captured":213,"truncated":false,"complete":true,"file":"bodies/12.res"}},"tunnel":null,"error":null}
```

| Field | Meaning |
|---|---|
| `seq` | exchange number within the session (`tap show S 12`); increases across restarts |
| `session_id` | the session's id |
| `started_at`, `started_unix_ms` | when the request started: RFC 3339 UTC with milliseconds, and Unix milliseconds |
| `ttfb_ms` | request start until the response head arrived; `null` if it never did |
| `duration_ms` | request start until the response body (or tunnel) finished |
| `mode` | `forward` (plain `http://` via the proxy), `mitm` (decrypted inside `CONNECT`), `reverse` (base-URL mode), `tunnel` (relayed without decrypting) |
| `client_addr` | the client's address, e.g. `127.0.0.1:53422` |
| `request` | what the client sent, see below |
| `response` | what upstream returned, or `null` (failed exchanges and tunnels) |
| `tunnel` | `{"bytes_up": N, "bytes_down": N}` for tunnels and upgraded connections such as WebSockets, else `null` |
| `error` | why the exchange failed (upstream unreachable, TLS failure, timeout, ...), else `null` |
| `notes` | remarks such as hook changes and failures or truncation; left out when there are none |

`request`: `method`, `url` (absolute; `host:port` for tunnels), `scheme` (`tcp` for tunnels),
`host`, `port`, `path` (path plus query; empty for tunnels), `version` (`HTTP/1.0`, `HTTP/1.1` or
`HTTP/2`), `headers`, `body`. `response`: `status`, `reason`, `version`, `headers`, `body`.

`headers` is a list of `[name, value]` pairs in the order they were seen. Names are lowercase;
repeated headers (e.g. `set-cookie`) are kept as separate pairs. Redacted values look like
`[REDACTED len=108 sha256=b9d171cc]`: the value's length and the first 8 hex digits of its SHA-256.

`body`:

| Field | Meaning |
|---|---|
| `size` | bytes that passed through |
| `captured` | bytes saved to `file` (at most `max_body`) |
| `truncated` | `true` when `captured < size` because of `max_body` |
| `complete` | `false` when the client or upstream aborted the body mid-way |
| `file` | path relative to the session directory; left out when nothing was captured |

Body files hold the bytes exactly as they crossed the wire, after transfer framing (chunked) is
removed but before content decoding: a response with `content-encoding: gzip` is stored gzipped.
If a request or response hook changed a message, the record and the body files still hold the
original and `notes` says what changed. A sync `on_event` hook's output, by contrast, is what gets
written.

## Recipes

Find a session directory and list its exchanges:

```bash
S=~/.config/tap/sessions/$(tap list | jq -r '.sessions[] | select(.label=="llm") | .id')
jq -r 'select(.type=="exchange") | [.seq, .response.status, .request.url] | @tsv' "$S/events.jsonl"
```

Which models did the Messages API calls ask for:

```bash
tap show llm --json host=anthropic.com,path=/v1/messages |
  jq -r '.request.body.file // empty' | while read -r f; do jq -r .model "$S/$f"; done
```

Rust code can read the format with the types in `src/record.rs` (`Event`, `Exchange`).

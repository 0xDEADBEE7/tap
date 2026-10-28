# Hooks

A hook is a program TAP runs for each exchange in the session's scope, with one JSON object on
stdin. A **sync** hook can change what is forwarded by printing JSON back; an **async** hook is
only told, and TAP does not wait for it. Use hooks to inject headers, rewrite requests, or feed
exchanges into your own tooling as they happen.

## Configuration

Hooks live in the session's `metadata.json`; restart the session after editing it.

```json
"hooks": {
  "on_request":  [{"mode": "sync", "command": ["python3", "hooks/add_header.py"]}],
  "on_response": [],
  "on_event":    [{"mode": "async", "command": ["python3", "/home/me/hooks/log_event.py", "/tmp/llm-calls.tsv"],
                   "timeout_ms": 2000}]
}
```

- `mode` (`"sync"` or `"async"`) and `command` are required. Without `mode`, `metadata.json` does
  not parse and `tap list` shows the session as `INVALID`.
- `command` is an argv array. It is never run through a shell; the program is looked up on `PATH`,
  and relative paths are relative to the directory you ran `tap start` in.
- `timeout_ms` defaults to 5000 and may be 1 to 600000.
- `tap start` checks every hook and names the bad one, e.g.
  ``invalid hook: hooks.on_request[0] (`python3 h.py`): timeout_ms must be between 1 and 600000, got 0``.
- Hooks run only for exchanges inside the session's [filters](filters.md).
- Hooks inherit the environment of `tap start` without the proxy variables, so HTTP calls a hook
  makes do not loop back through TAP.

| Phase | A sync hook runs | and may change |
|---|---|---|
| `on_request` | before the request is forwarded | `method`, `path`, `headers`, `body` |
| `on_response` | when the response arrives, before the client gets it | `status`, `headers`, `body` |
| `on_event` | when the exchange has finished, before it is written | the record itself |

Within a phase, sync hooks run in order, each seeing the previous one's result; then the async
hooks get the final version.

## Input

`on_request`:

```json
{"type":"request","session_id":"9f1c...","seq":12,"method":"POST",
 "url":"https://api.anthropic.com/v1/messages","scheme":"https","host":"api.anthropic.com",
 "port":443,"path":"/v1/messages",
 "headers":[["content-type","application/json"],["x-api-key","sk-ant-..."]],
 "body":"{\"model\":\"claude-sonnet-4-5\",...}"}
```

`on_response`:

```json
{"type":"response","session_id":"9f1c...","seq":12,
 "request":{"method":"POST","url":"https://api.anthropic.com/v1/messages"},
 "status":200,"headers":[["content-type","application/json"]],"body":"{\"id\":\"msg_01...\",...}"}
```

A body that is not valid UTF-8 arrives as `"body": null` plus `"body_base64": "..."`. Request and
response hooks see the real headers, secrets included.

`on_event` gets the finished record exactly as it will be written to `events.jsonl`
([capture-format.md](capture-format.md)), already redacted. It has no bodies, and the
`bodies/<seq>.req|res` files it names are written only after event hooks run (or while async ones
do), so use a request or response hook if you need body content.

## Output

- Print nothing: no change.
- Print the object back with your changes. Fields you may not change (`url`, `host`, `seq`, ...)
  are ignored, with a note. `headers` replaces the whole list, so append to the list you were
  given; it may also be an object `{"name": "value"}`, and names are lowercased. To set binary
  content print a `body_base64` string, which wins over `body`. When the body changes, TAP fixes
  `content-length`.
- A sync `on_event` hook may print a record (or just the top-level fields to replace); `seq` and
  `session_id` must stay the same. What it prints is what gets written.

Request and response hook changes are not stored: the record keeps what the client sent and what
upstream returned, and its notes list the changes. `tap show` prints them:

```text
note: on_request hook `python3 hooks/add_header.py`: changed headers
```

## Failures and timeouts

A hook that cannot start, exits non-zero, times out, or prints invalid JSON or an invalid value
(say, a `path` without a leading `/`) leaves the message unchanged, and the record gets a note
saying why (with the first line of its stderr):

```text
note: on_request hook `python3 hooks/add_header.py`: exited with status 1: Traceback (most recent call last):; unchanged
note: on_request hook `python3 slow.py`: timed out after 5000ms; unchanged
```

On timeout the hook and everything it started in its process group are killed. Async hook
failures go to the session's `tap.log`. A sync hook holds up its exchange until it finishes, so keep it quick and its timeout
short.

## Example: add a header (sync `on_request`)

Configured as `hooks/add_header.py` in [Configuration](#configuration).

```python
#!/usr/bin/env python3
"""Sync on_request hook: add a header to every in-scope request."""
import json
import sys

message = json.load(sys.stdin)
message["headers"].append(["x-tap-trace", "on"])
json.dump(message, sys.stdout)
```

## Example: log every exchange (async `on_event`)

Configured as `log_event.py` in [Configuration](#configuration), with the log file as its argument.

```python
#!/usr/bin/env python3
"""Async on_event hook: append one summary line per exchange to a file."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "tap-events.log"
exchange = json.load(sys.stdin)
request = exchange["request"]
response = exchange.get("response") or {}
status = response.get("status") or ("ERR" if exchange.get("error") else "-")
with open(path, "a") as log:
    log.write(f'{exchange["seq"]}\t{status}\t{request["method"]}\t{request["url"]}\n')
```

```text
$ tail -f /tmp/llm-calls.tsv
7	200	POST	https://api.anthropic.com/v1/messages
8	ERR	POST	https://api.openai.com/v1/chat/completions
```

## The buffering trade-off

Normally bodies stream straight through TAP. A sync `on_request` hook needs the whole request body
before anything is forwarded, and a sync `on_response` hook needs the whole response body before
the client gets any of it. So in an exchange with such hooks that body is buffered: a streamed
(SSE) LLM response reaches the client all at once at the end instead of token by token.

Async hooks and `on_event` hooks never hold up traffic. Async request/response hooks (when no sync
hook runs in that phase) get the captured body, up to the session's `max_body`, after the exchange
has finished. Use filters to keep sync hooks to the exchanges that need them.

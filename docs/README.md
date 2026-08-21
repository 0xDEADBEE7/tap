# TAP

Traffic Access Proxy for inspecting and transforming HTTP traffic from the shell.

## Quickstart

```bash
make build
./bin/tap proxy
```

Use TAP as an explicit proxy:

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
curl https://example.com/
```

HTTPS `CONNECT` is currently tunneled. Certificate commands exist for the planned MITM implementation.

## Filtering

Filters are regular expressions. A single `--filter` uses comma-separated AND conditions; repeated options are ORed:

```bash
./bin/tap proxy --filter 'method=^GET$,host=^api\\.example\\.com$,path=^/api/'
./bin/tap proxy --filter 'header:^x-tenant$=^acme$' --filter 'status=^5'
```

Supported fields are `method`, `scheme`, `host`, `port`, `path`, and `status`. Header keys are matched case-insensitively. `--host` and `--match` remain compatibility aliases for host and path filters.

## Current architecture

```text
request
  → request filter
  → sync on_request hooks
  → async on_request observers
  → upstream
  → sync on_response hooks
  → async on_response observers
  → client
  → event filter
  → sync on_event hooks
  → async on_event observers
  → events.jsonl
```

Session metadata is stored under the platform configuration directory in `tap/sessions/<id>/metadata.json`. It can contain `filters` and phase-specific `hooks`:

```json
{
  "filters": ["host=^api\\.example\\.com$"],
  "hooks": {
    "on_request": [{"mode": "sync", "command": ["rewrite-request"]}],
    "on_response": [{"mode": "sync", "command": ["redact-response"]}],
    "on_event": [{"mode": "async", "command": ["notify"]}]
  }
}
```

Hooks receive JSON on stdin. Commands are never run through a shell. Sync output must be a valid JSON object with immutable identity fields unchanged; failures are logged and the original value continues. Async hooks observe without changing traffic or persisted data and have stdout/stderr detached.

## Limitations

- HTTPS `CONNECT` is tunneled; TLS MITM is not yet integrated.
- Hook concurrency is not yet globally bounded.
- Hook timeout applies to synchronous hooks; asynchronous hooks are detached.
- Event IDs are currently request-scoped placeholders and should be replaced with a connection event ID.

## Process management

```bash
./bin/tap ps
./bin/tap kill PID
```

- [MVP specification](mvp.md)
- [UX patterns](guide/ux-patterns.md)
- [Build targets](../Makefile)
- [Source layout](../src/)

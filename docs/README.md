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

## Hooks

The hook execution foundation accepts JSON on stdin and uses an argument array rather than a shell command. Synchronous hooks can return a replacement JSON object; invalid results preserve the original object. Asynchronous hooks observe the value and do not transform it. Session configuration and event persistence are still being integrated.

## Process management

```bash
./bin/tap ps
./bin/tap kill PID
```

- [MVP specification](mvp.md)
- [UX patterns](guide/ux-patterns.md)
- [Build targets](../Makefile)
- [Source layout](../src/)

# TAP

Traffic Access Proxy for inspecting and transforming HTTP traffic from the shell.

## Quickstart

Build the binary:

```bash
make build
```

Start TAP on the default address, `127.0.0.1:8080`:

```bash
./bin/tap proxy
```

Use TAP as an explicit HTTP or HTTPS proxy:

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
curl https://example.com/
```

TAP supports HTTP requests and HTTPS `CONNECT` tunneling. HTTPS MITM interception requires a trusted TAP CA; initialize one with:

```bash
./bin/tap cert init
./bin/tap cert path
```

Install the printed `ca.crt` only in the application or test environment that should trust TAP. TAP never changes system trust stores automatically.

## Useful options

```bash
./bin/tap proxy --listen 127.0.0.1:9000
./bin/tap proxy --host api.example.com
./bin/tap proxy --match '/api/*'
./bin/tap proxy --json
```

### Process management

List running TAP proxies and their listening ports:

```bash
./bin/tap ps
```

Stop one by PID:

```bash
./bin/tap kill PID
```

List and kill now query live process arguments with `ps`; no `.tap/running` registry is written. A process only matches when its command is exactly an executable named `tap` followed by `proxy`, so unrelated processes are excluded.

- [MVP specification](mvp.md)
- [UX patterns](guide/ux-patterns.md)
- [Build targets](../Makefile)
- [Source layout](../src/)

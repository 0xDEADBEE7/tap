# TAP

Traffic Access Proxy for inspecting and transforming HTTP traffic.

## Commands

```text
usage: tap create PORT | start ID | stop ID | list
```

Create a durable session, then control it by ID:

```bash
make build
./bin/tap create 8080
./bin/tap list
./bin/tap start ID
./bin/tap stop ID
```

`start` launches the proxy in the background; no supported command runs it in the foreground. Session metadata and logs are stored under the platform configuration directory:

```text
tap/sessions/<id>/metadata.json
tap/sessions/<id>/tap.log
tap/sessions/<id>/events.jsonl
```

Applications use the configured port as a conventional HTTP proxy:

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
curl https://example.com/
```

Session metadata may contain filters and phase-specific hooks. Hooks receive JSON on stdin and are never run through a shell. HTTPS `CONNECT` is currently tunneled; TLS MITM is not yet integrated.

- [User guide](guide/user-guide.md)

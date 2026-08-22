# User guide

TAP runs proxy sessions in the background. The public command surface is:

```text
usage: tap create PORT | start ID | stop ID | list
```

## 1. Build TAP

```bash
cargo build
# or: make build
```

The smoke test uses `target/debug/tap` by default. Set `TAP_BIN` to use another binary.

## 2. Create a session

Choose a local proxy port and save the returned ID:

```bash
SESSION_ID=$(./target/debug/tap create 8080 | jq -r .id)
echo "$SESSION_ID"
```

`create` writes durable state under:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/tap/sessions/<ID>/
├── metadata.json
├── events.jsonl
└── tap.log
```

## 3. Configure the session

Edit `metadata.json` before starting it. For example, this limits traffic to `/smoke` on localhost and adds a synchronous request hook:

```json
{
  "filters": ["host=^127\\.0\\.0\\.1$,path=^/smoke$"],
  "hooks": {
    "on_request": [{
      "mode": "sync",
      "command": ["python3", "scripts/smoke-hook.py"]
    }]
  }
}
```

A synchronous hook receives the request JSON on stdin and must print the modified JSON. Commands are executed directly, not through a shell.

## 4. Start the session

```bash
./target/debug/tap start "$SESSION_ID"
./target/debug/tap list
```

`start` returns immediately. Configure applications to use the session port:

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
curl --noproxy '' http://example.test/
```

## 5. Stop and inspect it

```bash
./target/debug/tap stop "$SESSION_ID"
cat "$HOME/.config/tap/sessions/$SESSION_ID/metadata.json"
cat "$HOME/.config/tap/sessions/$SESSION_ID/events.jsonl"
cat "$HOME/.config/tap/sessions/$SESSION_ID/tap.log"
```

Use `$XDG_CONFIG_HOME` instead of `$HOME/.config` when it is set.

## Smoke test

Run the included end-to-end check after building:

```bash
scripts/smoke-test.sh
```

It starts a temporary Python upstream server, creates and configures a TAP session, starts it, sends one filtered curl request, and verifies that the request hook adds `X-Smoke-Hook: active`.

A successful run prints:

```text
smoketest passed: filter matched and hook added X-Smoke-Hook
```

The script then prints the stopped session's metadata, request/response events, and log. The log includes entries like:

```text
TAP listening on 127.0.0.1:<proxy-port>
SEND GET 127.0.0.1/smoke
RECV 200 127.0.0.1/smoke (GET)
```

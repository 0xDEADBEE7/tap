# UX Patterns

TAP is designed for short, composable shell workflows. Keep the proxy in the foreground and configure clients with standard proxy environment variables.

## Start and stop

```bash
./bin/tap proxy
./bin/tap proxy --listen 127.0.0.1:9000
```

Run TAP in one terminal and the client command in another. Press `Ctrl-C` to stop it.

## Scope traffic

Limit traffic to a host:

```bash
./bin/tap proxy --host api.example.com
```

Limit traffic to a path prefix:

```bash
./bin/tap proxy --match '/api/*'
```

Combine both filters when investigating a specific service:

```bash
./bin/tap proxy --host api.example.com --match '/api/*'
```

## Configure clients

Use environment variables for one command:

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
curl https://api.example.com/users
```

For tools that honor lowercase variables:

```bash
http_proxy=http://127.0.0.1:8080 \
https_proxy=http://127.0.0.1:8080 \
curl http://example.com/
```

## Machine-readable output

Emit JSONL for pipelines and logs:

```bash
./bin/tap proxy --json
```

Select failures with `jq`:

```bash
./bin/tap proxy --json | jq 'select(.status >= 400)'
```

Capture an investigation for later analysis:

```bash
./bin/tap proxy --json > traffic.jsonl
```

## CA lifecycle

Create the local CA once:

```bash
./bin/tap cert init
```

Print its certificate path when configuring a test client:

```bash
./bin/tap cert path
```

Trust the CA only in disposable or explicitly controlled environments. Do not share `~/.tap/ca.key`.

## Troubleshooting

- Confirm TAP is listening on the expected address.
- Check that the client is using `HTTP_PROXY` and `HTTPS_PROXY`.
- Use `--host` and `--match` to reduce noisy traffic.
- For HTTPS interception, verify that the client trusts `ca.crt`.
- Use HTTP first to validate proxy configuration before debugging TLS.

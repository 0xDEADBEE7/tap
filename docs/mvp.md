# TAP — Traffic Access Proxy

## Overview

**TAP (Traffic Access Proxy)** is a lightweight, programmable interception proxy designed primarily for penetration testing, debugging, and traffic analysis.

TAP is implemented in Rust and distributed as a single CLI binary. It is designed to compose naturally with shells, scripts, and other Unix tooling.

The MVP focuses on doing one thing well:

> Intercept HTTP and HTTPS traffic, expose it in a useful machine-readable form, and allow requests and responses to be inspected and modified.

TAP runs as a foreground process by default. It is not a daemon.

---

## Goals

The MVP should:

* Proxy HTTP and HTTPS traffic.
* Support standard explicit HTTP proxy semantics.
* Perform HTTPS MITM interception.
* Generate certificates dynamically from a local TAP CA.
* Inspect HTTP requests and responses.
* Modify requests and responses.
* Produce structured output suitable for scripts.
* Support simple traffic filtering.
* Run as a single self-contained CLI binary.
* Handle many concurrent connections efficiently.

The MVP should remain small enough that the architecture can evolve as TAP's use cases become clearer.

---

## Non-Goals

The initial version does **not** need:

* Transparent proxying.
* SOCKS proxying.
* HTTP/3 or QUIC.
* A graphical or terminal UI.
* Daemon operation.
* Remote control.
* Persistent sessions.
* WebSocket-specific tooling.
* A plugin ecosystem.
* Complex scripting runtimes.
* Automated vulnerability scanning.

These can be added later without defining the architecture around them prematurely.

---

# CLI

The basic invocation is:

```bash
tap proxy
```

By default TAP listens on:

```text
127.0.0.1:8080
```

A different address can be specified:

```bash
tap proxy --listen 127.0.0.1:9000
```

Applications can then use TAP as a conventional HTTP proxy:

```bash
HTTP_PROXY=http://localhost:8080 \
HTTPS_PROXY=http://localhost:8080 \
my-program
```

The application continues making requests to their real destinations.

For example:

```bash
HTTPS_PROXY=http://localhost:8080 \
curl https://api.example.com/users
```

The effective flow is:

```text
curl
 │
 │ CONNECT api.example.com:443
 ▼
TAP
 │
 │ TLS
 ▼
api.example.com
```

---

# Proxy Operation

## HTTP

For a normal HTTP proxy request, the client sends TAP an absolute URI:

```http
GET http://api.example.com/users HTTP/1.1
Host: api.example.com
```

TAP determines:

```text
scheme = http
host   = api.example.com
port   = 80
path   = /users
```

It establishes the upstream connection and forwards the request.

---

## HTTPS

HTTPS uses the HTTP `CONNECT` method.

The client sends:

```http
CONNECT api.example.com:443 HTTP/1.1
```

TAP now knows the requested upstream destination.

Instead of simply tunnelling opaque TLS traffic, TAP terminates TLS itself.

```text
             TLS #1                 TLS #2

Client  <---------------->  TAP  <---------------->  Server
        TAP certificate             Real certificate
```

TAP generates a certificate for `api.example.com` signed by the local TAP CA.

The client must therefore trust the TAP CA.

Once TLS is established, TAP can parse the decrypted HTTP traffic normally.

---

# Certificate Authority

TAP maintains a local CA used exclusively for interception.

For example:

```text
~/.tap/
├── ca.crt
└── ca.key
```

The CLI should provide:

```bash
tap cert init
tap cert path
```

`tap cert init` creates the CA if one does not already exist.

The user can then explicitly install `ca.crt` into the trust store used by the application under test.

TAP should never silently modify system trust stores.

When intercepting:

```text
CONNECT api.example.com:443
```

TAP dynamically creates an appropriate leaf certificate:

```text
CN / SAN: api.example.com
Issuer:   TAP CA
```

Generated certificates can be cached for reuse.

---

# Request Pipeline

Once traffic has been decoded, requests pass through a common pipeline.

```text
Client connection
       │
       ▼
Protocol handling
       │
       ▼
TLS interception
       │
       ▼
HTTP request
       │
       ▼
Request interceptors
       │
       ▼
Upstream
       │
       ▼
HTTP response
       │
       ▼
Response interceptors
       │
       ▼
Client
```

This pipeline should form the core abstraction of TAP.

The networking implementation should not need to know about individual pentesting features.

---

# Traffic Model

Internally TAP should expose normalized request and response structures roughly representing:

```text
Request
├── method
├── scheme
├── host
├── port
├── path
├── headers
└── body

Response
├── status
├── headers
└── body
```

Interceptors operate against these structures rather than directly against sockets.

This allows later features to reuse the same interception API.

---

# Interceptors

The core should support hooks conceptually equivalent to:

```text
on_request
on_response
```

An interceptor can:

```text
inspect
modify
continue
```

For example, an interceptor could change:

```http
Authorization: Bearer abc
```

into:

```http
Authorization: Bearer xyz
```

without the networking layer caring why the modification occurred.

The MVP can implement built-in interceptors rather than exposing a public plugin API immediately.

---

# Filtering

Traffic should be filterable so that pentesting against a busy application does not produce overwhelming output.

For example:

```bash
tap proxy --host api.example.com
```

or:

```bash
tap proxy --match '/api/*'
```

The initial filtering language should remain deliberately simple.

Useful primitives include:

```text
host
method
path
status
```

A richer expression language can be introduced later if necessary.

---

# Output

TAP should work well interactively:

```text
→ GET api.example.com/users
← 200 api.example.com/users  12ms

→ POST api.example.com/login
← 401 api.example.com/login  43ms
```

It should also expose structured output:

```bash
tap proxy --json
```

Each event is emitted as JSONL:

```json
{"type":"request","id":"42","method":"GET","host":"api.example.com","path":"/users"}
{"type":"response","id":"42","status":200,"duration_ms":12}
```

This makes TAP naturally composable:

```bash
tap proxy --json | jq 'select(.status >= 400)'
```

and:

```bash
tap proxy --json > traffic.jsonl
```

The event schema should be considered a stable interface of TAP.

---

# Runtime Architecture

TAP uses an asynchronous runtime.

A rough internal structure is:

```text
tap
 │
 ├── cli
 │
 └── proxy runtime
      │
      ├── listener
      │
      ├── connection tasks
      │
      ├── TLS / CA
      │
      ├── HTTP handling
      │
      ├── interception pipeline
      │
      └── output
```

Each client connection is handled independently by the async runtime.

A likely Rust stack is:

```text
tokio
hyper
rustls
clap
serde
serde_json
```

Additional dependencies should be introduced only when they provide substantial value.

---

# Suggested Source Layout

```text
src/
├── main.rs
├── cli.rs
│
├── proxy/
│   ├── mod.rs
│   ├── listener.rs
│   ├── connection.rs
│   └── upstream.rs
│
├── http/
│   ├── mod.rs
│   ├── request.rs
│   └── response.rs
│
├── tls/
│   ├── mod.rs
│   ├── ca.rs
│   └── cert.rs
│
├── intercept/
│   ├── mod.rs
│   ├── pipeline.rs
│   └── filter.rs
│
└── output/
    ├── mod.rs
    ├── human.rs
    └── json.rs
```

The exact structure should be allowed to evolve during implementation rather than being treated as a rigid contract.

---

# MVP Milestones

### 1. HTTP Proxy

Implement:

```bash
tap proxy
```

and successfully proxy ordinary HTTP traffic.

### 2. CONNECT Tunnelling

Support:

```http
CONNECT host:443
```

Initially this can simply tunnel encrypted traffic without inspection.

### 3. TAP Certificate Authority

Implement local CA creation and dynamic host certificates.

### 4. HTTPS Interception

Terminate client TLS, establish independent upstream TLS, and proxy decrypted HTTP requests and responses.

### 5. Inspection Pipeline

Normalize traffic into TAP request/response objects and pass them through interceptors.

### 6. Output

Provide concise human-readable traffic output and stable JSONL output.

### 7. Filtering and Modification

Add basic matching and built-in request/response modification.

At this point TAP constitutes a useful MVP.

---

# Future Direction

Once the core is proven, TAP can expand toward:

```text
TAP
├── explicit proxy
├── transparent proxy
├── capture / replay
├── WebSockets
├── HTTP/2
├── scripting
├── plugins
├── request mutation
├── fuzzing
├── traffic diffing
└── pentesting-specific analysis
```

A particularly valuable future capability is:

```bash
tap transparent
```

where operating-system networking rules redirect traffic through TAP without applications needing to be configured to use a proxy.

Another natural extension is a scripting interface that allows TAP to become a programmable traffic transformation engine rather than accumulating every pentesting feature directly in the core.

---

# Design Principle

TAP should remain fundamentally a **traffic primitive**, not an all-in-one security suite.

Its job is:

```text
intercept
    ↓
understand
    ↓
expose
    ↓
modify
    ↓
forward
```

Higher-level pentesting workflows can then be implemented by composing TAP with scripts, shell tools, or future TAP extensions.

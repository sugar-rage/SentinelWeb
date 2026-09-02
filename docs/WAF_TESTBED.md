# SentinelWeb reverse-proxy WAF and vulnerable testbed

## Architecture and request flow

The public proxy entry point accepts `GET`, `POST`, `PUT`, `PATCH`, `DELETE`,
`OPTIONS`, and `HEAD` at `/waf/{path}`. It is intentionally
separate from the authenticated scanner API and does not call `/api/scan` over HTTP.

```text
client request
  -> bounded request reader
  -> normalized path/query/safe-header/JSON/form/text components
  -> existing rule detectors + MLPredictor
  -> multi-vector risk policy (block at risk >= 80)
     -> blocked: safe HTTP 403, database evidence, no upstream request
     -> allowed: fixed upstream forward, upstream response returned, database outcome
```

Each request receives a UUID correlation ID. `waf_events`, `request_logs`, and any
per-vector `attack_logs` rows share that ID and are linked after the request completes.
Attack findings record the responsible component (for example `query.q`, `body.prompt`,
or `form.username`). Existing `/api/scan` contracts and behavior are unchanged.

## Configuration

The default target is the local testbed:

```dotenv
WAF_UPSTREAM_URL=http://127.0.0.1:9000
WAF_UPSTREAM_ALLOWED_HOSTS=127.0.0.1,localhost
WAF_UPSTREAM_TIMEOUT_SECONDS=5
WAF_MAX_REQUEST_BODY_BYTES=65536
```

The URL is server configuration, never client input. Its scheme and host are validated;
credentials, query strings, fragments, and hosts outside the explicit allowlist are rejected.

## Start and demonstrate locally

Apply migrations and start both processes in separate terminals:

```powershell
cd backend
.\venv\Scripts\python.exe -m alembic upgrade head
.\venv\Scripts\python.exe scripts\run_server.py
```

```powershell
cd backend
.\venv\Scripts\python.exe -m uvicorn testbed.app:app --app-dir .. --host 127.0.0.1 --port 9000
```

Direct SQL injection reaches the deliberately unsafe SQLite query:

```text
GET http://127.0.0.1:9000/login?username=admin%27%20--&password=wrong
```

The same request through `http://127.0.0.1:8000/waf/login?...` returns 403 and never
reaches `/login`. Direct `/search?q=<script>...</script>` reflects unsafe HTML, while
the WAF path blocks it. Direct `POST /chat` deterministically accepts “Ignore previous
instructions”; the WAF blocks that JSON before forwarding. Benign `/echo` and `/chat`
requests pass through and return the upstream response.

The testbed exposes local request counters at `/testbed/requests` and a reset endpoint
at `/testbed/reset` to demonstrate non-arrival of blocked traffic.

## Security boundaries and limitations

- The testbed is intentionally vulnerable, uses only its own SQLite database, has no
  SentinelWeb authentication, and must never be exposed or deployed.
- Authorization, Cookie, Host, hop-by-hop, and internal headers are not forwarded.
- Only a small allowlist of request/response headers crosses the proxy boundary.
- Request bodies are streamed into a bounded buffer; malformed JSON, unsupported body
  types, invalid lengths, and oversized bodies receive correlated safe errors.
- Upstream redirects are not followed. Timeouts/unavailability return safe 504/502 errors.
- Evidence is redacted, truncated, and hashed. Headers and credentials are not stored.
- This phase is a demonstrable application-layer WAF, not a replacement for a hardened
  edge proxy, TLS termination, network isolation, distributed limits, or a commercial WAF.

The proxy supports GET, POST, PUT, PATCH, DELETE, OPTIONS, and HEAD through the
same inspection, adaptive-risk, logging, and forwarding path. Forwarding headers
are untrusted unless the immediate socket peer is explicitly included in
`TRUSTED_PROXY_IPS`; see `backend/SECURITY.md` for chain resolution behavior.
Use the supplied launcher, which disables Uvicorn's separate forwarding-header
rewriting so the application always sees the real socket peer before applying
that policy.

Resource limits cover request bodies, URLs, aggregate headers, JSON nesting, form
field count, upstream response size, and concurrent WAF work. Responses are read
incrementally and terminated if the configured maximum is exceeded.

## Tests

From `backend/`:

```powershell
.\venv\Scripts\python.exe -m pytest -q
```

The Phase 3 cases are in `tests/test_waf_and_testbed.py` and use a fixed mock transport
to prove blocked requests never invoke the upstream. Final verification also starts both
real HTTP services and compares direct-testbed and through-WAF request counters.

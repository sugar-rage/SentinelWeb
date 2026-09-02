# SentinelWeb backend security operations

## Database migrations

SentinelWeb uses Alembic. Do not create production tables with SQLAlchemy
`create_all()`.

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

The Phase 2 migration is additive and preserves legacy rows. Historical attack
and request records retain nullable relationship/correlation fields because the
missing association cannot be reconstructed safely.

## Production configuration

Set `SENTINELWEB_ENV=production` and provide these environment values:

- `DATABASE_URL`
- `JWT_SECRET` with at least 32 characters
- `CORS_ORIGINS` as a comma-separated allowlist

The application refuses production startup when these values are absent or the
JWT secret is weak. `.env` remains ignored by Git; `.env.example` contains only
placeholders.

## JWT secret rotation

JWT secrets remain environment-managed and must never be committed. To rotate:

1. Generate a new cryptographically random secret of at least 32 characters.
2. Schedule a short maintenance window or accept that all current bearer tokens
   will be invalidated immediately; SentinelWeb deliberately does not retain old
   signing keys.
3. Replace `JWT_SECRET` in the deployment environment and restart every backend
   worker with the same new value.
4. Revoke active rows in `session_logs` if the deployment requires explicit audit
   evidence of the forced logout.
5. Confirm login, logout, revoked-token rejection, and production configuration
   validation before restoring traffic.

Production startup rejects the built-in development secret, known placeholder
secrets, and values shorter than 32 characters.

## Browser bearer token decision

The REST API retains Authorization bearer tokens because the academic test suite,
CLI clients, and WAF tooling use that contract. The React client stores its token
in `sessionStorage` rather than persistent `localStorage`, limiting persistence to
one browser tab. This storage is still readable by JavaScript and therefore relies
on preventing XSS. A cookie conversion was not introduced because a correct design
would also require CSRF tokens, cookie-domain/deployment decisions, and a coordinated
API contract migration. Production-facing deployments should prefer short-lived
HttpOnly, Secure, SameSite cookies with explicit CSRF protection.

## Trusted proxies

`X-Forwarded-For` and `Forwarded` are ignored by default. Set `TRUSTED_PROXY_IPS`
to explicit IP addresses or CIDR networks only when SentinelWeb is behind a proxy
that overwrites client forwarding headers. The resolver walks the chain from the
socket peer toward the client and selects the first untrusted address. Malformed,
ambiguous, or conflicting forwarding headers fall back to the socket peer.
Always launch with `python scripts/run_server.py` (or pass
`--no-proxy-headers` to Uvicorn). Uvicorn's built-in proxy-header processing is
intentionally disabled because it would rewrite the socket peer before the
application can enforce `TRUSTED_PROXY_IPS`.

## WAF resource boundaries

The WAF bounds request body, URL, aggregate header, JSON depth, form-field count,
upstream response size, and concurrent processing. The upstream HTTP client is
reused for connection pooling during the application lifespan and never forwards
Authorization or Cookie credentials.

## Initial administrator

There is no public admin registration or promotion endpoint. Configure an
independent `ADMIN_BOOTSTRAP_SECRET` of at least 32 characters and run:

```powershell
.\venv\Scripts\python.exe scripts\bootstrap_admin.py --username admin --email admin@example.com
```

The command prompts for both secrets, records an audit event, and refuses to run
when an administrator already exists. Remove or rotate the bootstrap secret
after provisioning.

## Sessions and audit evidence

JWTs contain random session and token identifiers. Only a SHA-256 digest of the
token identifier is stored. Logout marks the server-side session terminated, so
the JWT is rejected immediately.

Request logs store method, path, timing, status, correlation ID, and session
association. They never store headers or bodies. Attack evidence is redacted,
bounded to 4,096 characters by default, and accompanied by a SHA-256 digest of
the complete submitted payload. Passwords, bearer tokens, and authorization
headers are excluded from structured audit events.

The lightweight authentication limiter is process-local. A shared limiter such
as Redis is still required before horizontally scaling the API across multiple
workers or hosts.

## Reverse-proxy WAF

The WAF forwards only to `WAF_UPSTREAM_URL`, whose host must be present in
`WAF_UPSTREAM_ALLOWED_HOSTS`. Clients cannot provide a destination. Authorization,
Cookie, Host, hop-by-hop, and SentinelWeb internal headers are never forwarded.
Body size, content type, encoding, JSON syntax, and upstream timeout are bounded.
Redirects are returned but never followed.

`waf_events` stores request metadata, policy outcome, risk, and upstream status.
It stores no headers or body. Per-vector evidence in `attack_logs` uses the same
redaction, truncation, and digest controls as the scanner.

The application under `../testbed` is deliberately exploitable. It must be bound
to loopback, kept isolated from the SentinelWeb PostgreSQL database, and never deployed.
See `../docs/WAF_TESTBED.md` for the complete boundary and demonstration flow.

## Adaptive risk and authorization

Detected traffic receives bounded, linearly decayed history bonuses for repetition,
frequency, recent blocks, same-endpoint targeting, and attack-type diversity. Benign
current traffic never receives a history bonus. Queries use a 15-minute default window
and a 200-row maximum. The complete formula is documented in
`../docs/PHASE4_BACKEND.md`.

The role permission matrix separates user, developer, security analyst, and administrator.
Public registration cannot create privileged roles. History endpoints are paginated and
never return raw payloads, session identifiers, token hashes, passwords, or JWTs.

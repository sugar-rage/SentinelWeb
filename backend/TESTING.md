# Backend testing

Run the isolated backend suite from `backend/`:

```powershell
.\venv\Scripts\python.exe -m pytest -q
```

Pytest uses a dedicated PostgreSQL database. Set `TEST_DATABASE_URL` to a URL
whose database name contains `test`, for example
`postgresql://user:password@localhost:5432/sentinelweb_test`. If it is omitted,
the fixture derives `sentinelweb_test` from the configured development URL and
creates that database when the configured PostgreSQL user has permission.
The developer `sentinelweb` database is never reset or used for pytest data.

Apply development/production database migrations with:

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

Provision the first administrator locally (there is no public admin endpoint):

```powershell
$env:ADMIN_BOOTSTRAP_SECRET = "an-independent-random-secret-at-least-32-characters"
.\venv\Scripts\python.exe scripts\bootstrap_admin.py --username admin --email admin@example.com
```

The command prompts for the bootstrap secret and password, refuses to run after
an administrator exists, and never logs either secret.

## Scanner limits

- Individual scan payload: **32,768 characters**.
- Batch scan request: **100 payloads**.
- WAF request body: **65,536 bytes** by default (`WAF_MAX_REQUEST_BODY_BYTES`).

Oversized requests are rejected with FastAPI validation status `422`; payloads
are never silently truncated.

## Additional regression commands

```powershell
.\venv\Scripts\python.exe test_e2e.py
.\venv\Scripts\python.exe test_ml_eval.py
.\venv\Scripts\python.exe test_db.py
```

Phase 3 WAF/testbed tests are included in pytest. The full local HTTP demonstration
and two-process startup commands are documented in `../docs/WAF_TESTBED.md`.

## Standalone E2E isolation

`test_e2e.py` is self-contained and must not be run against a development database.
It uses `TEST_DATABASE_URL` when set; otherwise it derives a database name ending in
`_test`, starts its own backend on port 8010, preserves all 36 checks, and removes the
generated test schema afterward.

Phase 4 adaptive-risk and analytics behavior is covered by
`tests/test_phase4_adaptive_risk.py` and `tests/test_phase4_analytics_and_access.py`.

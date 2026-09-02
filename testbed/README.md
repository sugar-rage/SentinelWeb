# SentinelWeb intentionally vulnerable testbed

This application is deliberately vulnerable and exists only to demonstrate WAF prevention.
Run it on loopback only. Never deploy it or expose port 9000 to a network.

It uses its own SQLite database (`testbed.sqlite3`) and shares no authentication, storage,
or database connection with SentinelWeb.

From `backend/`, start it with:

```powershell
.\venv\Scripts\python.exe -m uvicorn testbed.app:app --app-dir .. --host 127.0.0.1 --port 9000
```

Endpoints:

- `GET /login`: deliberately interpolates credentials into an isolated SQLite query.
- `GET /search`: deliberately reflects `q` into HTML without encoding.
- `POST /chat`: deterministic, deliberately unsafe instruction handling (no external LLM).
- `GET|POST /echo`: benign forwarding/header demonstration.
- `/testbed/requests`: local request counters for proving a blocked request was not received.

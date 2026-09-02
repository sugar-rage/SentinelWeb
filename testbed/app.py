"""INTENTIONALLY VULNERABLE local-only demonstration application.

Never expose this service to a network or deploy it in production.
"""

import json
import os
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("TESTBED_DATABASE_PATH", str(BASE_DIR / "testbed.sqlite3")))

app = FastAPI(
    title="SentinelWeb Intentionally Vulnerable Testbed",
    description="Local educational target only. It deliberately contains SQLi, reflected XSS, and unsafe prompt handling.",
)
app.state.request_counts = {}


def _database() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _database() as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
        connection.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'local-demo-password')")
        connection.execute("INSERT OR IGNORE INTO users VALUES ('alice', 'wonderland')")


_initialize_database()


@app.middleware("http")
async def count_requests(request: Request, call_next):
    path = request.url.path
    app.state.request_counts[path] = app.state.request_counts.get(path, 0) + 1
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "intentionally_vulnerable_testbed", "local_only": True}


@app.get("/testbed/requests")
def request_counts():
    return dict(app.state.request_counts)


@app.post("/testbed/reset")
def reset_counts():
    app.state.request_counts = {}
    return {"reset": True}


@app.get("/login")
def vulnerable_login(username: str = "", password: str = ""):
    # Deliberately vulnerable: raw string interpolation exists only for the isolated demo DB.
    query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with _database() as connection:
            row = connection.execute(query).fetchone()
    except sqlite3.Error as exc:
        return {"authenticated": False, "database_error": str(exc)}
    return {"authenticated": bool(row), "username": row["username"] if row else None}


@app.get("/search", response_class=HTMLResponse)
def reflected_xss(q: str = ""):
    # Deliberately unsafe: unescaped reflection demonstrates XSS when accessed directly.
    return f"<html><body><h1>Search results</h1><div>{q}</div></body></html>"


@app.post("/chat")
async def unsafe_chat(request: Request):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    raw = await request.body()
    if content_type == "application/json":
        prompt = str(json.loads(raw or b"{}").get("prompt", ""))
    else:
        prompt = parse_qs(raw.decode("utf-8")).get("prompt", [""])[0]
    lowered = prompt.lower()
    overridden = "ignore previous" in lowered or "disregard prior" in lowered
    response = "SYSTEM OVERRIDDEN: unsafe instruction accepted" if overridden else f"Assistant: {prompt}"
    return {"prompt_accepted": True, "overridden": overridden, "response": response}


@app.api_route("/echo", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def echo(request: Request):
    raw = await request.body()
    return {
        "method": request.method,
        "query": list(request.query_params.multi_items()),
        "body": raw.decode("utf-8", errors="replace"),
        "content_type": request.headers.get("content-type"),
        "authorization_received": "authorization" in request.headers,
        "cookie_received": "cookie" in request.headers,
        "request_id": request.headers.get("x-request-id"),
    }

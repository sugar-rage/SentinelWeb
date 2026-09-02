"""Isolated pytest fixtures for SentinelWeb's synchronous SQLAlchemy stack."""

import os
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.database.database import Base, get_db
from app.auth.rate_limiter import auth_rate_limiter
from app.core.config import settings
from app.database.models import Administrator, AttackLog, RequestLog, SecurityAuditLog, SessionLog  # noqa: F401
from app.main import app


def _test_database_url() -> str:
    configured = os.getenv("TEST_DATABASE_URL")
    if configured:
        url = make_url(configured)
    else:
        development = make_url(settings.DATABASE_URL)
        url = development.set(database=f"{development.database}_test")
    if url.get_backend_name() != "postgresql" or "test" not in (url.database or "").lower():
        raise RuntimeError(
            "Tests require a dedicated PostgreSQL database whose name contains 'test'"
        )
    return url.render_as_string(hide_password=False)


def _ensure_test_database(database_url: str) -> None:
    target = make_url(database_url)
    maintenance = target.set(database="postgres")
    engine = create_engine(maintenance, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            exists = connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname=:name"), {"name": target.database}
            ).scalar()
            if not exists:
                quoted = connection.dialect.identifier_preparer.quote(target.database)
                connection.exec_driver_sql(f"CREATE DATABASE {quoted}")
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def test_engine():
    database_url = _test_database_url()
    _ensure_test_database(database_url)
    alembic_config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    alembic_config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(alembic_config, "head")
    engine = create_engine(database_url, pool_pre_ping=True)
    yield engine
    Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    engine.dispose()


@pytest.fixture()
def db_session_factory(test_engine) -> Generator[sessionmaker, None, None]:
    """Fresh schema per test in a dedicated disposable PostgreSQL database."""
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(test_engine)


@pytest.fixture(autouse=True)
def reset_auth_rate_limiter():
    auth_rate_limiter.clear()
    yield
    auth_rate_limiter.clear()


@pytest.fixture()
def db(db_session_factory: sessionmaker) -> Generator[Session, None, None]:
    session = db_session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session_factory: sessionmaker) -> Generator[TestClient, None, None]:
    """HTTP client whose route dependencies and request logger use the test DB."""
    def override_get_db() -> Generator[Session, None, None]:
        session = db_session_factory()
        try:
            yield session
        finally:
            session.close()

    original_factory = app.state.session_factory
    app.dependency_overrides[get_db] = override_get_db
    app.state.session_factory = db_session_factory
    test_client = TestClient(app, raise_server_exceptions=False)
    try:
        yield test_client
    finally:
        test_client.close()
        app.dependency_overrides.clear()
        app.state.session_factory = original_factory


def register(client: TestClient, username: str = "user1", email: str = "user1@example.com") -> dict:
    response = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": "UserSecure123!"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def login(client: TestClient, username: str = "user1", password: str = "UserSecure123!") -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def user_token(client: TestClient) -> str:
    register(client)
    return login(client)


@pytest.fixture()
def admin_token(client: TestClient, db_session_factory: sessionmaker) -> str:
    from app.auth.password import hash_password
    from app.database.models.administrator import Administrator

    session = db_session_factory()
    try:
        session.add(
            Administrator(
                username="admin1",
                email="admin1@example.com",
                password_hash=hash_password("AdminSecure123!"),
                role="admin",
            )
        )
        session.commit()
    finally:
        session.close()
    return login(client, username="admin1", password="AdminSecure123!")

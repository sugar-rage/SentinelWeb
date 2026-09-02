"""Phase 2 security schema, compatible with the existing development database.

Revision ID: 20260831_0001
Revises: None
"""

from datetime import datetime, timedelta, timezone
from typing import Sequence, Union
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision: str = "20260831_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}


def _checks(table: str) -> set[str]:
    return {check["name"] for check in sa.inspect(op.get_bind()).get_check_constraints(table)}


def _fks(table: str) -> set[str]:
    return {fk["name"] for fk in sa.inspect(op.get_bind()).get_foreign_keys(table)}


def _add_index(table: str, name: str, columns: list[str], unique: bool = False) -> None:
    if name not in _indexes(table):
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    tables = _table_names()
    if "administrators" not in tables:
        _create_fresh_schema()
        return

    if "role" in _columns("administrators") and "ck_administrators_role" not in _checks("administrators"):
        op.create_check_constraint("ck_administrators_role", "administrators", "role IN ('user', 'admin')")
    _add_index("administrators", "ix_administrators_role", ["role"])

    session_columns = _columns("session_logs")
    for column in (
        sa.Column("session_identifier", sa.String(64), nullable=True),
        sa.Column("token_jti_hash", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    ):
        if column.name not in session_columns:
            op.add_column("session_logs", column)

    bind = op.get_bind()
    now = datetime.now(timezone.utc)
    rows = bind.execute(sa.text("SELECT id, session_start FROM session_logs")).mappings().all()
    for row in rows:
        start = row["session_start"] or now
        if getattr(start, "tzinfo", None) is None:
            start = start.replace(tzinfo=timezone.utc)
        bind.execute(
            sa.text(
                "UPDATE session_logs SET session_identifier=:sid, token_jti_hash=:jti, "
                "expires_at=:expires, last_seen_at=:seen, session_status=COALESCE(session_status, 'expired') WHERE id=:id"
            ),
            {"sid": uuid4().hex, "jti": uuid4().hex + uuid4().hex, "expires": start + timedelta(hours=1), "seen": start, "id": row["id"]},
        )

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE session_logs ALTER COLUMN session_start TYPE TIMESTAMPTZ USING session_start AT TIME ZONE 'UTC'")
        op.execute("ALTER TABLE session_logs ALTER COLUMN session_end TYPE TIMESTAMPTZ USING session_end AT TIME ZONE 'UTC'")
    op.alter_column("session_logs", "session_start", nullable=False)
    op.alter_column("session_logs", "session_status", nullable=False)
    op.alter_column("session_logs", "session_identifier", nullable=False)
    op.alter_column("session_logs", "token_jti_hash", nullable=False)
    op.alter_column("session_logs", "expires_at", nullable=False)
    op.alter_column("session_logs", "last_seen_at", nullable=False)
    if "fk_session_logs_user_id_administrators" not in _fks("session_logs"):
        op.create_foreign_key("fk_session_logs_user_id_administrators", "session_logs", "administrators", ["user_id"], ["id"], ondelete="RESTRICT")
    if "ck_session_logs_status" not in _checks("session_logs"):
        op.create_check_constraint("ck_session_logs_status", "session_logs", "session_status IN ('active', 'logged_out', 'revoked', 'expired')")
    _add_index("session_logs", "ix_session_logs_user_id", ["user_id"])
    _add_index("session_logs", "ix_session_logs_session_identifier", ["session_identifier"], unique=True)
    _add_index("session_logs", "ix_session_logs_token_jti_hash", ["token_jti_hash"], unique=True)
    _add_index("session_logs", "ix_session_logs_session_start", ["session_start"])
    _add_index("session_logs", "ix_session_logs_expires_at", ["expires_at"])
    _add_index("session_logs", "ix_session_logs_session_status", ["session_status"])

    if "correlation_id" not in _columns("request_logs"):
        op.add_column("request_logs", sa.Column("correlation_id", sa.String(36), nullable=True))
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE request_logs ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC'")
    op.execute("UPDATE request_logs SET timestamp = CURRENT_TIMESTAMP WHERE timestamp IS NULL")
    op.alter_column("request_logs", "timestamp", nullable=False)
    request_fks = {fk["name"]: fk for fk in sa.inspect(bind).get_foreign_keys("request_logs")}
    legacy_request_fk = request_fks.get("request_logs_session_id_fkey")
    if legacy_request_fk and legacy_request_fk.get("options", {}).get("ondelete") != "SET NULL":
        op.drop_constraint("request_logs_session_id_fkey", "request_logs", type_="foreignkey")
        op.create_foreign_key(
            "fk_request_logs_session_id_session_logs",
            "request_logs",
            "session_logs",
            ["session_id"],
            ["id"],
            ondelete="SET NULL",
        )
    _add_index("request_logs", "ix_request_logs_correlation_id", ["correlation_id"])
    _add_index("request_logs", "ix_request_logs_session_id", ["session_id"])

    attack_columns = _columns("attack_logs")
    for column in (
        sa.Column("correlation_id", sa.String(36), nullable=True),
        sa.Column("request_id", sa.Integer(), nullable=True),
        sa.Column("session_id", sa.Integer(), nullable=True),
        sa.Column("payload_sha256", sa.String(64), nullable=True),
        sa.Column("payload_truncated", sa.Boolean(), nullable=True),
    ):
        if column.name not in attack_columns:
            op.add_column("attack_logs", column)
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE attack_logs ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC'")
    op.execute("UPDATE attack_logs SET timestamp = CURRENT_TIMESTAMP WHERE timestamp IS NULL")
    op.execute("UPDATE attack_logs SET action = 'allowed' WHERE action IS NULL")
    op.execute("UPDATE attack_logs SET payload_truncated = FALSE WHERE payload_truncated IS NULL")
    op.alter_column("attack_logs", "timestamp", nullable=False)
    op.alter_column("attack_logs", "action", nullable=False)
    op.alter_column("attack_logs", "payload_truncated", nullable=False)
    if "fk_attack_logs_request_id_request_logs" not in _fks("attack_logs"):
        op.create_foreign_key("fk_attack_logs_request_id_request_logs", "attack_logs", "request_logs", ["request_id"], ["id"], ondelete="SET NULL")
    if "fk_attack_logs_session_id_session_logs" not in _fks("attack_logs"):
        op.create_foreign_key("fk_attack_logs_session_id_session_logs", "attack_logs", "session_logs", ["session_id"], ["id"], ondelete="SET NULL")
    if "ck_attack_logs_action" not in _checks("attack_logs"):
        op.create_check_constraint("ck_attack_logs_action", "attack_logs", "action IN ('allowed', 'blocked')")
    if "ck_attack_logs_risk_score" not in _checks("attack_logs"):
        op.create_check_constraint("ck_attack_logs_risk_score", "attack_logs", "risk_score >= 0 AND risk_score <= 100")
    _add_index("attack_logs", "ix_attack_logs_correlation_id", ["correlation_id"])
    _add_index("attack_logs", "ix_attack_logs_request_id", ["request_id"])
    _add_index("attack_logs", "ix_attack_logs_session_id", ["session_id"])
    _add_index("attack_logs", "ix_attack_logs_action", ["action"])

    if "security_audit_logs" not in _table_names():
        _create_audit_table()


def _create_fresh_schema() -> None:
    op.create_table(
        "administrators",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(50), nullable=False, unique=True),
        sa.Column("email", sa.String(100), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.CheckConstraint("role IN ('user', 'admin')", name="ck_administrators_role"),
    )
    op.create_index("ix_administrators_role", "administrators", ["role"])
    op.create_table(
        "session_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("administrators.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("session_identifier", sa.String(64), nullable=False, unique=True),
        sa.Column("token_jti_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.String(255)),
        sa.Column("session_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("session_end", sa.DateTime(timezone=True)),
        sa.Column("session_status", sa.String(20), nullable=False),
        sa.CheckConstraint("session_status IN ('active', 'logged_out', 'revoked', 'expired')", name="ck_session_logs_status"),
    )
    for name, columns, unique in (
        ("ix_session_logs_user_id", ["user_id"], False),
        ("ix_session_logs_session_identifier", ["session_identifier"], True),
        ("ix_session_logs_token_jti_hash", ["token_jti_hash"], True),
        ("ix_session_logs_session_start", ["session_start"], False),
        ("ix_session_logs_expires_at", ["expires_at"], False),
        ("ix_session_logs_session_status", ["session_status"], False),
    ):
        op.create_index(name, "session_logs", columns, unique=unique)
    op.create_table(
        "request_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(36)),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(500), nullable=False),
        sa.Column("status_code", sa.Integer()),
        sa.Column("process_time", sa.Float()),
        sa.Column("session_id", sa.Integer(), sa.ForeignKey("session_logs.id", ondelete="SET NULL")),
    )
    for name, columns, unique in (
        ("ix_request_logs_timestamp", ["timestamp"], False),
        ("ix_request_logs_correlation_id", ["correlation_id"], False),
        ("ix_request_logs_session_id", ["session_id"], False),
    ):
        op.create_index(name, "request_logs", columns, unique=unique)
    op.create_table(
        "attack_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(36)),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("request_logs.id", ondelete="SET NULL")),
        sa.Column("session_id", sa.Integer(), sa.ForeignKey("session_logs.id", ondelete="SET NULL")),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("raw_payload", sa.Text(), nullable=False),
        sa.Column("payload_sha256", sa.String(64)),
        sa.Column("payload_truncated", sa.Boolean(), nullable=False),
        sa.Column("attack_detected", sa.Boolean(), nullable=False),
        sa.Column("attack_type", sa.String(50)),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(20)),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("explanation", sa.Text()),
        sa.Column("mitigation", sa.Text()),
        sa.Column("detection_method", sa.String(50)),
        sa.Column("action", sa.String(20), nullable=False),
        sa.CheckConstraint("action IN ('allowed', 'blocked')", name="ck_attack_logs_action"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_attack_logs_risk_score"),
    )
    for name, columns in (
        ("ix_attack_logs_timestamp", ["timestamp"]), ("ix_attack_logs_attack_detected", ["attack_detected"]),
        ("ix_attack_logs_attack_type", ["attack_type"]), ("ix_attack_logs_correlation_id", ["correlation_id"]),
        ("ix_attack_logs_request_id", ["request_id"]), ("ix_attack_logs_session_id", ["session_id"]),
        ("ix_attack_logs_action", ["action"]),
    ):
        op.create_index(name, "attack_logs", columns)
    _create_audit_table()


def _create_audit_table() -> None:
    op.create_table(
        "security_audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("administrators.id", ondelete="SET NULL")),
        sa.Column("session_id", sa.Integer(), sa.ForeignKey("session_logs.id", ondelete="SET NULL")),
        sa.Column("correlation_id", sa.String(36)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("details", sa.Text()),
        sa.CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="ck_security_audit_outcome"),
    )
    for name, columns in (
        ("ix_security_audit_logs_timestamp", ["timestamp"]), ("ix_security_audit_logs_event_type", ["event_type"]),
        ("ix_security_audit_logs_outcome", ["outcome"]), ("ix_security_audit_logs_user_id", ["user_id"]),
        ("ix_security_audit_logs_session_id", ["session_id"]), ("ix_security_audit_logs_correlation_id", ["correlation_id"]),
    ):
        op.create_index(name, "security_audit_logs", columns)


def downgrade() -> None:
    raise RuntimeError("Phase 2 migration is intentionally non-destructive; restore from backup to downgrade")

"""Phase 3 WAF event correlation and component-level findings.

Revision ID: 20260831_0002
Revises: 20260831_0001
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260831_0002"
down_revision: Union[str, None] = "20260831_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "waf_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(36), nullable=False),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("request_logs.id", ondelete="SET NULL")),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(500), nullable=False),
        sa.Column("attack_types", sa.Text()),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("upstream_status", sa.Integer()),
        sa.Column("error_code", sa.String(64)),
        sa.CheckConstraint("action IN ('allowed', 'blocked', 'rejected', 'error')", name="ck_waf_events_action"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_waf_events_risk_score"),
    )
    for name, columns in (
        ("ix_waf_events_timestamp", ["timestamp"]),
        ("ix_waf_events_correlation_id", ["correlation_id"]),
        ("ix_waf_events_request_id", ["request_id"]),
        ("ix_waf_events_action", ["action"]),
    ):
        op.create_index(name, "waf_events", columns)

    op.add_column("attack_logs", sa.Column("waf_event_id", sa.Integer(), nullable=True))
    op.add_column("attack_logs", sa.Column("request_component", sa.String(255), nullable=True))
    op.create_foreign_key(
        "fk_attack_logs_waf_event_id_waf_events",
        "attack_logs",
        "waf_events",
        ["waf_event_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_attack_logs_waf_event_id", "attack_logs", ["waf_event_id"])


def downgrade() -> None:
    op.drop_index("ix_attack_logs_waf_event_id", table_name="attack_logs")
    op.drop_constraint("fk_attack_logs_waf_event_id_waf_events", "attack_logs", type_="foreignkey")
    op.drop_column("attack_logs", "request_component")
    op.drop_column("attack_logs", "waf_event_id")
    op.drop_table("waf_events")

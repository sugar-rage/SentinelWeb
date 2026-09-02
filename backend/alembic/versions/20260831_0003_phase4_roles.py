"""Phase 4 role permission expansion.

Revision ID: 20260831_0003
Revises: 20260831_0002
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260831_0003"
down_revision: Union[str, None] = "20260831_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_administrators_role", "administrators", type_="check")
    op.create_check_constraint(
        "ck_administrators_role",
        "administrators",
        "role IN ('user', 'admin', 'security_analyst', 'developer')",
    )
    op.add_column("waf_events", sa.Column("base_risk_score", sa.Integer(), nullable=True))
    op.add_column("waf_events", sa.Column("adaptive_factors", sa.Text(), nullable=True))
    op.execute("UPDATE waf_events SET base_risk_score = risk_score WHERE base_risk_score IS NULL")
    op.alter_column("waf_events", "base_risk_score", nullable=False)


def downgrade() -> None:
    op.drop_column("waf_events", "adaptive_factors")
    op.drop_column("waf_events", "base_risk_score")
    op.execute("UPDATE administrators SET role = 'user' WHERE role IN ('security_analyst', 'developer')")
    op.drop_constraint("ck_administrators_role", "administrators", type_="check")
    op.create_check_constraint(
        "ck_administrators_role",
        "administrators",
        "role IN ('user', 'admin')",
    )

"""Add Phase 8 adaptive security decision metadata.

Revision ID: 0007_adaptive_policy
Revises: 0006_multi_mlkem
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0007_adaptive_policy"
down_revision: str | Sequence[str] | None = "0006_multi_mlkem"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "files", sa.Column("security_selection_mode", sa.String(length=16), nullable=True)
    )
    op.add_column("files", sa.Column("sensitivity", sa.String(length=32), nullable=True))
    op.add_column(
        "files", sa.Column("document_category", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "files",
        sa.Column("recommended_security_level", sa.String(length=16), nullable=True),
    )
    op.add_column("files", sa.Column("policy_version", sa.String(length=32), nullable=True))
    op.add_column("files", sa.Column("decision_reasons", sa.JSON(), nullable=True))
    op.add_column("files", sa.Column("policy_rules", sa.JSON(), nullable=True))
    op.add_column("files", sa.Column("user_override", sa.Boolean(), nullable=True))

    op.create_check_constraint(
        "ck_files_security_selection_mode",
        "files",
        "security_selection_mode IS NULL OR security_selection_mode IN "
        "('MANUAL', 'RECOMMEND', 'AUTO')",
    )
    op.create_check_constraint(
        "ck_files_sensitivity",
        "files",
        "sensitivity IS NULL OR sensitivity IN "
        "('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY_CONFIDENTIAL')",
    )
    op.create_check_constraint(
        "ck_files_document_category",
        "files",
        "document_category IS NULL OR document_category IN "
        "('GENERAL', 'ACADEMIC', 'PERSONAL', 'FINANCIAL', 'LEGAL', 'MEDICAL', "
        "'SOURCE_CODE', 'IDENTITY', 'CREDENTIALS', 'ARCHIVE', 'OTHER')",
    )
    op.create_check_constraint(
        "ck_files_recommended_security_level",
        "files",
        "recommended_security_level IS NULL OR recommended_security_level IN "
        "('LOW', 'STANDARD', 'HIGH')",
    )
    op.create_check_constraint(
        "ck_files_policy_decision_complete",
        "files",
        "security_selection_mode IS NULL OR "
        "(recommended_security_level IS NOT NULL AND policy_version IS NOT NULL "
        "AND decision_reasons IS NOT NULL AND policy_rules IS NOT NULL "
        "AND user_override IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_files_policy_decision_complete", "files", type_="check")
    op.drop_constraint("ck_files_recommended_security_level", "files", type_="check")
    op.drop_constraint("ck_files_document_category", "files", type_="check")
    op.drop_constraint("ck_files_sensitivity", "files", type_="check")
    op.drop_constraint("ck_files_security_selection_mode", "files", type_="check")

    op.drop_column("files", "user_override")
    op.drop_column("files", "policy_rules")
    op.drop_column("files", "decision_reasons")
    op.drop_column("files", "policy_version")
    op.drop_column("files", "recommended_security_level")
    op.drop_column("files", "document_category")
    op.drop_column("files", "sensitivity")
    op.drop_column("files", "security_selection_mode")

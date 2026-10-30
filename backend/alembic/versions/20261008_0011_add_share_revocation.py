"""Add share lifecycle, recipient-envelope disablement, and audit events.

Revision ID: 0011_share_revocation
Revises: 0010_digital_signatures
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0011_share_revocation"
down_revision: str | Sequence[str] | None = "0010_digital_signatures"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("file_shares", sa.Column("revoked_at", sa.DateTime(timezone=True)))
    op.add_column("file_shares", sa.Column("revoked_by_user_id", sa.Uuid(as_uuid=True)))
    op.add_column("file_shares", sa.Column("revoke_reason", sa.String(255)))
    op.create_foreign_key("fk_file_shares_revoked_by", "file_shares", "users",
                          ["revoked_by_user_id"], ["id"], ondelete="RESTRICT")
    op.drop_constraint("ck_file_shares_active_only", "file_shares", type_="check")
    op.create_check_constraint("ck_file_shares_status", "file_shares",
                               "status IN ('ACTIVE', 'REVOKED')")
    op.create_check_constraint("ck_file_shares_revocation_state", "file_shares",
        "(status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by_user_id IS NULL) OR "
        "(status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL)")
    op.create_check_constraint("ck_file_shares_revoke_reason_length", "file_shares",
                               "revoke_reason IS NULL OR length(revoke_reason) <= 255")
    op.drop_constraint("uq_file_shares_file_recipient", "file_shares", type_="unique")
    op.create_index("uq_file_shares_file_recipient_active", "file_shares",
                    ["file_id", "recipient_id"], unique=True,
                    postgresql_where=sa.text("status = 'ACTIVE'"))
    op.add_column("share_crypto_metadata", sa.Column("is_active", sa.Boolean(),
                                                       nullable=False, server_default=sa.true()))

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("file_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("share_id", sa.Uuid(as_uuid=True)),
        sa.Column("recipient_id", sa.Uuid(as_uuid=True)),
        sa.Column("previous_status", sa.String(16)),
        sa.Column("new_status", sa.String(16)),
        sa.Column("reason", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint("event_type IN ('SHARE_CREATED','SHARE_REVOKED',"
                           "'SHARE_DOWNLOAD_DENIED_REVOKED','FILE_DELETED')",
                           name="ck_audit_logs_event_type"),
        sa.CheckConstraint("previous_status IS NULL OR previous_status IN ('ACTIVE','REVOKED')",
                           name="ck_audit_logs_previous_status"),
        sa.CheckConstraint("new_status IS NULL OR new_status IN ('ACTIVE','REVOKED')",
                           name="ck_audit_logs_new_status"),
    )
    op.create_index("ix_audit_logs_share_created", "audit_logs", ["share_id", "created_at"])
    op.create_index("ix_audit_logs_file_created", "audit_logs", ["file_id", "created_at"])
    op.create_index("uq_audit_logs_share_revoked", "audit_logs", ["share_id"],
                    unique=True, postgresql_where=sa.text("event_type = 'SHARE_REVOKED'"))


def downgrade() -> None:
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM audit_logs) "
               "OR EXISTS (SELECT 1 FROM file_shares WHERE status='REVOKED') "
               "OR EXISTS (SELECT 1 FROM share_crypto_metadata WHERE NOT is_active) "
               "THEN RAISE EXCEPTION 'Revocation history must be preserved before downgrade'; END IF; END $$")
    op.drop_index("uq_audit_logs_share_revoked", table_name="audit_logs")
    op.drop_index("ix_audit_logs_file_created", table_name="audit_logs")
    op.drop_index("ix_audit_logs_share_created", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_column("share_crypto_metadata", "is_active")
    op.drop_index("uq_file_shares_file_recipient_active", table_name="file_shares")
    op.create_unique_constraint("uq_file_shares_file_recipient", "file_shares",
                                ["file_id", "recipient_id"])
    op.drop_constraint("ck_file_shares_revoke_reason_length", "file_shares", type_="check")
    op.drop_constraint("ck_file_shares_revocation_state", "file_shares", type_="check")
    op.drop_constraint("ck_file_shares_status", "file_shares", type_="check")
    op.create_check_constraint("ck_file_shares_active_only", "file_shares", "status = 'ACTIVE'")
    op.drop_constraint("fk_file_shares_revoked_by", "file_shares", type_="foreignkey")
    op.drop_column("file_shares", "revoke_reason")
    op.drop_column("file_shares", "revoked_by_user_id")
    op.drop_column("file_shares", "revoked_at")

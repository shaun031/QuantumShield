"""Small, owner-scoped dashboard aggregates; never serialize key material."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from uuid import UUID
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentActiveUser
from app.core.config import settings
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.crypto_metadata import CryptoMetadata
from app.models.file import File
from app.models.file_share import FileShare
from app.models.user_crypto_key import UserCryptoKey


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/file-share-counts")
def file_share_counts(
    current_user: CurrentActiveUser,
    database: Annotated[Session, Depends(get_db)],
    file_ids: Annotated[list[UUID], Query(max_length=20)],
) -> dict[str, int]:
    if not file_ids:
        return {}
    counts = database.execute(
        select(FileShare.file_id, func.count(FileShare.id))
        .join(File, File.id == FileShare.file_id)
        .where(File.owner_id == current_user.id, FileShare.status == "ACTIVE",
               FileShare.file_id.in_(file_ids))
        .group_by(FileShare.file_id)
    )
    return {str(file_id): total for file_id, total in counts}


@router.get("/summary")
def dashboard_summary(
    current_user: CurrentActiveUser,
    database: Annotated[Session, Depends(get_db)],
) -> dict:
    user_id = current_user.id

    def count(statement) -> int:
        return int(database.scalar(statement) or 0)

    my_files = count(select(func.count(File.id)).where(File.owner_id == user_id))
    received = count(select(func.count(FileShare.id)).where(FileShare.recipient_id == user_id))
    sent = count(select(func.count(FileShare.id)).where(FileShare.sender_id == user_id))
    share_status = {"ACTIVE": 0, "REVOKED": 0}
    for status, total in database.execute(
        select(FileShare.status, func.count(FileShare.id))
        .where(FileShare.sender_id == user_id)
        .group_by(FileShare.status)
    ):
        share_status[status] = total

    def distribution(column, statement, names):
        result = {name: 0 for name in names}
        for name, total in database.execute(statement.group_by(column)):
            result[name or "LEGACY"] = total
        return result

    own_crypto = File.owner_id == user_id
    levels = distribution(
        CryptoMetadata.security_level,
        select(CryptoMetadata.security_level, func.count(File.id))
        .select_from(File).outerjoin(CryptoMetadata, CryptoMetadata.file_id == File.id)
        .where(own_crypto),
        ("LOW", "STANDARD", "HIGH"),
    )
    architectures = distribution(
        CryptoMetadata.security_architecture,
        select(CryptoMetadata.security_architecture, func.count(File.id))
        .select_from(File).outerjoin(CryptoMetadata, CryptoMetadata.file_id == File.id)
        .where(own_crypto),
        ("PQ_ONLY", "HYBRID"),
    )
    modes = distribution(
        File.selection_mode,
        select(File.selection_mode, func.count(File.id))
        .where(own_crypto),
        ("MANUAL", "RECOMMEND", "AUTO"),
    )
    keys = set(database.scalars(
        select(UserCryptoKey.algorithm).where(
            UserCryptoKey.user_id == user_id, UserCryptoKey.is_active.is_(True)
        )
    ))
    recent_files = database.execute(
        select(File.original_filename, File.selection_mode, File.sensitivity,
               CryptoMetadata.security_level, CryptoMetadata.crypto_suite_id,
               File.decision_reasons, File.created_at)
        .outerjoin(CryptoMetadata, CryptoMetadata.file_id == File.id)
        .where(File.owner_id == user_id)
        .order_by(File.created_at.desc(), File.id.desc()).limit(5)
    ).all()
    recent_events = database.scalars(
        select(AuditLog)
        .where(or_(AuditLog.actor_user_id == user_id, AuditLog.recipient_id == user_id))
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(10)
    ).all()
    return {
        "my_files": my_files,
        "shared_with_me": received,
        "shared_by_me": sent,
        "active_shares": share_status["ACTIVE"],
        "revoked_shares": share_status["REVOKED"],
        "key_readiness": {algorithm: algorithm in keys for algorithm in
                          ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", settings.default_signature_algorithm)},
        "security_levels": levels,
        "architectures": architectures,
        "selection_modes": modes,
        "recent_decisions": [
            {"filename": name, "mode": mode, "sensitivity": sensitivity,
             "level": level, "suite": suite, "reasons": reasons or [], "created_at": created_at}
            for name, mode, sensitivity, level, suite, reasons, created_at in recent_files
        ],
        "recent_activity": [
            {"event_type": event.event_type, "created_at": event.created_at,
             "role": "actor" if event.actor_user_id == user_id else "recipient"}
            for event in recent_events
        ],
    }

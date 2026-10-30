"""Non-destructive database connectivity helpers."""

import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


def is_database_available(session: Session) -> bool:
    """Run a side-effect-free connectivity query.

    Only the exception type is logged so connection credentials and driver
    details cannot be reflected to logs or API clients.
    """

    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        logger.warning(
            "Database connectivity check failed (%s).",
            type(exc).__name__,
        )
        return False
    return True


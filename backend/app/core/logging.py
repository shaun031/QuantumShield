"""Small, secret-conscious logging configuration."""

import logging

from app.core.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure application logs without serializing the settings object."""

    level_name = (
        "DEBUG" if settings.debug and settings.log_level == "INFO" else settings.log_level
    )
    logging.basicConfig(
        level=getattr(logging, level_name),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


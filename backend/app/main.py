"""FastAPI application factory and process lifecycle."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging


configure_logging(settings)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings.storage_directory.mkdir(parents=True, exist_ok=True)
    logger.info(
        "%s %s starting in %s mode.",
        settings.app_name,
        __version__,
        settings.app_env,
    )
    yield
    logger.info("%s stopped.", settings.app_name)


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Crypto-agile file encryption, revocable sharing, read-only dashboard summaries, and offline paired adaptive evaluation with optional "
            "X25519 + ML-KEM hybrid key establishment, AES-256-GCM content protection, "
            "and ML-DSA sender authenticity."
        ),
        # Keep framework traceback responses disabled even in local development.
        # DEBUG controls application log verbosity, never client error detail.
        debug=False,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Authorization", "Content-Type"],
        expose_headers=["Content-Disposition"],
    )

    application.include_router(api_router, prefix=settings.api_prefix)

    @application.exception_handler(Exception)
    async def handle_unexpected_error(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.error(
            "Unhandled error while processing %s %s (%s).",
            request.method,
            request.url.path,
            type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected server error occurred."},
        )

    return application


app = create_app()


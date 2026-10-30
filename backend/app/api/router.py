"""Central API router composed from feature routers."""

from fastapi import APIRouter

from app.api.routes import auth, crypto_keys, crypto_suites, dashboard, files, research, security, shares, system, users


api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(crypto_keys.router)
api_router.include_router(crypto_suites.router)
api_router.include_router(security.router)
api_router.include_router(files.router)
api_router.include_router(shares.router)
api_router.include_router(dashboard.router)
api_router.include_router(research.router)


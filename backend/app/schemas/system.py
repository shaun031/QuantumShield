"""Schemas for liveness and dependency status endpoints."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: Literal["ok"]


class SystemStatusResponse(BaseModel):
    backend: Literal["ok"]
    database: Literal["ok", "unavailable"]
    supported_kems: list[str]
    supported_suites: list[str]
    provider_availability: dict[str, list[str]]
    active_suite_count: int


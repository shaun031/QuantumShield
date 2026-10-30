"""Read-only access to complete, local synthetic research exports."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.api.dependencies import CurrentActiveUser
from app.core.config import BACKEND_DIR


router = APIRouter(prefix="/research", tags=["research"])
RESULTS = BACKEND_DIR / "benchmark_results"


def latest_export(folder: Path, filename: str, version_field: str) -> dict:
    # Only server-owned UUID run directories and fixed filenames are read.
    import uuid

    if not folder.is_dir():
        raise HTTPException(status_code=404, detail="No completed results available")
    candidates = []
    for path in folder.iterdir():
        try:
            uuid.UUID(path.name)
        except ValueError:
            continue
        target = path / filename
        if (path.is_dir() and path.resolve().parent == folder.resolve() and
                target.is_file() and target.stat().st_size <= 20 * 1024 * 1024):
            candidates.append(target)
    for target in sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if data.get(version_field) == 1 and (
            (version_field == "benchmark_schema_version" and isinstance(data.get("results"), list)) or
            (version_field == "experiment_schema_version" and data.get("status") == "COMPLETED"
             and isinstance(data.get("comparisons"), list))
        ):
            return data
    raise HTTPException(status_code=404, detail="No completed results available")


@router.get("/benchmarks/latest")
def latest_benchmark(current_user: CurrentActiveUser) -> dict:
    del current_user
    data = latest_export(RESULTS, "results.json", "benchmark_schema_version")
    # CLI notes are user-entered, not measurements, and may not be safe to publish
    # to every authenticated viewer.
    data.pop("note", None)
    return data


@router.get("/adaptive/latest")
def latest_adaptive(current_user: CurrentActiveUser) -> dict:
    del current_user
    return latest_export(RESULTS / "adaptive", "adaptive_vs_fixed.json", "experiment_schema_version")

"""Run paired rule-based Adaptive versus Fixed-HIGH synthetic experiments."""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.experiments.adaptive import AdaptiveExperimentService, PROFILES  # noqa: E402
from app.experiments.export import export_experiment  # noqa: E402


def _load_reference(path: Path | None) -> tuple[Path, dict]:
    if path is not None:
        candidates = (path,)
    else:
        candidates = tuple(sorted(Path("benchmark_results").glob("*/results.json"),
                                  key=lambda item: item.stat().st_mtime, reverse=True))
    for candidate in candidates:
        try:
            document = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            if path is not None:
                raise ValueError("Phase 13 reference is unreadable") from None
            continue
        if document.get("benchmark_schema_version") == 1 and document.get("profile") == "standard":
            return candidate, document
        if path is not None:
            raise ValueError("Phase 13 reference must be a standard schema-v1 export")
    raise ValueError("No Phase 13 standard export found; run scripts/run_benchmarks.py --profile standard first")


def _write_status(directory: Path, run_id: str, status: str,
                  error_type: str | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {"experiment_run_id": run_id, "status": status,
               "updated_at": datetime.now(UTC).isoformat()}
    if error_type is not None:
        payload["error_type"] = error_type
    (directory / "status.json").write_text(json.dumps(payload, indent=2) + "\n",
                                           encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="quick")
    parser.add_argument("--iterations", type=int, help="override measured iterations (1-100)")
    parser.add_argument("--warmups", type=int, help="override excluded warmups (0-20)")
    parser.add_argument("--phase13-reference", type=Path,
                        help="Phase 13 standard results.json; latest standard export is used if omitted")
    parser.add_argument("--output", type=Path, default=Path("benchmark_results/adaptive"),
                        help="parent output directory")
    args = parser.parse_args(argv)
    try:
        reference_path, reference = _load_reference(args.phase13_reference)
        service = AdaptiveExperimentService(args.profile, iterations=args.iterations,
                                            warmups=args.warmups)
    except ValueError as exc:
        parser.error(str(exc))
    run_id = str(uuid4())
    directory = args.output / run_id
    _write_status(directory, run_id, "STARTED")
    try:
        run = service.run(reference, run_id=run_id)
        paths = export_experiment(run, directory)
    except Exception as exc:
        _write_status(directory, run_id, "FAILED", type(exc).__name__)
        raise
    _write_status(directory, run_id, "COMPLETED")
    print(f"Validated {len(run['comparisons'])} scenarios and {len(run['raw_pairs'])} paired measurements.")
    print(f"Phase 13 reference: {reference_path.resolve()}")
    for kind, path in paths.items():
        print(f"{kind.upper()}: {path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Run bounded synthetic benchmarks without a database or web server."""

import argparse
import sys
from pathlib import Path

# Permit the documented direct script command from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.benchmarks.config import PROFILES, parse_size, validate_config  # noqa: E402
from app.benchmarks.export import export_run  # noqa: E402
from app.benchmarks.service import BenchmarkService  # noqa: E402
from app.crypto.suite_specs import APPROVED_SUITE_SPECS  # noqa: E402
from app.benchmarks.config import BASELINE_ID  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="quick")
    parser.add_argument("--suite", default="all", help="all or one approved suite ID")
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--file-sizes", help="comma-separated sizes, e.g. 1KB,1MB,10MB")
    parser.add_argument("--output", type=Path, default=Path("benchmark_results"),
                        help="parent output directory; a per-run subdirectory is created")
    parser.add_argument("--note", default="", help="short optional non-sensitive run note")
    arguments = parser.parse_args(argv)
    profile = PROFILES[arguments.profile]
    try:
        sizes = tuple(parse_size(item) for item in arguments.file_sizes.split(",")) \
            if arguments.file_sizes else profile.file_sizes
        iterations = arguments.iterations if arguments.iterations is not None else profile.iterations
        warmups = arguments.warmups if arguments.warmups is not None else profile.warmups
        validate_config(iterations, warmups, sizes, profile.recipient_counts)
        allowed = (BASELINE_ID,) + tuple(spec.suite_id for spec in APPROVED_SUITE_SPECS)
        if arguments.suite not in ("all", *allowed):
            raise ValueError("Unknown benchmark suite")
        suite_ids = allowed if arguments.suite == "all" else (arguments.suite,)
        service = BenchmarkService(iterations=iterations, warmups=warmups,
                                   file_sizes=sizes, recipient_counts=profile.recipient_counts,
                                   suite_ids=suite_ids)
        run = service.run(profile=arguments.profile, note=arguments.note)
        paths = export_run(run, arguments.output / run["run_id"])
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    print(f"Validated {len(run['results'])} benchmark rows for run {run['run_id']}.")
    for kind, path in paths.items():
        print(f"{kind.upper()}: {path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""One-command Stage 1 data pipeline: download, clean, and load BigQuery."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from config import Settings
from data.clean import CleanResult, clean_all, write_ndjson
from data.fetch import download_raw
from data.load_bq import load_indicators, resolve_project


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(path)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def run(args: argparse.Namespace) -> dict:
    settings = Settings()
    max_malicious = (
        args.max_malicious if args.max_malicious is not None else settings.max_malicious_rows
    )
    max_benign = args.max_benign if args.max_benign is not None else settings.max_benign_rows

    openphish_path = settings.data_dir / "openphish.txt"
    tranco_path = settings.data_dir / "tranco.csv"
    if args.refresh or not (openphish_path.exists() and tranco_path.exists()):
        openphish_path, tranco_path = download_raw(settings.data_dir)

    result: CleanResult = clean_all(
        _read(openphish_path),
        _read(tranco_path),
        max_malicious=max_malicious,
        max_benign=max_benign,
    )

    clean_path = settings.clean_dir / "indicators.jsonl"
    stats_path = settings.clean_dir / "stats.json"
    row_count = write_ndjson(result.indicators, clean_path)

    summary: dict = {
        "generated_at": datetime.now(UTC).isoformat(),
        "sources": {
            "openphish": str(openphish_path),
            "tranco": str(tranco_path),
        },
        "stats": result.stats.model_dump(),
        "clean_file": str(clean_path),
        "clean_rows": row_count,
        "bigquery": None,
    }

    if not args.local:
        project = resolve_project(args.project or settings.google_cloud_project or None)
        loaded = load_indicators(
            result.indicators,
            project=project,
            dataset_id=settings.bq_dataset,
            table_id=settings.bq_table,
            location=settings.bq_location,
        )
        summary["bigquery"] = asdict(loaded)

    _write_json(stats_path, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--local",
        action="store_true",
        help="Download and clean only; do not write to BigQuery.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Re-download raw feeds instead of using cached files.",
    )
    parser.add_argument("--max-malicious", type=_positive_int, default=None)
    parser.add_argument("--max-benign", type=_positive_int, default=None)
    parser.add_argument("--project", default=None, help="Google Cloud project ID override.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

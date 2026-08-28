"""Build and load URL features for BigQuery ML."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from google.cloud import bigquery

from config import Settings
from data.load_bq import resolve_project
from tools.bq import get_client, qualified_name
from tools.feature_schema import feature_values
from tools.url_features import extract_url_features
from tools.validation import parse_indicator

ROOT = Path(__file__).resolve().parents[1]
FEATURE_SCHEMA_PATH = ROOT / "infra" / "bigquery" / "schema_url_features.json"
CASES_PATH = ROOT / "evals" / "cases.json"


def load_feature_schema() -> list[bigquery.SchemaField]:
    raw = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    return [
        bigquery.SchemaField(
            field["name"],
            field["type"],
            mode=field.get("mode", "NULLABLE"),
        )
        for field in raw
    ]


def holdout_domains(path: Path = CASES_PATH) -> set[str]:
    """Domains in the agent eval set, excluded from model training."""
    if not path.exists():
        return set()
    domains: set[str] = set()
    for case in json.loads(path.read_text(encoding="utf-8")):
        parsed = parse_indicator(case["input"])
        if parsed is not None:
            domains.add(parsed.host)
    return domains


def feature_row(
    url: str,
    domain: str,
    label: str,
    source: str,
) -> dict[str, Any] | None:
    """Convert one indicator URL into a flat BQML feature row."""
    result = extract_url_features(url)
    if result["status"] != "ok" or result["features"] is None:
        return None
    values = feature_values(result["features"])
    return {
        "url": url,
        "domain": domain,
        "label": label,
        "source": source,
        **values,
    }


def build_and_load() -> dict[str, Any]:
    settings = Settings()
    project = resolve_project(settings.google_cloud_project or None)
    client = get_client()
    try:
        indicators_table = qualified_name(settings, project, settings.bq_table)
        features_table_id = f"{project}.{settings.bq_dataset}.{settings.bq_features_table}"
        rows = client.query(f"SELECT url, domain, label, source FROM {indicators_table}").result()

        holdout = holdout_domains()
        feature_rows: list[dict[str, Any]] = []
        skipped_holdout = 0
        feature_errors = 0
        for row in rows:
            if row["domain"] in holdout:
                skipped_holdout += 1
                continue
            url = row["url"] or f"https://{row['domain']}/"
            feature = feature_row(url, row["domain"], row["label"], row["source"])
            if feature is None:
                feature_errors += 1
                continue
            feature_rows.append(feature)

        if not feature_rows:
            raise RuntimeError("no feature rows were built")

        job_config = bigquery.LoadJobConfig(
            schema=load_feature_schema(),
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
        )
        job = client.load_table_from_json(feature_rows, features_table_id, job_config=job_config)
        job.result()
        if job.errors:
            raise RuntimeError(f"BigQuery feature load failed: {job.errors}")

        labels = Counter(row["label"] for row in feature_rows)
        sources = Counter(row["source"] for row in feature_rows)
        return {
            "project": project,
            "dataset": settings.bq_dataset,
            "table": settings.bq_features_table,
            "rows": len(feature_rows),
            "holdout_skipped": skipped_holdout,
            "feature_errors": feature_errors,
            "holdout_domains": sorted(holdout),
            "labels": dict(labels),
            "sources": dict(sources),
        }
    finally:
        client.close()


def main() -> int:
    print(json.dumps(build_and_load(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

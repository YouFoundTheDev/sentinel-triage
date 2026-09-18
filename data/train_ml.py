"""Train and evaluate the BigQuery ML URL classifier."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import Settings
from data.load_bq import resolve_project
from tools.bq import get_client, qualified_model, qualified_name

ROOT = Path(__file__).resolve().parents[1]
TRAIN_SQL_PATH = ROOT / "infra" / "bigquery" / "train_ml.sql"


def train_and_evaluate() -> dict[str, Any]:
    settings = Settings()
    project = resolve_project(settings.google_cloud_project or None)
    model = qualified_model(settings, project)
    features_table = qualified_name(settings, project, settings.bq_features_table)
    client = get_client()
    try:
        template = TRAIN_SQL_PATH.read_text(encoding="utf-8")
        train_sql = template.format(model=model, features_table=features_table)
        client.query(train_sql).result()

        evaluate_sql = f"SELECT * FROM ML.EVALUATE(MODEL {model})"
        metrics = [dict(row) for row in client.query(evaluate_sql).result()]

        table = client.get_table(f"{project}.{settings.bq_dataset}.{settings.bq_features_table}")
        payload = {
            "model": model,
            "features_table": features_table,
            "training_table_rows": table.num_rows,
            "evaluate": metrics,
        }
        settings.clean_dir.mkdir(parents=True, exist_ok=True)
        metrics_path = settings.clean_dir / "ml_metrics.json"
        metrics_path.write_text(
            json.dumps(payload, indent=2, default=float) + "\n",
            encoding="utf-8",
        )
        payload["metrics_path"] = str(metrics_path)
        return payload
    finally:
        client.close()


def main() -> int:
    print(json.dumps(train_and_evaluate(), indent=2, default=float))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

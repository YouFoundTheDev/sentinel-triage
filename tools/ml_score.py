"""BigQuery ML URL scoring tool."""

from __future__ import annotations

from typing import Literal

from google.cloud import bigquery

from config import Settings
from tools.bq import get_client, qualified_model
from tools.feature_schema import FEATURE_COLUMNS, bq_type, feature_values
from tools.schemas import ToolResult
from tools.url_features import extract_url_features


class MlScoreResult(ToolResult):
    tool: Literal["ml_score"] = "ml_score"
    model: str | None = None
    predicted_label: str | None = None
    malicious_probability: float | None = None
    benign_probability: float | None = None


def ml_score(url: str) -> dict:
    """Score a URL or domain with the BigQuery ML URL classifier.

    This invokes ML.PREDICT with parameterized feature values. It never fetches
    or connects to the submitted URL. The result status is "ok", "invalid", or
    "unavailable"; BigQuery failures are returned, never raised.
    """
    extracted = extract_url_features(url)
    if extracted["status"] != "ok" or extracted["features"] is None:
        return MlScoreResult(
            status="invalid",
            summary="Invalid input for ML scoring.",
            error="input failed URL validation",
        ).model_dump(mode="json")

    values = feature_values(extracted["features"])

    try:
        settings = Settings()
        client = get_client()
        project = settings.google_cloud_project or client.project
        model = qualified_model(settings, project)
        feature_select = ",\n  ".join(f"@{column} AS {column}" for column in FEATURE_COLUMNS)
        sql = f"""
SELECT
  predicted_label,
  (SELECT prob FROM UNNEST(predicted_label_probs) AS p
   WHERE p.label = 'malicious') AS malicious_probability,
  (SELECT prob FROM UNNEST(predicted_label_probs) AS p
   WHERE p.label = 'benign') AS benign_probability
FROM ML.PREDICT(
  MODEL {model},
  (SELECT {feature_select})
)
""".strip()
        parameters = [
            bigquery.ScalarQueryParameter(column, bq_type(column), values[column])
            for column in FEATURE_COLUMNS
        ]
        job_config = bigquery.QueryJobConfig(query_parameters=parameters)
        row = next(iter(client.query(sql, job_config=job_config).result()), None)
        if row is None:
            raise RuntimeError("ML.PREDICT returned no rows")

        malicious_probability = (
            float(row["malicious_probability"])
            if row["malicious_probability"] is not None
            else None
        )
        benign_probability = (
            float(row["benign_probability"]) if row["benign_probability"] is not None else None
        )
        predicted_label = str(row["predicted_label"])
    except Exception as exc:
        return MlScoreResult(
            status="unavailable",
            summary="ML scoring is unavailable.",
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
        ).model_dump(mode="json")

    summary = f"ML model predicts {predicted_label}"
    if malicious_probability is not None:
        summary += f" (malicious probability {malicious_probability:.3f})"
    return MlScoreResult(
        status="ok",
        model=model,
        predicted_label=predicted_label,
        malicious_probability=malicious_probability,
        benign_probability=benign_probability,
        summary=summary + ".",
    ).model_dump(mode="json")

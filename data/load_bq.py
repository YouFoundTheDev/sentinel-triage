"""Load cleaned indicators into BigQuery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import google.auth
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import bigquery
from google.cloud.exceptions import NotFound

from data.clean import Indicator

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "infra" / "bigquery" / "schema_indicators.json"


@dataclass(frozen=True)
class LoadResult:
    project: str
    dataset: str
    table: str
    location: str
    rows: int


def load_schema() -> list[bigquery.SchemaField]:
    """Read the table schema from the shared JSON definition."""
    raw = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return [
        bigquery.SchemaField(
            field["name"],
            field["type"],
            mode=field.get("mode", "NULLABLE"),
        )
        for field in raw
    ]


def resolve_project(explicit: str | None) -> str:
    """Resolve the project from an argument/env value or Application Default Credentials."""
    if explicit == "your-project-id":
        raise RuntimeError(
            "Replace GOOGLE_CLOUD_PROJECT=your-project-id in .env with your real project ID."
        )
    if explicit:
        return explicit

    try:
        _, project = google.auth.default()
    except DefaultCredentialsError as exc:
        raise RuntimeError(
            "Application Default Credentials not found. Run "
            "`gcloud auth application-default login` or set GOOGLE_APPLICATION_CREDENTIALS."
        ) from exc
    if not project:
        raise RuntimeError(
            "No Google Cloud project found. Set GOOGLE_CLOUD_PROJECT in .env "
            "or configure a default project with gcloud."
        )
    return project


def ensure_dataset(
    client: bigquery.Client,
    dataset_id: str,
    location: str,
) -> bigquery.Dataset:
    """Return the dataset, creating it when missing; reject location drift."""
    dataset_ref = bigquery.Dataset(f"{client.project}.{dataset_id}")
    try:
        dataset = client.get_dataset(dataset_ref)
    except NotFound:
        dataset_ref.location = location
        return client.create_dataset(dataset_ref)

    if dataset.location and location and dataset.location.upper() != location.upper():
        raise RuntimeError(f"dataset {dataset_id} is in {dataset.location}, expected {location}")
    return dataset


def load_indicators(
    indicators: list[Indicator],
    *,
    project: str,
    dataset_id: str,
    table_id: str,
    location: str,
) -> LoadResult:
    """Replace the indicators table with the supplied rows."""
    client = bigquery.Client(project=project, location=location)
    try:
        dataset = ensure_dataset(client, dataset_id, location)
        table_ref = dataset.table(table_id)
        job_config = bigquery.LoadJobConfig(
            schema=load_schema(),
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
        )
        job = client.load_table_from_json(
            [indicator.to_bq_row() for indicator in indicators],
            table_ref,
            job_config=job_config,
        )
        job.result()
        if job.errors:
            raise RuntimeError(f"BigQuery load failed: {job.errors}")
        table = client.get_table(table_ref)
        return LoadResult(
            project=project,
            dataset=dataset_id,
            table=table_id,
            location=table.location or location,
            rows=table.num_rows,
        )
    finally:
        client.close()

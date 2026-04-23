"""Shared BigQuery helpers for agent tools."""

from __future__ import annotations

import re
from functools import lru_cache

from google.cloud import bigquery

from config import Settings

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]+$")


@lru_cache(maxsize=1)
def get_client() -> bigquery.Client:
    """Return a cached BigQuery client using Application Default Credentials."""
    settings = Settings()
    return bigquery.Client(project=settings.google_cloud_project or None)


def qualified_name(settings: Settings, project: str, resource: str) -> str:
    """Return a validated, backticked dataset resource reference."""
    if project == "your-project-id":
        raise ValueError("GOOGLE_CLOUD_PROJECT is still the placeholder value")
    for value in (project, settings.bq_dataset, resource):
        if not value or _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("invalid BigQuery identifier in configuration")
    return f"`{project}.{settings.bq_dataset}.{resource}`"


def qualified_table(settings: Settings, project: str) -> str:
    return qualified_name(settings, project, settings.bq_table)


def qualified_model(settings: Settings, project: str) -> str:
    return qualified_name(settings, project, settings.bq_model)

"""BigQuery sighting lookup tool."""

from __future__ import annotations

from datetime import date
from typing import Literal

from google.cloud import bigquery
from pydantic import BaseModel, Field

from config import Settings
from tools.bq import get_client, qualified_table
from tools.schemas import ToolResult
from tools.validation import domain_variants, parse_indicator

LOOKUP_SQL = """
SELECT url, domain, label, threat_type, first_seen, source
FROM {table}
WHERE domain IN UNNEST(@domains)
   OR (@url IS NOT NULL AND url = @url)
ORDER BY first_seen DESC
LIMIT 50
"""


class LookupMatch(BaseModel):
    url: str | None = None
    domain: str
    label: Literal["malicious", "benign"]
    threat_type: str | None = None
    first_seen: date | None = None
    source: str


class LookupIndicatorResult(ToolResult):
    tool: Literal["lookup_indicator"] = "lookup_indicator"
    query: str
    matches: list[LookupMatch] = Field(default_factory=list)
    sightings: int = 0
    malicious_count: int = 0
    benign_count: int = 0
    has_conflicting_labels: bool = False


def _coerce_date(value: object) -> date | None:
    if value is None or isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _short_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc)[:300]}"


def lookup_indicator(domain_or_url: str) -> dict:
    """Look up previous malicious or benign sightings of a URL/domain in BigQuery.

    Use this before assigning a verdict. The SQL is fully parameterized. The
    result status is one of "ok", "not_found", "invalid", or "unavailable";
    lookup failures are returned, never raised. This tool does not fetch or
    connect to the submitted URL.
    """
    parsed = parse_indicator(domain_or_url)
    if parsed is None:
        return LookupIndicatorResult(
            status="invalid",
            query=domain_or_url,
            summary="Invalid input: expected a public http(s) URL or domain.",
            error="input failed URL/domain validation",
        ).model_dump(mode="json")

    normalized_query = parsed.url or parsed.host
    try:
        settings = Settings()
        client = get_client()
        project = settings.google_cloud_project or client.project
        table = qualified_table(settings, project)
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ArrayQueryParameter("domains", "STRING", domain_variants(parsed.host)),
                bigquery.ScalarQueryParameter("url", "STRING", parsed.url),
            ]
        )
        rows = client.query(LOOKUP_SQL.format(table=table), job_config=job_config).result()
        matches = [
            LookupMatch(
                url=row["url"],
                domain=row["domain"],
                label=row["label"],
                threat_type=row["threat_type"],
                first_seen=_coerce_date(row["first_seen"]),
                source=row["source"],
            )
            for row in rows
        ]
    except Exception as exc:
        return LookupIndicatorResult(
            status="unavailable",
            query=normalized_query,
            summary="BigQuery sighting lookup is unavailable.",
            error=_short_error(exc),
        ).model_dump(mode="json")

    malicious_count = sum(match.label == "malicious" for match in matches)
    benign_count = sum(match.label == "benign" for match in matches)
    has_conflicting_labels = malicious_count > 0 and benign_count > 0

    if matches:
        summary = (
            f"Found {len(matches)} sighting(s) for {parsed.host}: "
            f"{malicious_count} malicious, {benign_count} benign."
        )
        if has_conflicting_labels:
            summary += " Evidence conflicts and requires review."
    else:
        summary = f"No previous sightings for {parsed.host}."

    return LookupIndicatorResult(
        status="ok" if matches else "not_found",
        query=normalized_query,
        summary=summary,
        matches=matches,
        sightings=len(matches),
        malicious_count=malicious_count,
        benign_count=benign_count,
        has_conflicting_labels=has_conflicting_labels,
    ).model_dump(mode="json")

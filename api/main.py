"""FastAPI wrapper around the SOC triage agent."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agent.pipeline import triage
from agent.schemas import TriageResult
from config import Settings
from tools.bq import get_client

LOGGER = logging.getLogger("soc_triage.api")
READY_TTL_SECONDS = 30.0
TRIAGE_TIMEOUT_SECONDS = 230.0

app = FastAPI(
    title="SOC Alert Triage Agent",
    description="Evidence-gathering and fail-closed triage for a suspicious URL or domain.",
    version="0.1.0",
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/ui/", status_code=307)


_ready_cache: tuple[float, bool, dict[str, Any]] | None = None


class TriageRequest(BaseModel):
    indicator: str = Field(
        min_length=1,
        max_length=4096,
        description="Suspicious URL or domain to triage.",
    )


def _check_readiness() -> tuple[bool, dict[str, Any]]:
    checks: dict[str, Any] = {}
    try:
        settings = Settings()
        if not settings.google_cloud_project:
            raise RuntimeError("GOOGLE_CLOUD_PROJECT is not configured")
        checks["config"] = "ok"

        client = get_client()
        client.get_dataset(f"{settings.google_cloud_project}.{settings.bq_dataset}")
        checks["bigquery"] = "ok"
        return True, checks
    except Exception as exc:
        checks["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        return False, checks


def _cached_readiness() -> tuple[bool, dict[str, Any]]:
    global _ready_cache
    now = time.monotonic()
    if _ready_cache is not None and now - _ready_cache[0] < READY_TTL_SECONDS:
        return _ready_cache[1], _ready_cache[2]
    ready, checks = _check_readiness()
    _ready_cache = (now, ready, checks)
    return ready, checks


@app.get("/healthz")
@app.get("/health")
async def healthz() -> dict[str, str]:
    """Liveness check. Does not touch Google Cloud.

    ``/healthz`` is the requested path. ``/health`` is a Cloud Run-safe alias
    because Cloud Run's edge reserves some paths ending in ``z``.
    """
    return {"status": "ok"}


@app.get("/readyz")
@app.get("/ready")
async def readyz() -> JSONResponse:
    """Readiness check for config and BigQuery dataset access.

    Vertex AI is exercised by the first /triage call; this check stays cheap and
    does not make a model call. ``/ready`` is a Cloud Run-safe alias for
    ``/readyz``.
    """
    ready, checks = _cached_readiness()
    if not ready:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "checks": checks},
        )
    return JSONResponse(status_code=200, content={"status": "ready", "checks": checks})


@app.post("/triage", response_model=TriageResult)
async def triage_endpoint(request: TriageRequest) -> TriageResult:
    """Run the agent and return a structured, fail-closed Verdict."""
    try:
        return await asyncio.wait_for(
            triage(request.indicator),
            timeout=TRIAGE_TIMEOUT_SECONDS,
        )
    except TimeoutError as exc:
        LOGGER.exception("triage timed out")
        raise HTTPException(
            status_code=504,
            detail="Triage timed out; escalate to a human analyst.",
        ) from exc
    except Exception as exc:
        LOGGER.exception("triage endpoint failed")
        raise HTTPException(
            status_code=503,
            detail="Triage unavailable; escalate to a human analyst.",
        ) from exc

"""Structured JSON logging for triage runs."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime

from agent.schemas import TriageResult

_LOGGER_NAME = "soc_triage"


def _logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
        logger.propagate = False
    return logger


def log_triage(result: TriageResult) -> None:
    """Write one JSON line containing the input, tools, verdict, and latency."""
    payload = {
        "event": "triage_run",
        "timestamp": datetime.now(UTC).isoformat(),
        "run_id": result.run_id,
        "input": result.input,
        "model": result.model,
        "use_ml": result.use_ml,
        "tools_called": [item.model_dump(mode="json") for item in result.tools_called],
        "verdict": result.verdict.model_dump(mode="json"),
        "policy_escalations": result.policy_escalations,
        "latency_ms": round(result.latency_ms, 2),
        "investigator_latency_ms": (
            round(result.investigator_latency_ms, 2)
            if result.investigator_latency_ms is not None
            else None
        ),
        "formatter_latency_ms": (
            round(result.formatter_latency_ms, 2)
            if result.formatter_latency_ms is not None
            else None
        ),
        "error": result.error,
    }
    _logger().info(json.dumps(payload, default=str, separators=(",", ":")))

import json

import pytest

from agent.pipeline import _fail_closed, _verdict_from_state_or_text
from agent.recorder import ToolCall, ToolRecorder


def make_verdict_dict() -> dict:
    return {
        "severity": "low",
        "confidence": 0.9,
        "reasoning": "Benign evidence.",
        "evidence": [],
        "recommended_action": "Close as benign.",
        "status": "auto_closed",
        "classification": "benign",
    }


def test_verdict_from_state_dict() -> None:
    verdict = _verdict_from_state_or_text({"verdict": make_verdict_dict()}, "")

    assert verdict.classification == "benign"
    assert verdict.confidence == 0.9


def test_verdict_from_text_and_code_fence() -> None:
    raw = json.dumps(make_verdict_dict())
    verdict = _verdict_from_state_or_text({}, f"```json\n{raw}\n```")

    assert verdict.severity == "low"


def test_verdict_from_empty_text_raises() -> None:
    with pytest.raises(ValueError):
        _verdict_from_state_or_text({}, "")


def test_fail_closed_is_unknown_and_needs_review() -> None:
    recorder = ToolRecorder(
        calls=[
            ToolCall(
                tool="lookup_indicator",
                arguments={"domain_or_url": "example.com"},
                result={"status": "unavailable", "summary": "timeout"},
                status="unavailable",
                summary="timeout",
                latency_ms=1.0,
            )
        ]
    )

    verdict, reasons = _fail_closed("example.com", "RuntimeError: boom", recorder)

    assert verdict.status == "needs_review"
    assert verdict.classification == "unknown"
    assert verdict.confidence == 0.0
    assert verdict.evidence[0].tool == "lookup_indicator"
    assert reasons

from agent.policy import apply_policy
from agent.recorder import ToolCall, ToolRecorder
from agent.schemas import Verdict


def make_call(
    tool: str,
    status: str = "ok",
    result: dict | None = None,
    summary: str = "ok",
) -> ToolCall:
    payload = result or {"status": status, "summary": summary}
    return ToolCall(
        tool=tool,
        arguments={},
        result=payload,
        status=status,
        summary=summary,
        latency_ms=5.0,
    )


def make_verdict(**overrides) -> Verdict:
    values = {
        "severity": "low",
        "confidence": 0.9,
        "reasoning": "Evidence supports benign.",
        "evidence": [],
        "recommended_action": "Close as benign.",
        "status": "auto_closed",
        "classification": "benign",
    }
    values.update(overrides)
    return Verdict(**values)


def clean_recorder() -> ToolRecorder:
    return ToolRecorder(
        calls=[
            make_call(
                "lookup_indicator",
                result={
                    "status": "ok",
                    "summary": "found benign",
                    "malicious_count": 0,
                    "benign_count": 1,
                    "has_conflicting_labels": False,
                },
            ),
            make_call("enrich_domain", summary="DNS and RDAP ok"),
            make_call("extract_url_features", summary="features ok"),
        ]
    )


def test_clean_benign_verdict_can_auto_close() -> None:
    verdict, reasons = apply_policy(make_verdict(), clean_recorder())

    assert verdict.status == "auto_closed"
    assert reasons == []
    assert len(verdict.evidence) == 3
    assert [item.tool for item in verdict.evidence] == [
        "lookup_indicator",
        "enrich_domain",
        "extract_url_features",
    ]


def test_low_confidence_escalates() -> None:
    verdict, reasons = apply_policy(make_verdict(confidence=0.69), clean_recorder())

    assert verdict.status == "needs_review"
    assert any("confidence" in reason for reason in reasons)


def test_unavailable_tool_escalates() -> None:
    recorder = clean_recorder()
    recorder.calls[1] = make_call("enrich_domain", status="unavailable", summary="timeout")

    verdict, reasons = apply_policy(make_verdict(), recorder)

    assert verdict.status == "needs_review"
    assert any("enrich_domain" in reason for reason in reasons)


def test_partial_tool_escalates() -> None:
    recorder = clean_recorder()
    recorder.calls[1] = make_call("enrich_domain", status="partial", summary="no RDAP age")

    verdict, reasons = apply_policy(make_verdict(), recorder)

    assert verdict.status == "needs_review"
    assert any("partial" in reason for reason in reasons)


def test_missing_required_tool_escalates() -> None:
    recorder = clean_recorder()
    recorder.calls = [call for call in recorder.calls if call.tool != "enrich_domain"]

    verdict, reasons = apply_policy(make_verdict(), recorder)

    assert verdict.status == "needs_review"
    assert any("enrich_domain" in reason for reason in reasons)


def test_conflicting_lookup_labels_escalate() -> None:
    recorder = clean_recorder()
    recorder.calls[0] = make_call(
        "lookup_indicator",
        result={
            "status": "ok",
            "summary": "conflict",
            "malicious_count": 1,
            "benign_count": 1,
            "has_conflicting_labels": True,
        },
    )

    verdict, reasons = apply_policy(make_verdict(), recorder)

    assert verdict.status == "needs_review"
    assert any(
        "conflicting" in reason or "both malicious and benign" in reason for reason in reasons
    )


def test_benign_verdict_against_malicious_sighting_escalates() -> None:
    recorder = clean_recorder()
    recorder.calls[0] = make_call(
        "lookup_indicator",
        result={
            "status": "ok",
            "summary": "malicious",
            "malicious_count": 2,
            "benign_count": 0,
            "has_conflicting_labels": False,
        },
    )

    verdict, reasons = apply_policy(make_verdict(), recorder)

    assert verdict.status == "needs_review"
    assert any("only malicious" in reason for reason in reasons)


def test_malicious_verdict_always_escalates() -> None:
    verdict, reasons = apply_policy(
        make_verdict(classification="malicious", severity="medium"), clean_recorder()
    )

    assert verdict.status == "needs_review"
    assert any("malicious" in reason for reason in reasons)


def test_unknown_classification_escalates() -> None:
    verdict, reasons = apply_policy(make_verdict(classification="unknown"), clean_recorder())

    assert verdict.status == "needs_review"
    assert any("unknown" in reason for reason in reasons)


def test_high_severity_escalates() -> None:
    verdict, reasons = apply_policy(make_verdict(severity="high"), clean_recorder())

    assert verdict.status == "needs_review"
    assert any("severity" in reason for reason in reasons)


def test_model_requested_review_is_preserved() -> None:
    verdict, reasons = apply_policy(
        make_verdict(status="needs_review"),
        clean_recorder(),
    )

    assert verdict.status == "needs_review"
    assert reasons == []


def test_policy_replaces_model_evidence_and_appends_reasoning() -> None:
    verdict, _ = apply_policy(make_verdict(confidence=0.4), clean_recorder())

    assert verdict.evidence
    assert "Policy escalation:" in verdict.reasoning

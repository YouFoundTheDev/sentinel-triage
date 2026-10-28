"""Deterministic fail-closed policy applied after the model responds."""

from __future__ import annotations

from agent.recorder import ToolRecorder
from agent.schemas import Evidence, Verdict

MIN_CONFIDENCE = 0.7
REQUIRED_TOOLS = frozenset({"lookup_indicator", "enrich_domain", "extract_url_features"})
DEGRADED_STATUSES = frozenset({"partial", "unavailable", "invalid"})


def apply_policy(
    verdict: Verdict,
    recorder: ToolRecorder,
    *,
    expect_ml: bool = False,
) -> tuple[Verdict, list[str]]:
    """Enforce escalation rules after the model returns a verdict.

    The model is never trusted to be the only line of defense. Missing tools,
    degraded/unavailable tool calls, low confidence, conflicting evidence, and
    non-benign verdicts all force ``needs_review``.
    """
    reasons: list[str] = []

    required_tools = set(REQUIRED_TOOLS)
    if expect_ml:
        required_tools.add("ml_score")

    called_tools = {call.tool for call in recorder.calls}
    missing = required_tools - called_tools
    if missing:
        reasons.append(f"required tool(s) not called: {', '.join(sorted(missing))}")

    for call in recorder.calls:
        if call.status in DEGRADED_STATUSES:
            reasons.append(f"{call.tool} returned degraded status: {call.status}")

    if verdict.confidence < MIN_CONFIDENCE:
        reasons.append(
            f"confidence {verdict.confidence:.2f} is below the {MIN_CONFIDENCE:.1f} threshold"
        )

    lookup = recorder.last_result("lookup_indicator")
    if lookup:
        malicious = int(lookup.get("malicious_count", 0) or 0)
        benign = int(lookup.get("benign_count", 0) or 0)
        if lookup.get("has_conflicting_labels"):
            reasons.append("lookup evidence contains both malicious and benign labels")
        if malicious and not benign and verdict.classification == "benign":
            reasons.append("verdict says benign but lookup found only malicious sightings")
        if benign and not malicious and verdict.classification == "malicious":
            reasons.append("verdict says malicious but lookup found only benign sightings")

    ml = recorder.last_result("ml_score")
    if ml and ml.get("status") == "ok":
        predicted_label = ml.get("predicted_label")
        malicious_probability = ml.get("malicious_probability")
        if predicted_label == "malicious" and verdict.classification == "benign":
            reasons.append("ML predicts malicious while verdict says benign")
        if predicted_label == "benign" and verdict.classification == "malicious":
            reasons.append("ML predicts benign while verdict says malicious")
        if lookup:
            malicious = int(lookup.get("malicious_count", 0) or 0)
            benign = int(lookup.get("benign_count", 0) or 0)
            if predicted_label == "malicious" and benign and not malicious:
                reasons.append("ML predicts malicious but lookup found only benign sightings")
            if predicted_label == "benign" and malicious and not benign:
                reasons.append("ML predicts benign but lookup found only malicious sightings")
        if isinstance(malicious_probability, int | float):
            if malicious_probability >= 0.7 and verdict.classification == "benign":
                reasons.append("ML malicious probability is high while verdict says benign")
            if malicious_probability <= 0.3 and verdict.classification == "malicious":
                reasons.append("ML malicious probability is low while verdict says malicious")

    if verdict.classification == "unknown":
        reasons.append("classification is unknown")
    elif verdict.classification == "malicious":
        reasons.append("malicious verdicts require human review before blocking action")

    if verdict.severity in {"high", "critical"}:
        reasons.append("high or critical severity requires human review")

    reasons = list(dict.fromkeys(reasons))

    if reasons:
        status = "needs_review"
    elif verdict.status == "needs_review":
        status = "needs_review"
    else:
        status = "auto_closed"

    reasoning = verdict.reasoning.strip()
    if reasons:
        policy_note = "Policy escalation: " + "; ".join(reasons) + "."
        reasoning = f"{reasoning}\n\n{policy_note}" if reasoning else policy_note

    evidence = [
        Evidence(tool=call.tool, status=call.status, summary=call.summary)
        for call in recorder.calls
    ]
    updated = verdict.model_copy(
        update={"status": status, "reasoning": reasoning, "evidence": evidence}
    )
    return updated, reasons

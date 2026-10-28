"""Two-stage ADK triage pipeline: investigator, formatter, then policy."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from agent.instructions import FORMATTER_INSTRUCTION, INVESTIGATOR_INSTRUCTION
from agent.logging import log_triage
from agent.policy import apply_policy
from agent.recorder import ToolRecorder, record_tool
from agent.schemas import Evidence, TriageResult, Verdict
from config import Settings
from tools.enrich_domain import enrich_domain
from tools.lookup_indicator import lookup_indicator
from tools.url_features import extract_url_features

APP_NAME = "soc_triage"
MODEL_TIMEOUT_SECONDS = 90.0


def _event_text(event: Any) -> str:
    content = getattr(event, "content", None)
    if not content or not content.parts:
        return ""
    return "".join(
        part.text
        for part in content.parts
        if getattr(part, "text", None) and not getattr(part, "thought", False)
    )


async def _run_agent(agent: LlmAgent, prompt: str, user_id: str) -> tuple[str, dict[str, Any]]:
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME)
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=user_id)
    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    final_text = ""
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session.id,
        new_message=message,
    ):
        if event.is_final_response():
            final_text = _event_text(event) or final_text
    session = await runner.session_service.get_session(
        app_name=APP_NAME,
        user_id=user_id,
        session_id=session.id,
    )
    return final_text, dict(session.state)


def _build_investigator(recorder: ToolRecorder, model: str) -> LlmAgent:
    tools = [
        record_tool(lookup_indicator, recorder),
        record_tool(enrich_domain, recorder),
        record_tool(extract_url_features, recorder),
    ]
    return LlmAgent(
        name="soc_investigator",
        model=model,
        description="Gathers threat-intel, DNS/RDAP, and URL evidence for a suspicious indicator.",
        instruction=INVESTIGATOR_INSTRUCTION,
        tools=tools,
        output_key="analysis",
        timeout=MODEL_TIMEOUT_SECONDS,
        generate_content_config=types.GenerateContentConfig(temperature=0.2),
    )


def _build_formatter(model: str) -> LlmAgent:
    return LlmAgent(
        name="soc_verdict_formatter",
        model=model,
        description="Turns SOC evidence into a structured, fail-closed Verdict.",
        instruction=FORMATTER_INSTRUCTION,
        output_schema=Verdict,
        output_key="verdict",
        timeout=MODEL_TIMEOUT_SECONDS,
        generate_content_config=types.GenerateContentConfig(temperature=0.2),
    )


def _formatter_prompt(indicator: str, analysis: str, recorder: ToolRecorder) -> str:
    tool_payload = [
        {
            "tool": call.tool,
            "arguments": call.arguments,
            "status": call.status,
            "summary": call.summary,
            "result": call.result,
        }
        for call in recorder.calls
    ]
    return (
        f"Original indicator:\n{indicator}\n\n"
        f"Investigator summary:\n{analysis or '(empty)'}\n\n"
        "Raw tool results (JSON):\n"
        f"{json.dumps(tool_payload, indent=2, default=str)}\n\n"
        "Produce the Verdict now. Set evidence to an empty list; the orchestrator attaches "
        "the actual tool evidence. Follow the rubric and fail closed."
    )


def _verdict_from_state_or_text(state: dict[str, Any], text: str) -> Verdict:
    raw = state.get("verdict")
    if isinstance(raw, dict):
        return Verdict.model_validate(raw)
    if isinstance(raw, str):
        return Verdict.model_validate_json(raw)

    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
    if not cleaned:
        raise ValueError("formatter produced no verdict")
    return Verdict.model_validate_json(cleaned)


def _fail_closed(
    indicator: str,
    error: str,
    recorder: ToolRecorder,
) -> tuple[Verdict, list[str]]:
    evidence = [
        Evidence(tool=call.tool, status=call.status, summary=call.summary)
        for call in recorder.calls
    ]
    verdict = Verdict(
        severity="medium",
        confidence=0.0,
        reasoning=(
            f"Automated triage did not complete: {error}. "
            "This is not a clean verdict and must not be auto-closed."
        ),
        evidence=evidence,
        recommended_action="Escalate to a human analyst; do not auto-close.",
        status="needs_review",
        classification="unknown",
    )
    return verdict, [f"triage pipeline failed: {error}"]


async def triage(indicator: str) -> TriageResult:
    """Run the ADK investigator and formatter, then enforce policy in code."""
    settings = Settings()
    model = settings.gemini_model
    run_id = uuid.uuid4().hex
    recorder = ToolRecorder()
    started = time.perf_counter()
    investigator_latency_ms: float | None = None
    formatter_latency_ms: float | None = None
    analysis = ""
    error: str | None = None

    try:
        investigator = _build_investigator(recorder, model)
        investigator_started = time.perf_counter()
        analysis, _ = await _run_agent(
            investigator,
            f"Indicator to triage:\n{indicator}\n\nGather evidence now.",
            f"{run_id}-investigator",
        )
        investigator_latency_ms = (time.perf_counter() - investigator_started) * 1000

        if not recorder.calls:
            raise RuntimeError("investigator made no tool calls")

        formatter = _build_formatter(model)
        formatter_started = time.perf_counter()
        final_text, state = await _run_agent(
            formatter,
            _formatter_prompt(indicator, analysis, recorder),
            f"{run_id}-formatter",
        )
        formatter_latency_ms = (time.perf_counter() - formatter_started) * 1000

        verdict = _verdict_from_state_or_text(state, final_text)
        verdict, escalations = apply_policy(verdict, recorder)
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:500]}"
        verdict, escalations = _fail_closed(indicator, error, recorder)

    latency_ms = (time.perf_counter() - started) * 1000
    result = TriageResult(
        run_id=run_id,
        input=indicator,
        verdict=verdict,
        tools_called=recorder.to_summaries(),
        policy_escalations=escalations,
        latency_ms=latency_ms,
        investigator_latency_ms=investigator_latency_ms,
        formatter_latency_ms=formatter_latency_ms,
        model=model,
        error=error,
    )
    log_triage(result)
    return result

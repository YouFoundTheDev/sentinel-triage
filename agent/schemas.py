"""Pydantic schemas for the SOC triage agent."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Classification = Literal["benign", "malicious", "unknown"]
VerdictStatus = Literal["auto_closed", "needs_review"]


class Evidence(BaseModel):
    """One tool result used by the verdict."""

    tool: str = Field(description="Tool name, such as lookup_indicator.")
    status: str = Field(description="Tool status, such as ok, partial, or unavailable.")
    summary: str = Field(description="Short summary of what the tool returned.")


class Verdict(BaseModel):
    """Structured triage verdict returned by the agent."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity = Field(
        description="Risk severity: one of info, low, medium, high, critical."
    )
    confidence: float = Field(
        ge=0,
        le=1,
        description="Calibrated confidence from 0 to 1.",
    )
    reasoning: str = Field(description="Why the evidence supports this verdict.")
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Tool results used. The orchestrator replaces this with actual tool evidence.",
    )
    recommended_action: str = Field(description="Concrete next action for a SOC analyst.")
    status: VerdictStatus = Field(
        description="auto_closed only for confident benign results; otherwise needs_review."
    )
    classification: Classification = Field(
        description="Machine-readable label: benign, malicious, or unknown."
    )


class ToolCallSummary(BaseModel):
    """A compact, log-safe record of one tool invocation."""

    tool: str
    status: str
    summary: str
    latency_ms: float
    arguments: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    """Full result of one triage run, including tool and latency metadata."""

    run_id: str
    input: str
    verdict: Verdict
    tools_called: list[ToolCallSummary] = Field(default_factory=list)
    policy_escalations: list[str] = Field(default_factory=list)
    latency_ms: float
    investigator_latency_ms: float | None = None
    formatter_latency_ms: float | None = None
    model: str
    use_ml: bool = True
    error: str | None = None

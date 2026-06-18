"""Per-run tool call recording and exception-safe tool wrapping."""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Any

from agent.schemas import ToolCallSummary


@dataclass
class ToolCall:
    """In-memory record used by policy and evidence construction."""

    tool: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    status: str
    summary: str
    latency_ms: float


@dataclass
class ToolRecorder:
    """Collects tool calls for one triage run."""

    calls: list[ToolCall] = field(default_factory=list)

    def record(self, call: ToolCall) -> None:
        self.calls.append(call)

    def has_tool(self, name: str) -> bool:
        return any(call.tool == name for call in self.calls)

    def last_result(self, name: str) -> dict[str, Any] | None:
        for call in reversed(self.calls):
            if call.tool == name:
                return call.result
        return None

    def to_summaries(self) -> list[ToolCallSummary]:
        return [
            ToolCallSummary(
                tool=call.tool,
                status=call.status,
                summary=call.summary,
                latency_ms=round(call.latency_ms, 2),
                arguments=call.arguments,
            )
            for call in self.calls
        ]


def record_tool(
    fn: Callable[..., dict[str, Any]],
    recorder: ToolRecorder,
) -> Callable[..., dict[str, Any]]:
    """Wrap a tool so calls, statuses, and latency are recorded for this run.

    ``functools.wraps`` preserves the original signature and docstring, which is
    what ADK uses to build the model-facing tool schema.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
            if not isinstance(result, dict):
                result = {
                    "status": "unavailable",
                    "tool": fn.__name__,
                    "summary": f"{fn.__name__} returned a non-dict result.",
                    "error": "invalid tool return type",
                }
        except Exception as exc:
            result = {
                "status": "unavailable",
                "tool": fn.__name__,
                "summary": f"{fn.__name__} raised an unexpected exception.",
                "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            }

        try:
            bound = inspect.signature(fn).bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
        except TypeError:
            arguments = {"args": list(args), "kwargs": kwargs}

        latency_ms = (time.perf_counter() - started) * 1000
        recorder.record(
            ToolCall(
                tool=fn.__name__,
                arguments=arguments,
                result=result,
                status=str(result.get("status", "unavailable")),
                summary=str(result.get("summary", "")),
                latency_ms=latency_ms,
            )
        )
        return result

    return wrapper

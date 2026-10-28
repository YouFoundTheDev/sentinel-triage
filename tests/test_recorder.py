import inspect

from agent.recorder import ToolRecorder, record_tool


def test_record_tool_records_success_and_preserves_metadata() -> None:
    def sample_tool(domain_or_url: str) -> dict:
        """Look up a sample value."""
        return {"status": "ok", "summary": "found", "value": domain_or_url}

    recorder = ToolRecorder()
    wrapped = record_tool(sample_tool, recorder)

    result = wrapped("example.com")

    assert result["value"] == "example.com"
    assert wrapped.__doc__ == sample_tool.__doc__
    assert inspect.signature(wrapped) == inspect.signature(sample_tool)
    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call.tool == "sample_tool"
    assert call.status == "ok"
    assert call.summary == "found"
    assert call.arguments == {"domain_or_url": "example.com"}
    assert call.latency_ms >= 0


def test_record_tool_catches_exceptions() -> None:
    def broken_tool(value: str) -> dict:
        """Always fails."""
        raise RuntimeError("boom")

    recorder = ToolRecorder()
    wrapped = record_tool(broken_tool, recorder)

    result = wrapped("x")

    assert result["status"] == "unavailable"
    assert "RuntimeError" in result["error"]
    assert len(recorder.calls) == 1
    assert recorder.calls[0].status == "unavailable"


def test_record_tool_rejects_non_dict_results() -> None:
    def bad_tool(value: str) -> dict:
        """Returns the wrong type."""
        return "not a dict"  # type: ignore[return-value]

    recorder = ToolRecorder()
    wrapped = record_tool(bad_tool, recorder)

    result = wrapped("x")

    assert result["status"] == "unavailable"
    assert recorder.calls[0].status == "unavailable"

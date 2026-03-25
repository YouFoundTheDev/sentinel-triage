"""Shared pydantic schemas for tool results."""

from typing import Literal

from pydantic import BaseModel

ToolStatus = Literal["ok", "not_found", "partial", "unavailable", "invalid"]


class ToolResult(BaseModel):
    """Common envelope returned by every agent tool."""

    status: ToolStatus
    tool: str
    summary: str
    error: str | None = None

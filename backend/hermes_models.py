"""Data models for Hermes execution requests, results, and usage tracking."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HermesExecutionRequest(BaseModel):
    """Configuration and input parameter payload for requesting a Hermes execution."""

    prompt: str = Field(
        ...,
        description="The prompt or instruction to execute via Hermes agent.",
    )
    workspace_dir: str = Field(
        ...,
        description="Target workspace directory where Hermes will operate.",
    )
    model: Optional[str] = Field(
        default=None,
        description="Model override for Hermes invocation. Defaults to configured HERMES_DEFAULT_MODEL.",
    )
    toolsets: Optional[List[str]] = Field(
        default=None,
        description="List of toolset names to enable for this invocation.",
    )
    timeout_seconds: Optional[int] = Field(
        default=None,
        description="Timeout duration in seconds for the subprocess execution.",
    )
    safe_mode: Optional[bool] = Field(
        default=None,
        description="Whether to execute in safe mode (--safe-mode). Defaults to config setting.",
    )
    extra_args: Optional[List[str]] = Field(
        default_factory=list,
        description="Additional safe command line flags if needed.",
    )


class HermesUsageReport(BaseModel):
    """Structured report parsed from Hermes usage-file output."""

    estimated_cost_usd: float = 0.0
    cost_status: Optional[str] = None
    cost_source: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    api_calls: int = 0
    model: Optional[str] = None
    provider: Optional[str] = None
    session_id: Optional[str] = None
    completed: bool = False
    failed: bool = False
    service_tier: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class HermesExecutionResult(BaseModel):
    """Result of a Hermes subprocess execution."""

    success: bool = Field(
        ...,
        description="True if execution finished cleanly with returncode == 0 and without timing out.",
    )
    stdout: str = Field(
        default="",
        description="Captured standard output stream.",
    )
    stderr: str = Field(
        default="",
        description="Captured standard error stream.",
    )
    exit_code: Optional[int] = Field(
        default=None,
        description="Process exit code.",
    )
    timed_out: bool = Field(
        default=False,
        description="True if the execution timed out.",
    )
    cancelled: bool = Field(
        default=False,
        description="True if execution was manually cancelled.",
    )
    usage: Optional[HermesUsageReport] = Field(
        default=None,
        description="Parsed usage report if usage file was written and parsed.",
    )
    command_executed: List[str] = Field(
        default_factory=list,
        description="The actual command list invoked for execution.",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Detailed failure message if an error occurred during execution.",
    )
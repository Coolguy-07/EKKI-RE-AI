"""Audit logging module for tracking Hermes tool executions, permissions, and security decisions."""

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Regex patterns for detecting common credentials and sensitive tokens
SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token|bearer)\s*[:= ]\s*['\"]?([^\s'\";]+)['\"]?",
    r"sk-[a-zA-Z0-9]{20,}",
    r"ghp_[a-zA-Z0-9]{36}",
]
SECRET_REGEX = re.compile("|".join(SECRET_PATTERNS))


def redact_secrets(text: Optional[str]) -> Optional[str]:
    """Redacts passwords, tokens, and API keys from logged command strings or outputs."""
    if not text:
        return text
    return SECRET_REGEX.sub("[REDACTED_SECRET]", text)


class AuditRecord(BaseModel):
    """Structured audit event record for tool execution."""

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of the execution event.",
    )
    execution_id: str = Field(
        ...,
        description="Unique identifier for the execution request.",
    )
    project_id: Optional[str] = Field(
        default=None,
        description="Project ID associated with the execution context.",
    )
    requested_tool: str = Field(
        ...,
        description="Name of the requested tool.",
    )
    request_source: Optional[str] = Field(
        default="unknown",
        description="Model or component initiating the request.",
    )
    workspace: str = Field(
        ...,
        description="Configured workspace directory for the tool execution.",
    )
    command: Optional[str] = Field(
        default=None,
        description="Command string (sanitized/redacted) if terminal tool.",
    )
    working_dir: Optional[str] = Field(
        default=None,
        description="Working directory for the operation.",
    )
    permission_mode: Optional[str] = Field(
        default=None,
        description="Active permission mode (SAFE, ASK, FULL).",
    )
    approval_decision: Optional[str] = Field(
        default=None,
        description="Approval decision status (ALLOW, DENY, APPROVED, DENIED, etc.).",
    )
    approval_scope: Optional[str] = Field(
        default=None,
        description="Granted approval scope (once, session, None).",
    )
    security_decision: str = Field(
        ...,
        description="Security policy decision code.",
    )
    success: bool = Field(
        ...,
        description="Whether the tool execution completed successfully.",
    )
    duration_seconds: float = Field(
        default=0.0,
        description="Execution duration in seconds.",
    )
    exit_status: Optional[int] = Field(
        default=None,
        description="Subprocess exit code if applicable.",
    )
    sanitized_params: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Sanitized parameter dictionary without sensitive data.",
    )


class AuditLogger:
    """Thread-safe logger for recording structured security audit events."""

    def __init__(self, log_path: Optional[Union[str, Path]] = None):
        if log_path:
            self.log_path = Path(log_path)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.log_path = None
        self._in_memory_records: List[AuditRecord] = []

    def log_event(self, record: AuditRecord) -> None:
        """Records an audit event to memory and optionally appends to disk."""
        # Redact secrets in command string if present
        if record.command:
            record.command = redact_secrets(record.command)

        self._in_memory_records.append(record)
        logger.info(
            f"[AUDIT] ID={record.execution_id} Tool={record.requested_tool} "
            f"Mode={record.permission_mode} Decision={record.security_decision} "
            f"Success={record.success} Duration={record.duration_seconds:.3f}s"
        )
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(record.model_dump_json() + "\n")
            except Exception as e:
                logger.error(f"Failed to write audit log to '{self.log_path}': {e}")

    def get_records(self) -> List[AuditRecord]:
        """Returns in-memory recorded audit logs (primarily for testing and inspection)."""
        return list(self._in_memory_records)

    def clear(self) -> None:
        """Clears in-memory audit records."""
        self._in_memory_records.clear()


# Default global audit logger instance
audit_logger = AuditLogger()

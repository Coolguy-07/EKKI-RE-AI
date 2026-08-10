"""Security-enforced ToolRouter for controlled Hermes tool execution and permission routing in EKKI-RE-AI."""

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field

from backend.config import settings
from backend.hermes_bridge import HermesBridge, HermesBridgeError
from backend.hermes_models import HermesExecutionRequest, HermesExecutionResult, HermesUsageReport
from backend.security.audit_logger import AuditLogger, AuditRecord, audit_logger, redact_secrets
from backend.security.permission_manager import (
    ApprovalRequest,
    ExecutionMode,
    PermissionDecision,
    PermissionManager,
    permission_manager,
)
from backend.security.workspace_policy import WorkspacePolicy, WorkspacePolicyError

logger = logging.getLogger(__name__)

# Phase 3 Tool Allowlist (includes controlled terminal execution)
ALLOWED_TOOLS: Set[str] = {"file_list", "file_read", "file_metadata", "terminal_execute"}
MAX_OUTPUT_BYTES: int = 102_400  # 100 KB max output limit


class ToolRequest(BaseModel):
    """Structured tool execution request model."""

    tool: str = Field(
        ...,
        description="Name of the tool operation to execute (must be in ALLOWED_TOOLS).",
    )
    workspace_dir: str = Field(
        ...,
        description="Target workspace directory for the tool execution.",
    )
    project_id: Optional[str] = Field(
        default=None,
        description="Optional project ID for context tracking.",
    )
    session_id: Optional[str] = Field(
        default="default",
        description="Session identifier for tracking active session permissions.",
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured key-value arguments for the tool operation.",
    )
    request_source: Optional[str] = Field(
        default="AgentOrchestrator",
        description="Source identifier initiating the tool request.",
    )
    timeout_seconds: Optional[int] = Field(
        default=None,
        description="Optional execution timeout override in seconds.",
    )


class ToolExecutionResult(BaseModel):
    """Structured result returned by ToolRouter to callers."""

    success: bool = Field(
        ...,
        description="True if execution completed and passed all security checks.",
    )
    tool: str = Field(
        ...,
        description="The requested tool name.",
    )
    project_id: Optional[str] = Field(
        default=None,
        description="Project ID context.",
    )
    execution_id: str = Field(
        ...,
        description="Unique execution tracking ID.",
    )
    output: Optional[Any] = Field(
        default=None,
        description="Sanitized tool output.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error details if execution failed or was denied.",
    )
    duration: float = Field(
        default=0.0,
        description="Total duration of the operation in seconds.",
    )
    usage: Optional[HermesUsageReport] = Field(
        default=None,
        description="Token usage metrics if available.",
    )
    security_decision: str = Field(
        ...,
        description="Security decision code (e.g. ALLOW, DENY_UNALLOWED_TOOL, DENY_PATH_TRAVERSAL, APPROVAL_REQUIRED).",
    )
    approval_request: Optional[ApprovalRequest] = Field(
        default=None,
        description="Approval request details if user confirmation is required.",
    )


class ToolRouter:
    """Centralized security router for executing abstract tool operations via Hermes bridge."""

    def __init__(
        self,
        bridge: Optional[HermesBridge] = None,
        workspace_root: Optional[str] = None,
        logger_instance: Optional[AuditLogger] = None,
        permission_mgr: Optional[PermissionManager] = None,
    ):
        self.workspace_root = workspace_root or settings.HERMES_WORKSPACE_ROOT
        self.bridge = bridge or HermesBridge(workspace_root=self.workspace_root)
        self.audit_logger = logger_instance or audit_logger
        self.permission_mgr = permission_mgr or permission_manager

    async def execute_tool(self, request: ToolRequest) -> ToolExecutionResult:
        """Validates security boundaries, permission modes, constructs safe Hermes request,

        executes tool, and logs structured audit trail.
        """
        execution_id = uuid.uuid4().hex
        start_time = time.time()
        tool_name = request.tool.strip() if request.tool else ""
        perm_mode = self.permission_mgr.get_mode().value

        # 1. Tool Allowlist Check
        if tool_name not in ALLOWED_TOOLS:
            duration = time.time() - start_time
            err_msg = f"Tool '{tool_name}' is not in the approved allowlist ({sorted(ALLOWED_TOOLS)})."
            self.audit_logger.log_event(
                AuditRecord(
                    execution_id=execution_id,
                    project_id=request.project_id,
                    requested_tool=tool_name,
                    request_source=request.request_source,
                    workspace=request.workspace_dir,
                    permission_mode=perm_mode,
                    security_decision="DENY_UNALLOWED_TOOL",
                    success=False,
                    duration_seconds=duration,
                    sanitized_params=self._sanitize_params(request.arguments),
                )
            )
            return ToolExecutionResult(
                success=False,
                tool=tool_name,
                project_id=request.project_id,
                execution_id=execution_id,
                error=err_msg,
                duration=duration,
                security_decision="DENY_UNALLOWED_TOOL",
            )

        # 2. Workspace Policy & Containment Validation
        try:
            policy = WorkspacePolicy(request.workspace_dir)
            validated_workspace = policy.workspace_root
            if not validated_workspace.exists():
                raise WorkspacePolicyError(f"Workspace directory '{request.workspace_dir}' does not exist.")
        except Exception as e:
            duration = time.time() - start_time
            err_msg = f"Invalid workspace boundary: {e}"
            self.audit_logger.log_event(
                AuditRecord(
                    execution_id=execution_id,
                    project_id=request.project_id,
                    requested_tool=tool_name,
                    request_source=request.request_source,
                    workspace=request.workspace_dir,
                    permission_mode=perm_mode,
                    security_decision="DENY_INVALID_WORKSPACE",
                    success=False,
                    duration_seconds=duration,
                    sanitized_params=self._sanitize_params(request.arguments),
                )
            )
            return ToolExecutionResult(
                success=False,
                tool=tool_name,
                project_id=request.project_id,
                execution_id=execution_id,
                error=err_msg,
                duration=duration,
                security_decision="DENY_INVALID_WORKSPACE",
            )

        # 3. Path & Parameter Security Check (Run before permission check to block traversal early)
        if tool_name == "terminal_execute":
            command = str(request.arguments.get("command", "")).strip()
            if not command:
                duration = time.time() - start_time
                err_msg = "Command string is required for terminal execution."
                return ToolExecutionResult(
                    success=False,
                    tool=tool_name,
                    project_id=request.project_id,
                    execution_id=execution_id,
                    error=err_msg,
                    duration=duration,
                    security_decision="INVALID_ARGUMENTS",
                )

            cwd_param = str(request.arguments.get("cwd", ".")).strip()
            try:
                target_cwd_full = validated_workspace / cwd_param
                resolved_cwd = policy.resolve_and_validate(target_cwd_full)
                safe_rel_cwd = resolved_cwd.relative_to(validated_workspace)
            except Exception as e:
                duration = time.time() - start_time
                err_msg = f"Working directory security violation for '{cwd_param}': {e}"
                self.audit_logger.log_event(
                    AuditRecord(
                        execution_id=execution_id,
                        project_id=request.project_id,
                        requested_tool=tool_name,
                        request_source=request.request_source,
                        workspace=str(validated_workspace),
                        command=command,
                        working_dir=cwd_param,
                        permission_mode=perm_mode,
                        security_decision="DENY_PATH_TRAVERSAL",
                        success=False,
                        duration_seconds=duration,
                        sanitized_params=self._sanitize_params(request.arguments),
                    )
                )
                return ToolExecutionResult(
                    success=False,
                    tool=tool_name,
                    project_id=request.project_id,
                    execution_id=execution_id,
                    error=err_msg,
                    duration=duration,
                    security_decision="DENY_PATH_TRAVERSAL",
                )

            prompt = f"Execute terminal command inside workspace: '{command}' in working directory '{safe_rel_cwd}'."
            toolsets = ["terminal", "file"]

        else:
            rel_path = request.arguments.get("path", ".")
            try:
                target_full_path = validated_workspace / rel_path
                resolved_target = policy.resolve_and_validate(target_full_path)
                safe_rel_path = resolved_target.relative_to(validated_workspace)
            except Exception as e:
                duration = time.time() - start_time
                err_msg = f"Path security violation for parameter '{rel_path}': {e}"
                self.audit_logger.log_event(
                    AuditRecord(
                        execution_id=execution_id,
                        project_id=request.project_id,
                        requested_tool=tool_name,
                        request_source=request.request_source,
                        workspace=str(validated_workspace),
                        permission_mode=perm_mode,
                        security_decision="DENY_PATH_TRAVERSAL",
                        success=False,
                        duration_seconds=duration,
                        sanitized_params=self._sanitize_params(request.arguments),
                    )
                )
                return ToolExecutionResult(
                    success=False,
                    tool=tool_name,
                    project_id=request.project_id,
                    execution_id=execution_id,
                    error=err_msg,
                    duration=duration,
                    security_decision="DENY_PATH_TRAVERSAL",
                )

            prompt = self._build_prompt_for_tool(tool_name, str(safe_rel_path), request.arguments)
            toolsets = ["file"]

        # 4. Permission Policy Evaluation (SAFE / ASK / FULL)
        decision = self.permission_mgr.evaluate_permission(tool_name, session_id=request.session_id)

        if decision == PermissionDecision.DENY:
            duration = time.time() - start_time
            err_msg = f"Execution of tool '{tool_name}' is denied under permission mode '{perm_mode}'."
            self.audit_logger.log_event(
                AuditRecord(
                    execution_id=execution_id,
                    project_id=request.project_id,
                    requested_tool=tool_name,
                    request_source=request.request_source,
                    workspace=request.workspace_dir,
                    permission_mode=perm_mode,
                    security_decision="DENY_PERMISSION_POLICY",
                    success=False,
                    duration_seconds=duration,
                    sanitized_params=self._sanitize_params(request.arguments),
                )
            )
            return ToolExecutionResult(
                success=False,
                tool=tool_name,
                project_id=request.project_id,
                execution_id=execution_id,
                error=err_msg,
                duration=duration,
                security_decision="DENY_PERMISSION_POLICY",
            )

        if decision == PermissionDecision.ASK:
            duration = time.time() - start_time
            command_str = str(request.arguments.get("command") or request.arguments.get("path") or tool_name)
            cwd_str = str(request.arguments.get("cwd") or ".")
            app_req = self.permission_mgr.create_approval_request(
                tool=tool_name,
                command=command_str,
                workspace_dir=request.workspace_dir,
                cwd=cwd_str,
                reason=f"Model request from source '{request.request_source}'",
                request_source=request.request_source,
                timeout_seconds=request.timeout_seconds or settings.HERMES_DEFAULT_TIMEOUT_SECONDS,
            )
            self.audit_logger.log_event(
                AuditRecord(
                    execution_id=execution_id,
                    project_id=request.project_id,
                    requested_tool=tool_name,
                    request_source=request.request_source,
                    workspace=request.workspace_dir,
                    command=command_str,
                    working_dir=cwd_str,
                    permission_mode=perm_mode,
                    security_decision="APPROVAL_REQUIRED",
                    success=False,
                    duration_seconds=duration,
                    sanitized_params=self._sanitize_params(request.arguments),
                )
            )
            return ToolExecutionResult(
                success=False,
                tool=tool_name,
                project_id=request.project_id,
                execution_id=execution_id,
                error="User approval required for tool execution.",
                duration=duration,
                security_decision="APPROVAL_REQUIRED",
                approval_request=app_req,
            )

        # 5. Build Subprocess Request
        hermes_req = HermesExecutionRequest(
            prompt=prompt,
            workspace_dir=str(validated_workspace),
            toolsets=toolsets,
            safe_mode=True,
            timeout_seconds=request.timeout_seconds,
        )

        # 6. Execute Subprocess via HermesBridge
        bridge_res: HermesExecutionResult = await self.bridge.execute(hermes_req)
        duration = time.time() - start_time

        # 7. Apply Output Size Limits & Sanitization
        output_str = bridge_res.stdout
        if output_str:
            output_str = redact_secrets(output_str)
            if len(output_str.encode("utf-8")) > MAX_OUTPUT_BYTES:
                output_str = output_str[:MAX_OUTPUT_BYTES] + "\n[OUTPUT TRUNCATED DUE TO SIZE LIMIT]"

        security_decision = "ALLOW" if bridge_res.success else "EXECUTION_FAILED"

        # 8. Record Audit Event
        self.audit_logger.log_event(
            AuditRecord(
                execution_id=execution_id,
                project_id=request.project_id,
                requested_tool=tool_name,
                request_source=request.request_source,
                workspace=str(validated_workspace),
                command=request.arguments.get("command"),
                working_dir=request.arguments.get("cwd"),
                permission_mode=perm_mode,
                security_decision=security_decision,
                success=bridge_res.success,
                duration_seconds=duration,
                exit_status=bridge_res.exit_code,
                sanitized_params=self._sanitize_params(request.arguments),
            )
        )

        return ToolExecutionResult(
            success=bridge_res.success,
            tool=tool_name,
            project_id=request.project_id,
            execution_id=execution_id,
            output=output_str if bridge_res.success else None,
            error=bridge_res.error_message or (bridge_res.stderr if not bridge_res.success else None),
            duration=duration,
            usage=bridge_res.usage,
            security_decision=security_decision,
        )

    def _build_prompt_for_tool(self, tool_name: str, rel_path: str, args: Dict[str, Any]) -> str:
        """Constructs an unambiguous, safe execution prompt for Hermes based on abstract tool parameters."""
        clean_path = "." if rel_path in ("", ".") else rel_path

        if tool_name == "file_list":
            return f"List all files and subdirectories in '{clean_path}' inside the workspace."

        elif tool_name == "file_read":
            max_bytes = min(int(args.get("max_bytes", 4096)), MAX_OUTPUT_BYTES)
            return f"Read the text content of file '{clean_path}' up to {max_bytes} bytes."

        elif tool_name == "file_metadata":
            return f"Show metadata details (file size, permissions, modified time) for '{clean_path}'."

        raise ValueError(f"Unsupported tool '{tool_name}'.")

    def _sanitize_params(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Returns a sanitized copy of arguments suitable for logging without leaking secrets."""
        sanitized = {}
        for k, v in args.items():
            if any(s in k.lower() for s in ("secret", "token", "password", "key")) and not isinstance(v, dict):
                sanitized[k] = "******"
            elif isinstance(v, str):
                redacted_v = redact_secrets(v)
                sanitized[k] = redacted_v[:200] + "..." if len(redacted_v) > 200 else redacted_v
            else:
                sanitized[k] = v
        return sanitized

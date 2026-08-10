"""Unit and security integration tests for Phase 3 PermissionManager, AuditLogger secret redaction,

and ToolRouter user-controlled command execution.
"""

import asyncio
import os
import pytest
from pathlib import Path

from backend.agent_orchestrator import AgentOrchestrator
from backend.hermes_bridge import HermesBridge
from backend.hermes_models import HermesExecutionRequest, HermesExecutionResult, HermesUsageReport
from backend.security.audit_logger import AuditLogger, AuditRecord, redact_secrets
from backend.security.permission_manager import (
    ApprovalRequest,
    ApprovalScope,
    ApprovalStatus,
    ExecutionMode,
    PermissionDecision,
    PermissionManager,
)
from backend.tool_router import (
    ALLOWED_TOOLS,
    MAX_OUTPUT_BYTES,
    ToolExecutionResult,
    ToolRequest,
    ToolRouter,
)


class TestPermissionManager:
    """Unit test suite for PermissionManager modes, decisions, and approval scopes."""

    def test_default_safe_mode(self):
        pm = PermissionManager()
        assert pm.get_mode() == ExecutionMode.SAFE

    def test_safe_tools_allowed_in_all_modes(self):
        pm = PermissionManager()
        for mode in [ExecutionMode.SAFE, ExecutionMode.ASK, ExecutionMode.FULL]:
            pm.set_mode(mode, caller_source="user")
            for safe_tool in ["file_list", "file_read", "file_metadata"]:
                assert pm.evaluate_permission(safe_tool) == PermissionDecision.ALLOW

    def test_safe_mode_denies_terminal_execution(self):
        pm = PermissionManager(mode=ExecutionMode.SAFE)
        assert pm.evaluate_permission("terminal_execute") == PermissionDecision.DENY

    def test_full_mode_allows_terminal_execution(self):
        pm = PermissionManager(mode=ExecutionMode.FULL)
        assert pm.evaluate_permission("terminal_execute") == PermissionDecision.ALLOW

    def test_ask_mode_requires_approval(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        assert pm.evaluate_permission("terminal_execute") == PermissionDecision.ASK

    def test_user_mode_change(self):
        pm = PermissionManager()
        pm.set_mode(ExecutionMode.ASK, caller_source="user")
        assert pm.get_mode() == ExecutionMode.ASK

        pm.set_mode(ExecutionMode.FULL, caller_source="api")
        assert pm.get_mode() == ExecutionMode.FULL

    def test_unauthorized_model_mode_change_rejection(self):
        pm = PermissionManager()
        with pytest.raises(ValueError) as exc_info:
            pm.set_mode(ExecutionMode.FULL, caller_source="model")
        assert "Unauthorized caller" in str(exc_info.value)
        assert pm.get_mode() == ExecutionMode.SAFE

    def test_create_and_get_approval_request(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        req = pm.create_approval_request(
            tool="terminal_execute",
            command="python script.py",
            workspace_dir="/tmp/workspace",
            cwd=".",
            reason="Model requested analysis",
        )
        assert req.status == ApprovalStatus.PENDING
        assert req.command == "python script.py"
        assert len(pm.get_pending_requests()) == 1
        assert pm.get_request(req.request_id) == req

    def test_allow_once_approval(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        req = pm.create_approval_request(
            tool="terminal_execute",
            command="ls",
            workspace_dir="/tmp/workspace",
        )
        updated = pm.submit_decision(req.request_id, action="approve", scope=ApprovalScope.ONCE, caller_source="user")
        assert updated.status == ApprovalStatus.APPROVED
        assert updated.approval_scope == ApprovalScope.ONCE
        assert len(pm.get_pending_requests()) == 0

    def test_deny_approval(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        req = pm.create_approval_request(
            tool="terminal_execute",
            command="rm -rf /",
            workspace_dir="/tmp/workspace",
        )
        updated = pm.submit_decision(req.request_id, action="deny", caller_source="user")
        assert updated.status == ApprovalStatus.DENIED
        assert updated.approval_scope is None

    def test_allow_session_approval(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        req = pm.create_approval_request(
            tool="terminal_execute",
            command="python run.py",
            workspace_dir="/tmp/workspace",
        )
        pm.submit_decision(req.request_id, action="approve", scope=ApprovalScope.SESSION, session_id="sess_100", caller_source="user")
        
        # Second call in same session should now be automatically ALLOWED
        assert pm.evaluate_permission("terminal_execute", session_id="sess_100") == PermissionDecision.ALLOW
        # Different session should still be ASK
        assert pm.evaluate_permission("terminal_execute", session_id="sess_200") == PermissionDecision.ASK

    def test_session_permission_clear(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        req = pm.create_approval_request(
            tool="terminal_execute",
            command="dir",
            workspace_dir="/tmp/workspace",
        )
        pm.submit_decision(req.request_id, action="approve", scope=ApprovalScope.SESSION, session_id="sess_100", caller_source="user")
        assert pm.evaluate_permission("terminal_execute", session_id="sess_100") == PermissionDecision.ALLOW

        pm.clear_session_permissions(session_id="sess_100")
        assert pm.evaluate_permission("terminal_execute", session_id="sess_100") == PermissionDecision.ASK

    def test_unauthorized_model_self_approval_rejection(self):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        req = pm.create_approval_request(
            tool="terminal_execute",
            command="whoami",
            workspace_dir="/tmp/workspace",
        )
        with pytest.raises(ValueError) as exc_info:
            pm.submit_decision(req.request_id, action="approve", caller_source="model")
        assert "Unauthorized caller" in str(exc_info.value)


class TestSecretRedaction:
    """Test suite for secret redaction in audit logging."""

    def test_redact_api_keys_and_passwords(self):
        raw_cmd = "python script.py --api-key sk-abc1234567890123456789 --password Secret123Pass"
        redacted = redact_secrets(raw_cmd)
        assert "sk-abc" not in redacted
        assert "Secret123Pass" not in redacted
        assert "[REDACTED_SECRET]" in redacted


@pytest.mark.anyio
class TestToolRouterPhase3:
    """Security integration tests for Phase 3 ToolRouter command execution."""

    async def test_safe_mode_blocks_terminal_execute(self, tmp_path):
        pm = PermissionManager(mode=ExecutionMode.SAFE)
        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger, permission_mgr=pm)

        req = ToolRequest(
            tool="terminal_execute",
            workspace_dir=str(tmp_path),
            arguments={"command": "dir"},
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "DENY_PERMISSION_POLICY"
        assert "denied under permission mode 'SAFE'" in res.error

    async def test_ask_mode_triggers_approval_required(self, tmp_path):
        pm = PermissionManager(mode=ExecutionMode.ASK)
        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger, permission_mgr=pm)

        req = ToolRequest(
            tool="terminal_execute",
            workspace_dir=str(tmp_path),
            arguments={"command": "python -m py_compile app.py", "cwd": "."},
            request_source="VulnerabilityAnalyst",
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "APPROVAL_REQUIRED"
        assert res.approval_request is not None
        assert res.approval_request.command == "python -m py_compile app.py"
        assert res.approval_request.request_source == "VulnerabilityAnalyst"

    async def test_full_mode_terminal_execution(self, tmp_path):
        pm = PermissionManager(mode=ExecutionMode.FULL)

        class MockTerminalBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                return HermesExecutionResult(
                    success=True,
                    stdout="Command Output Data",
                    exit_code=0,
                )

        router = ToolRouter(bridge=MockTerminalBridge(), workspace_root=str(tmp_path), permission_mgr=pm)

        req = ToolRequest(
            tool="terminal_execute",
            workspace_dir=str(tmp_path),
            arguments={"command": "echo test", "cwd": "."},
        )
        res = await router.execute_tool(req)

        assert res.success is True
        assert res.security_decision == "ALLOW"
        assert res.output == "Command Output Data"

    async def test_invalid_cwd_path_traversal_rejection(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        pm = PermissionManager(mode=ExecutionMode.FULL)
        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger, permission_mgr=pm)

        req = ToolRequest(
            tool="terminal_execute",
            workspace_dir=str(workspace),
            arguments={"command": "dir", "cwd": "../secret"},
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "DENY_PATH_TRAVERSAL"
        assert "Working directory security violation" in res.error

    async def test_secret_redaction_in_audit_record(self, tmp_path):
        pm = PermissionManager(mode=ExecutionMode.FULL)

        class MockBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                return HermesExecutionResult(success=True, stdout="Output sk-12345678901234567890", exit_code=0)

        test_logger = AuditLogger()
        router = ToolRouter(bridge=MockBridge(), workspace_root=str(tmp_path), logger_instance=test_logger, permission_mgr=pm)

        req = ToolRequest(
            tool="terminal_execute",
            workspace_dir=str(tmp_path),
            arguments={"command": "run --key=sk-12345678901234567890", "cwd": "."},
        )
        res = await router.execute_tool(req)

        assert res.success is True
        assert "sk-12345" not in res.output
        assert "[REDACTED_SECRET]" in res.output

        records = test_logger.get_records()
        assert len(records) == 1
        assert "sk-12345" not in records[0].command

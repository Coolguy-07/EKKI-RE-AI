"""Unit and security integration tests for Phase 2 ToolRouter, AuditLogger, and AgentOrchestrator integration."""

import asyncio
import os
import sys
import tempfile
import pytest
from pathlib import Path

from backend.agent_orchestrator import AgentOrchestrator
from backend.config import settings
from backend.hermes_bridge import HermesBridge
from backend.hermes_models import HermesExecutionRequest, HermesExecutionResult, HermesUsageReport
from backend.security.audit_logger import AuditLogger, AuditRecord, audit_logger
from backend.tool_router import (
    ALLOWED_TOOLS,
    MAX_OUTPUT_BYTES,
    ToolExecutionResult,
    ToolRequest,
    ToolRouter,
)


@pytest.mark.anyio
class TestToolRouterSecurity:
    """Security and functional test suite for ToolRouter."""

    async def test_allowed_tool_execution(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        test_file = workspace / "sample.txt"
        test_file.write_text("Hello Hermes Security Boundary", encoding="utf-8")

        class FastSuccessBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                return HermesExecutionResult(
                    success=True,
                    stdout="sample.txt",
                    exit_code=0,
                    usage=HermesUsageReport(completed=True, total_tokens=10),
                )

        test_logger = AuditLogger()
        router = ToolRouter(bridge=FastSuccessBridge(), workspace_root=str(tmp_path), logger_instance=test_logger)

        req = ToolRequest(
            tool="file_list",
            workspace_dir=str(workspace),
            arguments={"path": "."},
            request_source="TestAgent",
        )
        res = await router.execute_tool(req)

        assert res.success is True
        assert res.security_decision == "ALLOW"
        assert res.tool == "file_list"
        assert res.execution_id is not None
        assert "sample.txt" in str(res.output)

        records = test_logger.get_records()
        assert len(records) == 1
        assert records[0].security_decision == "ALLOW"
        assert records[0].requested_tool == "file_list"

    async def test_denied_unallowed_tool(self, tmp_path):
        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger)

        unallowed_tools = [
            "terminal", "powershell", "browser", "computer_use",
            "cron", "messaging", "delegation", "code_execution", "exec_shell"
        ]

        for bad_tool in unallowed_tools:
            req = ToolRequest(
                tool=bad_tool,
                workspace_dir=str(tmp_path),
                arguments={"cmd": "whoami"},
            )
            res = await router.execute_tool(req)
            assert res.success is False
            assert res.security_decision == "DENY_UNALLOWED_TOOL"
            assert "not in the approved allowlist" in res.error

        records = test_logger.get_records()
        assert len(records) == len(unallowed_tools)
        for record in records:
            assert record.security_decision == "DENY_UNALLOWED_TOOL"

    async def test_invalid_workspace_rejection(self, tmp_path):
        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger)
        non_existent_workspace = tmp_path / "non_existent_dir_12345"

        req = ToolRequest(
            tool="file_list",
            workspace_dir=str(non_existent_workspace),
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "DENY_INVALID_WORKSPACE"
        assert "does not exist" in res.error

    async def test_path_traversal_rejection(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside_secret = tmp_path / "secret.txt"
        outside_secret.write_text("SUPER_SECRET_KEY", encoding="utf-8")

        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger)

        req = ToolRequest(
            tool="file_read",
            workspace_dir=str(workspace),
            arguments={"path": "../secret.txt"},
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "DENY_PATH_TRAVERSAL"
        assert "Path security violation" in res.error

        records = test_logger.get_records()
        assert len(records) == 1
        assert records[0].security_decision == "DENY_PATH_TRAVERSAL"

    async def test_absolute_external_path_rejection(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger)

        ext_path = "C:\\Windows\\System32\\cmd.exe" if os.name == "nt" else "/etc/passwd"

        req = ToolRequest(
            tool="file_metadata",
            workspace_dir=str(workspace),
            arguments={"path": ext_path},
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "DENY_PATH_TRAVERSAL"

    async def test_symlink_escape_rejection(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "external.txt"
        outside_file.write_text("External Data", encoding="utf-8")

        symlink_path = workspace / "escaped_link"
        try:
            os.symlink(str(outside_file), str(symlink_path))
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this platform/privilege level.")

        test_logger = AuditLogger()
        router = ToolRouter(workspace_root=str(tmp_path), logger_instance=test_logger)

        req = ToolRequest(
            tool="file_read",
            workspace_dir=str(workspace),
            arguments={"path": "escaped_link"},
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "DENY_PATH_TRAVERSAL"

    async def test_oversized_output_truncation(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        class MockBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                huge_data = "A" * (MAX_OUTPUT_BYTES + 5000)
                return HermesExecutionResult(
                    success=True,
                    stdout=huge_data,
                    exit_code=0,
                )

        router = ToolRouter(bridge=MockBridge(), workspace_root=str(tmp_path), logger_instance=AuditLogger())

        req = ToolRequest(
            tool="file_read",
            workspace_dir=str(workspace),
            arguments={"path": "."},
        )
        res = await router.execute_tool(req)

        assert res.success is True
        assert "[OUTPUT TRUNCATED DUE TO SIZE LIMIT]" in res.output
        assert len(res.output.encode("utf-8")) <= MAX_OUTPUT_BYTES + 200

    async def test_timeout_handling(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        class TimeoutMockBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                return HermesExecutionResult(
                    success=False,
                    timed_out=True,
                    error_message="Execution timed out after 1 seconds.",
                )

        router = ToolRouter(bridge=TimeoutMockBridge(), workspace_root=str(tmp_path), logger_instance=AuditLogger())

        req = ToolRequest(
            tool="file_read",
            workspace_dir=str(workspace),
            arguments={"path": "."},
            timeout_seconds=1,
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "EXECUTION_FAILED"
        assert "timed out" in res.error

    async def test_hermes_bridge_failure_handling(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        class FailingBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                return HermesExecutionResult(
                    success=False,
                    exit_code=1,
                    stderr="Hermes internal error",
                    error_message="Process exited with non-zero status code: 1.",
                )

        router = ToolRouter(bridge=FailingBridge(), workspace_root=str(tmp_path), logger_instance=AuditLogger())

        req = ToolRequest(
            tool="file_read",
            workspace_dir=str(workspace),
            arguments={"path": "."},
        )
        res = await router.execute_tool(req)

        assert res.success is False
        assert res.security_decision == "EXECUTION_FAILED"
        assert "Process exited with non-zero status code: 1." in res.error

    async def test_no_arbitrary_cli_injection(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        captured_request = None

        class InspectingBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                nonlocal captured_request
                captured_request = request
                return HermesExecutionResult(success=True, stdout="OK", exit_code=0)

        router = ToolRouter(bridge=InspectingBridge(), workspace_root=str(tmp_path), logger_instance=AuditLogger())

        # Attempting to inject raw CLI flags inside arguments dict
        req = ToolRequest(
            tool="file_list",
            workspace_dir=str(workspace),
            arguments={
                "path": ".",
                "extra_args": ["--yolo", "rm -rf /"],
                "cli_flag": "--yolo",
            },
        )
        res = await router.execute_tool(req)

        assert res.success is True
        assert captured_request is not None
        # Verify that safe mode is enforced and toolsets are restricted to ['file']
        assert captured_request.safe_mode is True
        assert captured_request.toolsets == ["file"]
        # Verify that prompt is constructed safely without raw CLI flag injection
        assert "--yolo" not in captured_request.prompt
        assert "rm -rf" not in captured_request.prompt

    async def test_agent_orchestrator_tool_router_integration(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "test.c").write_text("int main() { return 0; }", encoding="utf-8")

        class FastSuccessBridge(HermesBridge):
            async def execute(self, request: HermesExecutionRequest) -> HermesExecutionResult:
                return HermesExecutionResult(
                    success=True,
                    stdout="test.c",
                    exit_code=0,
                    usage=HermesUsageReport(completed=True, total_tokens=10),
                )

        test_logger = AuditLogger()
        router = ToolRouter(bridge=FastSuccessBridge(), workspace_root=str(tmp_path), logger_instance=test_logger)
        orchestrator = AgentOrchestrator(tool_router=router)

        req = ToolRequest(
            tool="file_list",
            workspace_dir=str(workspace),
            arguments={"path": "."},
            request_source="AgentOrchestratorTest",
        )
        res = await orchestrator.execute_tool(req)

        assert res.success is True
        assert res.security_decision == "ALLOW"
        assert "test.c" in str(res.output)

        records = test_logger.get_records()
        assert len(records) == 1
        assert records[0].request_source == "AgentOrchestratorTest"

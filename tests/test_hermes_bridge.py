"""Unit and integration tests for Phase 1 Hermes Integration (HermesBridge and WorkspacePolicy)."""

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path
import pytest

from backend.config import settings
from backend.security.workspace_policy import WorkspacePolicy, WorkspacePolicyError
from backend.hermes_models import HermesExecutionRequest, HermesExecutionResult, HermesUsageReport
from backend.hermes_bridge import HermesBridge, HermesBridgeError


class TestWorkspacePolicy:
    """Test suite for WorkspacePolicy path resolution and containment checking."""

    def test_workspace_containment_valid_paths(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        sub_file = workspace / "sub" / "file.txt"
        sub_file.parent.mkdir()
        sub_file.touch()

        policy = WorkspacePolicy(workspace)

        resolved = policy.resolve_and_validate(sub_file)
        assert resolved == sub_file.resolve()
        assert policy.is_contained(sub_file) is True

    def test_workspace_containment_rejection_outside(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.touch()

        policy = WorkspacePolicy(workspace)

        assert policy.is_contained(outside_file) is False
        with pytest.raises(WorkspacePolicyError) as exc_info:
            policy.resolve_and_validate(outside_file)
        assert "escapes workspace root" in str(exc_info.value)

    def test_workspace_containment_traversal_rejection(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        traversal_path = workspace / ".." / "outside.txt"

        policy = WorkspacePolicy(workspace)

        assert policy.is_contained(traversal_path) is False
        with pytest.raises(WorkspacePolicyError):
            policy.resolve_and_validate(traversal_path)

    def test_empty_path_rejection(self, tmp_path):
        policy = WorkspacePolicy(tmp_path)
        with pytest.raises(WorkspacePolicyError):
            policy.resolve_and_validate("")


@pytest.mark.anyio
class TestHermesBridge:
    """Test suite for HermesBridge subprocess execution, timeouts, cancellation, and metrics."""

    async def test_hermes_executable_detection(self):
        bridge = HermesBridge(hermes_path=settings.HERMES_PATH)
        assert bridge.is_available() is True

    async def test_hermes_version_check(self):
        bridge = HermesBridge(hermes_path=settings.HERMES_PATH)
        version_str = await bridge.check_version()
        assert "Hermes Agent" in version_str or "v0." in version_str

    async def test_successful_safe_invocation(self, tmp_path):
        bridge = HermesBridge(
            hermes_path=settings.HERMES_PATH,
            workspace_root=str(tmp_path),
            usage_dir=str(tmp_path / "usage"),
        )
        req = HermesExecutionRequest(
            prompt="reply with exactly HERMES_SAFE_OK",
            workspace_dir=str(tmp_path),
            toolsets=["file"],
            safe_mode=True,
        )
        res = await bridge.execute(req)
        assert res.success is True
        assert res.exit_code == 0
        assert "HERMES_SAFE_OK" in res.stdout
        assert res.timed_out is False
        assert res.cancelled is False

    async def test_stdout_stderr_exit_code_capture(self, tmp_path):
        bridge = HermesBridge(
            hermes_path=settings.HERMES_PATH,
            workspace_root=str(tmp_path),
            usage_dir=str(tmp_path / "usage"),
        )
        req = HermesExecutionRequest(
            prompt="reply with exactly TEST_STDOUT_CAPTURE",
            workspace_dir=str(tmp_path),
        )
        res = await bridge.execute(req)
        assert res.success is True
        assert res.stdout is not None and len(res.stdout) > 0
        assert res.exit_code == 0

    async def test_model_override(self, tmp_path):
        bridge = HermesBridge(
            hermes_path=settings.HERMES_PATH,
            workspace_root=str(tmp_path),
            usage_dir=str(tmp_path / "usage"),
        )
        req = HermesExecutionRequest(
            prompt="reply OK",
            workspace_dir=str(tmp_path),
            model="huihui_ai/qwen2.5-vl-abliterated:7b",
        )
        res = await bridge.execute(req)
        assert res.success is True
        assert "-m" in res.command_executed
        assert "huihui_ai/qwen2.5-vl-abliterated:7b" in res.command_executed

    async def test_workspace_containment_validation(self, tmp_path):
        workspace = tmp_path / "valid_workspace"
        workspace.mkdir()
        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()

        bridge = HermesBridge(
            hermes_path=settings.HERMES_PATH,
            workspace_root=str(workspace),
            usage_dir=str(tmp_path / "usage"),
        )
        req = HermesExecutionRequest(
            prompt="reply OK",
            workspace_dir=str(outside_dir),
        )
        res = await bridge.execute(req)
        assert res.success is False
        assert "Workspace containment violation" in res.error_message

    async def test_usage_file_parsing(self, tmp_path):
        usage_dir = tmp_path / "usage"
        usage_dir.mkdir()
        bridge = HermesBridge(
            hermes_path=settings.HERMES_PATH,
            workspace_root=str(tmp_path),
            usage_dir=str(usage_dir),
        )
        req = HermesExecutionRequest(
            prompt="reply PARSE_USAGE_TEST",
            workspace_dir=str(tmp_path),
        )
        res = await bridge.execute(req)
        assert res.success is True
        assert res.usage is not None
        assert isinstance(res.usage, HermesUsageReport)
        assert res.usage.completed is True
        assert res.usage.total_tokens > 0

    async def test_timeout_handling(self, tmp_path):
        # Test timeout using python executable simulating a long sleep
        python_executable = sys.executable
        bridge = HermesBridge(
            hermes_path=python_executable,
            workspace_root=str(tmp_path),
            usage_dir=str(tmp_path / "usage"),
        )
        # Mocking python command to sleep for 5 seconds with -c
        req = HermesExecutionRequest(
            prompt="import time; time.sleep(5)",
            workspace_dir=str(tmp_path),
            timeout_seconds=1,
            extra_args=[],
        )
        # Override _build_command for mock timeout test
        bridge._build_command = lambda r, w, u: [python_executable, "-c", r.prompt]
        res = await bridge.execute(req)
        assert res.success is False
        assert res.timed_out is True
        assert "timed out" in res.error_message

    async def test_cancellation_handling(self, tmp_path):
        python_executable = sys.executable
        bridge = HermesBridge(
            hermes_path=python_executable,
            workspace_root=str(tmp_path),
            usage_dir=str(tmp_path / "usage"),
        )
        req = HermesExecutionRequest(
            prompt="import time; time.sleep(5)",
            workspace_dir=str(tmp_path),
            timeout_seconds=10,
        )
        bridge._build_command = lambda r, w, u: [python_executable, "-c", r.prompt]

        cancel_event = asyncio.Event()

        async def trigger_cancel():
            await asyncio.sleep(0.5)
            cancel_event.set()

        asyncio.create_task(trigger_cancel())
        res = await bridge.execute(req, cancel_event=cancel_event)

        assert res.success is False
        assert res.cancelled is True
        assert "cancelled" in res.error_message

    async def test_windows_process_cleanup(self, tmp_path):
        python_executable = sys.executable
        bridge = HermesBridge(
            hermes_path=python_executable,
            workspace_root=str(tmp_path),
            usage_dir=str(tmp_path / "usage"),
        )
        req = HermesExecutionRequest(
            prompt="import time; time.sleep(5)",
            workspace_dir=str(tmp_path),
            timeout_seconds=1,
        )
        bridge._build_command = lambda r, w, u: [python_executable, "-c", r.prompt]

        start_time = time.time()
        res = await bridge.execute(req)
        elapsed = time.time() - start_time

        assert res.timed_out is True
        assert elapsed < 3.0

"""Asynchronous Hermes CLI bridge for process execution, lifecycle management, and output capture."""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional, List

from backend.config import settings
from backend.hermes_models import (
    HermesExecutionRequest,
    HermesExecutionResult,
    HermesUsageReport,
)
from backend.security.workspace_policy import WorkspacePolicy, WorkspacePolicyError

logger = logging.getLogger(__name__)


class HermesBridgeError(Exception):
    """Base exception for Hermes bridge errors."""
    pass


class HermesBridge:
    """Asynchronous bridge wrapper around the Hermes CLI subprocess execution."""

    def __init__(
        self,
        hermes_path: Optional[str] = None,
        workspace_root: Optional[str] = None,
        usage_dir: Optional[str] = None,
    ):
        raw_path = hermes_path or settings.HERMES_PATH
        self.hermes_path = shutil.which(raw_path) or raw_path
        self.workspace_root = workspace_root or settings.HERMES_WORKSPACE_ROOT
        self.usage_dir = usage_dir or settings.HERMES_USAGE_DIR
        self.workspace_policy = WorkspacePolicy(self.workspace_root)

        # Ensure usage directory exists
        try:
            os.makedirs(self.usage_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create usage directory '{self.usage_dir}': {e}")

    def is_available(self) -> bool:
        """Checks if the Hermes executable is accessible on the host system."""
        if os.path.isabs(self.hermes_path) or os.path.exists(self.hermes_path):
            return os.access(self.hermes_path, os.X_OK) or os.path.isfile(self.hermes_path)
        return shutil.which(self.hermes_path) is not None

    def _get_base_cmd(self) -> List[str]:
        """Returns base command list for Hermes (using python -m hermes_cli.main when available to avoid Windows AppLocker restriction WinError 4551)."""
        if os.path.exists(self.hermes_path):
            parent = Path(self.hermes_path).parent
            python_exe = parent / "python.exe"
            if python_exe.exists() and "hermes-agent" in str(parent).lower():
                return [str(python_exe), "-m", "hermes_cli.main"]
        return [self.hermes_path]

    async def check_version(self) -> str:
        """Executes `hermes --version` and returns the output string."""
        if not self.is_available():
            raise HermesBridgeError(f"Hermes executable '{self.hermes_path}' not found on system PATH.")

        cmd = self._get_base_cmd() + ["--version"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if proc.returncode == 0:
                return stdout.decode("utf-8", errors="replace").strip()
            else:
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                raise HermesBridgeError(f"Hermes version check failed (exit code {proc.returncode}): {err_msg}")
        except asyncio.TimeoutError:
            raise HermesBridgeError("Hermes version check timed out.")
        except Exception as e:
            raise HermesBridgeError(f"Hermes version check error: {e}")

    def _build_command(
        self,
        request: HermesExecutionRequest,
        validated_workspace: Path,
        usage_file_path: Path,
    ) -> List[str]:
        """Constructs the exact CLI argument list for the Hermes subprocess command."""
        model = request.model or settings.HERMES_DEFAULT_MODEL
        toolsets = request.toolsets if request.toolsets is not None else settings.HERMES_DEFAULT_TOOLSETS
        safe_mode = request.safe_mode if request.safe_mode is not None else settings.HERMES_SAFE_MODE

        cmd = self._get_base_cmd() + [
            "-z", request.prompt,
            "--in", str(validated_workspace),
            "-m", model,
            "--usage-file", str(usage_file_path),
        ]

        if safe_mode:
            cmd.append("--safe-mode")

        if toolsets:
            cmd.extend(["-t", ",".join(toolsets)])

        if request.extra_args:
            cmd.extend(request.extra_args)

        return cmd

    def _parse_usage_file(self, usage_file_path: Path) -> Optional[HermesUsageReport]:
        """Reads and parses the usage report JSON written by Hermes."""
        if not usage_file_path.exists():
            return None

        try:
            with open(usage_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return HermesUsageReport(
                estimated_cost_usd=float(data.get("estimated_cost_usd", 0.0)),
                cost_status=data.get("cost_status"),
                cost_source=data.get("cost_source"),
                input_tokens=int(data.get("input_tokens", 0)),
                output_tokens=int(data.get("output_tokens", 0)),
                cache_read_tokens=int(data.get("cache_read_tokens", 0)),
                cache_write_tokens=int(data.get("cache_write_tokens", 0)),
                reasoning_tokens=int(data.get("reasoning_tokens", 0)),
                total_tokens=int(data.get("total_tokens", 0)),
                api_calls=int(data.get("api_calls", 0)),
                model=data.get("model"),
                provider=data.get("provider"),
                session_id=data.get("session_id"),
                completed=bool(data.get("completed", False)),
                failed=bool(data.get("failed", False)),
                service_tier=data.get("service_tier"),
                raw_data=data,
            )
        except Exception as e:
            logger.error(f"Failed to parse Hermes usage file '{usage_file_path}': {e}")
            return None

    async def execute(
        self,
        request: HermesExecutionRequest,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> HermesExecutionResult:
        """Asynchronously executes Hermes subprocess within policy boundaries with process cleanup."""
        # 1. Validate executable existence
        if not self.is_available():
            return HermesExecutionResult(
                success=False,
                error_message=f"Hermes executable '{self.hermes_path}' not found.",
            )

        # 2. Validate workspace directory containment
        try:
            validated_workspace = self.workspace_policy.resolve_and_validate(request.workspace_dir)
        except WorkspacePolicyError as e:
            return HermesExecutionResult(
                success=False,
                error_message=f"Workspace containment violation: {e}",
            )

        # 3. Determine timeout limits
        timeout = request.timeout_seconds or settings.HERMES_DEFAULT_TIMEOUT_SECONDS
        if timeout > settings.HERMES_MAX_TIMEOUT_SECONDS:
            timeout = settings.HERMES_MAX_TIMEOUT_SECONDS

        # 4. Prepare unique usage file path
        usage_file_path = Path(self.usage_dir) / f"hermes_usage_{uuid.uuid4().hex}.json"

        # 5. Build command line
        cmd = self._build_command(request, validated_workspace, usage_file_path)

        # 6. Configure Windows process creation flags for process tree containment
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = None
        timed_out = False
        cancelled = False
        stdout_bytes = b""
        stderr_bytes = b""
        exit_code = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=creationflags,
            )

            async def wait_process():
                nonlocal stdout_bytes, stderr_bytes
                stdout_bytes, stderr_bytes = await proc.communicate()

            tasks = [asyncio.create_task(wait_process())]
            
            if cancel_event:
                async def wait_cancel():
                    await cancel_event.wait()

                tasks.append(asyncio.create_task(wait_cancel()))

            done, pending = await asyncio.wait(
                tasks,
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel remaining pending tasks
            for t in pending:
                t.cancel()

            if not done:
                # Timeout occurred
                timed_out = True
                await self._terminate_process_tree(proc)
            elif cancel_event and cancel_event.is_set():
                # Cancellation requested
                cancelled = True
                await self._terminate_process_tree(proc)
            else:
                # Process completed normally
                exit_code = proc.returncode

        except Exception as e:
            logger.error(f"Hermes subprocess execution failed with exception: {e}")
            if proc:
                await self._terminate_process_tree(proc)
            return HermesExecutionResult(
                success=False,
                command_executed=cmd,
                error_message=f"Subprocess execution error: {e}",
            )
        finally:
            # Clean up usage file after reading
            usage_report = self._parse_usage_file(usage_file_path)
            if usage_file_path.exists():
                try:
                    usage_file_path.unlink()
                except Exception:
                    pass

        stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()
        success = (exit_code == 0) and not timed_out and not cancelled

        error_msg = None
        if timed_out:
            error_msg = f"Execution timed out after {timeout} seconds."
        elif cancelled:
            error_msg = "Execution was cancelled."
        elif exit_code != 0:
            error_msg = f"Process exited with non-zero status code: {exit_code}."

        return HermesExecutionResult(
            success=success,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            timed_out=timed_out,
            cancelled=cancelled,
            usage=usage_report,
            command_executed=cmd,
            error_message=error_msg,
        )

    async def _terminate_process_tree(self, proc: asyncio.subprocess.Process):
        """Cleanly terminates the subprocess and all child processes (Windows & Unix safe)."""
        if proc.returncode is not None:
            return

        pid = proc.pid
        try:
            if os.name == "nt":
                # Use taskkill /F /T /PID on Windows to terminate process group/tree
                kill_proc = await asyncio.create_subprocess_exec(
                    "taskkill", "/F", "/T", "/PID", str(pid),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await kill_proc.wait()
            else:
                proc.kill()
            await proc.wait()
        except Exception as e:
            logger.warning(f"Failed to terminate process {pid}: {e}")

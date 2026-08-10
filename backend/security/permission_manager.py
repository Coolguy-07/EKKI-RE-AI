"""PermissionManager for user-controlled execution permissions and approval workflows."""

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Safe read-only operations allowed in all execution modes
SAFE_TOOLS: Set[str] = {"file_list", "file_read", "file_metadata"}


class ExecutionMode(str, Enum):
    SAFE = "SAFE"
    ASK = "ASK"
    FULL = "FULL"


class PermissionDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK = "ASK"


class ApprovalScope(str, Enum):
    ONCE = "once"
    SESSION = "session"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ApprovalRequest(BaseModel):
    """Structured approval request payload for commands requiring user confirmation."""

    request_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the approval request.",
    )
    tool: str = Field(..., description="The requested tool name.")
    command: Optional[str] = Field(None, description="Command string to execute.")
    workspace_dir: str = Field(..., description="Target workspace directory.")
    cwd: Optional[str] = Field(None, description="Working directory relative to workspace.")
    reason: Optional[str] = Field(None, description="Reason or request source description.")
    request_source: Optional[str] = Field("AgentOrchestrator", description="Requesting agent or component.")
    status: ApprovalStatus = Field(ApprovalStatus.PENDING, description="Current approval status.")
    approval_scope: Optional[ApprovalScope] = Field(None, description="Scope granted upon approval.")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of the approval request creation.",
    )
    expected_timeout_seconds: Optional[int] = Field(120, description="Expected execution timeout.")


class PermissionManager:
    """Thread-safe permission manager controlling execution modes and user approval flows."""

    def __init__(self, mode: ExecutionMode = ExecutionMode.SAFE):
        self._mode: ExecutionMode = mode
        # Pending approval requests keyed by request_id
        self._pending_requests: Dict[str, ApprovalRequest] = {}
        # Session permissions: session_id -> Set[tool_name]
        self._session_permissions: Dict[str, Set[str]] = {}

    def get_mode(self) -> ExecutionMode:
        """Returns the active execution mode."""
        return self._mode

    def set_mode(self, mode: ExecutionMode, caller_source: str = "user") -> ExecutionMode:
        """Sets the execution mode. Only user/API actions may invoke this method."""
        if caller_source not in ("user", "api", "system_admin"):
            raise ValueError(f"Unauthorized caller '{caller_source}' cannot change execution mode.")
        logger.info(f"[PERMISSION] Execution mode changed from {self._mode} to {mode} by {caller_source}")
        self._mode = mode
        return self._mode

    def evaluate_permission(
        self,
        tool: str,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> PermissionDecision:
        """Evaluates whether a tool execution request should be ALLOWED, DENIED, or ASKED."""
        tool_clean = tool.strip()

        # 1. Safe read tools are always ALLOWED in all modes
        if tool_clean in SAFE_TOOLS:
            return PermissionDecision.ALLOW

        # 2. Check active execution mode
        if self._mode == ExecutionMode.SAFE:
            return PermissionDecision.DENY

        if self._mode == ExecutionMode.FULL:
            return PermissionDecision.ALLOW

        if self._mode == ExecutionMode.ASK:
            # Check session permission
            sess_id = session_id or "default"
            if tool_clean in self._session_permissions.get(sess_id, set()):
                return PermissionDecision.ALLOW

            # Check if specific request_id was APPROVED for once
            if request_id and request_id in self._pending_requests:
                req = self._pending_requests[request_id]
                if req.status == ApprovalStatus.APPROVED and req.approval_scope == ApprovalScope.ONCE:
                    del self._pending_requests[request_id]
                    return PermissionDecision.ALLOW

            # Check if any request for this tool was APPROVED for once
            for rid, req in list(self._pending_requests.items()):
                if req.tool == tool_clean and req.status == ApprovalStatus.APPROVED and req.approval_scope == ApprovalScope.ONCE:
                    del self._pending_requests[rid]
                    return PermissionDecision.ALLOW

            return PermissionDecision.ASK

        return PermissionDecision.DENY

    def create_approval_request(
        self,
        tool: str,
        command: Optional[str],
        workspace_dir: str,
        cwd: Optional[str] = None,
        reason: Optional[str] = None,
        request_source: Optional[str] = "AgentOrchestrator",
        timeout_seconds: Optional[int] = 120,
    ) -> ApprovalRequest:
        """Creates and tracks a new pending approval request."""
        req = ApprovalRequest(
            tool=tool,
            command=command,
            workspace_dir=workspace_dir,
            cwd=cwd,
            reason=reason or f"Requesting tool execution '{tool}'",
            request_source=request_source,
            expected_timeout_seconds=timeout_seconds,
        )
        self._pending_requests[req.request_id] = req
        logger.info(f"[PERMISSION] Created approval request {req.request_id} for tool '{tool}'")
        return req

    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Lists all pending approval requests."""
        return [r for r in self._pending_requests.values() if r.status == ApprovalStatus.PENDING]

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Retrieves an approval request by ID."""
        return self._pending_requests.get(request_id)

    def submit_decision(
        self,
        request_id: str,
        action: str,  # "approve" or "deny"
        scope: Optional[ApprovalScope] = ApprovalScope.ONCE,
        session_id: Optional[str] = "default",
        caller_source: str = "user",
    ) -> ApprovalRequest:
        """Submits a user approval decision for a pending request."""
        if caller_source not in ("user", "api", "system_admin"):
            raise ValueError(f"Unauthorized caller '{caller_source}' cannot submit approval decisions.")

        req = self._pending_requests.get(request_id)
        if not req:
            raise ValueError(f"Approval request ID '{request_id}' not found.")

        action_clean = action.lower().strip()
        sess_id = session_id or "default"

        if action_clean == "approve":
            req.status = ApprovalStatus.APPROVED
            req.approval_scope = scope or ApprovalScope.ONCE
            if scope == ApprovalScope.SESSION:
                if sess_id not in self._session_permissions:
                    self._session_permissions[sess_id] = set()
                self._session_permissions[sess_id].add(req.tool)
                logger.info(f"[PERMISSION] Granted session permission for tool '{req.tool}' on session '{sess_id}'")
        elif action_clean == "deny":
            req.status = ApprovalStatus.DENIED
            req.approval_scope = None
        else:
            raise ValueError(f"Invalid approval action '{action}'. Must be 'approve' or 'deny'.")

        logger.info(f"[PERMISSION] Submitted decision for request {request_id}: {req.status} ({req.approval_scope})")
        return req

    def clear_session_permissions(self, session_id: Optional[str] = None) -> None:
        """Clears session permissions for a session, or all sessions if None."""
        if session_id:
            self._session_permissions.pop(session_id, None)
        else:
            self._session_permissions.clear()

    def clear_all(self) -> None:
        """Resets all pending requests and session permissions."""
        self._pending_requests.clear()
        self._session_permissions.clear()


# Default global permission manager instance
permission_manager = PermissionManager()

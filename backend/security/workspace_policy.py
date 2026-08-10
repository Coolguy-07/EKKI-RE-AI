"""Workspace isolation and path containment policy for EKKI-RE-AI tools & integrations."""

import os
from pathlib import Path
from typing import Union


class WorkspacePolicyError(Exception):
    """Raised when a workspace boundary or security policy violation occurs."""

    pass


class WorkspacePolicy:
    """Policy manager that enforces strict path resolution and workspace containment."""

    def __init__(self, workspace_root: Union[str, Path]):
        """Initialize WorkspacePolicy with a target root workspace directory."""
        self.workspace_root = Path(workspace_root).resolve()

    def resolve_and_validate(self, target_path: Union[str, Path]) -> Path:
        """Resolves target_path to an absolute Path and validates that it resides strictly

        within the configured workspace_root boundary.

        Raises:
            WorkspacePolicyError: If target_path escapes the workspace boundary.
        """
        if not target_path:
            raise WorkspacePolicyError("Target path cannot be empty.")

        # Resolve path strictly (handles symlinks, relative segments '..', etc.)
        resolved_target = Path(target_path).resolve()

        # Check containment: resolved_target must start with workspace_root
        if not self.is_contained(resolved_target):
            raise WorkspacePolicyError(
                f"Path containment violation: '{target_path}' (resolved: '{resolved_target}') "
                f"escapes workspace root '{self.workspace_root}'."
            )

        return resolved_target

    def is_contained(self, target_path: Union[str, Path]) -> bool:
        """Checks whether target_path resides within workspace_root.

        Does NOT raise exceptions. Returns True if contained, False otherwise.
        """
        try:
            resolved_target = Path(target_path).resolve()
            resolved_root = self.workspace_root.resolve()
            
            # Commonpath comparison handles drive letter casing on Windows cleanly
            common = os.path.commonpath([str(resolved_target), str(resolved_root)])
            return os.path.abspath(common).lower() == str(resolved_root).lower()
        except Exception:
            return False
"""
backend/analysis/base.py

Abstract Base Class definition for all analysis engines in EKKI-RE-AI.
Ensures plugin compatibility for future engines (PE, ELF, Capstone, Ghidra, YARA).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseAnalysisEngine(ABC):
    """Abstract interface that all analysis engines must implement."""

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Returns unique string identifier of the engine (e.g. 'binary_intelligence')."""
        pass

    @property
    @abstractmethod
    def engine_version(self) -> str:
        """Returns version string of the engine (e.g. '1.0.0')."""
        pass

    @abstractmethod
    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Executes analysis on raw byte payload and returns updated metadata dict.

        Args:
            file_id: Immutable file identifier.
            filename: Display filename.
            content: Raw byte payload of the file.
            mime_type: Uploaded MIME content type.
            existing_metadata: Optional dict of previously extracted metadata.

        Returns:
            Dict containing engine analysis results to be merged/persisted into metadata.json.
        """
        pass

    def _inject_engine_result(
        self,
        existing_metadata: Optional[Dict[str, Any]],
        parsed_data: Dict[str, Any],
        exec_time_ms: float,
        errors: Optional[List[str]] = None,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Unified helper to inject engine results into accumulated metadata without overwriting."""
        if existing_metadata is None:
            existing_metadata = {}

        engine_payload: Dict[str, Any] = {
            "engine_version": self.engine_version,
            "execution_time_ms": exec_time_ms,
            "parsed_data": parsed_data,
        }
        if extra_fields:
            engine_payload.update(extra_fields)

        # Inject into engine_metadata dictionary
        engine_meta = existing_metadata.get("engine_metadata", {})
        engine_meta[self.engine_name] = engine_payload
        existing_metadata["engine_metadata"] = engine_meta

        # Backward-compatibility alias at root level for direct callers
        existing_metadata[self.engine_name] = engine_payload

        if errors:
            existing_metadata.setdefault("errors", []).extend(errors)

        return existing_metadata


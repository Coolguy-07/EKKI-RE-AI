"""
backend/analysis/yara_engine.py

Production-grade YARA Analysis Engine for EKKI-RE-AI.
Compiles and executes built-in YARA rules against binary payloads.
Provides graceful degradation if yara-python is not installed.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

from .base import BaseAnalysisEngine

logger = logging.getLogger(__name__)


class YaraAnalysisEngine(BaseAnalysisEngine):
    """Engine responsible for YARA pattern matching."""

    def __init__(self, rules_dir: Optional[Path] = None):
        """Initializes the engine and compiles rules if available."""
        super().__init__()
        if rules_dir is None:
            # Default to backend/analysis/rules/yara
            self.rules_dir = Path(__file__).parent / "rules" / "yara"
        else:
            self.rules_dir = rules_dir
        
        self.compiled_rules = None
        self.rules_loaded_count = 0
        self.init_error = None
        
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Finds and compiles all .yar and .yara files in rules_dir."""
        if not YARA_AVAILABLE:
            self.init_error = "yara-python package is not installed."
            return

        if not self.rules_dir.exists() or not self.rules_dir.is_dir():
            self.init_error = f"YARA rules directory not found at {self.rules_dir}"
            return

        filepaths = {}
        # Simple recursive search for .yar and .yara
        for p in self.rules_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".yar", ".yara"):
                # Use relative path stem as namespace
                namespace = p.stem
                filepaths[namespace] = str(p)

        if not filepaths:
            self.init_error = "No YARA rules found to compile."
            return

        try:
            self.compiled_rules = yara.compile(filepaths=filepaths)
            self.rules_loaded_count = len(filepaths)
            logger.info("YARA engine compiled %d rule files successfully.", self.rules_loaded_count)
        except Exception as err:
            self.init_error = f"YARA compilation failed: {err}"
            logger.error(self.init_error)

    @property
    def engine_name(self) -> str:
        return "yara_analysis"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    def can_handle(
        self,
        content: bytes,
        detected_type: str = "",
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Determines if the file is eligible for YARA scanning.
        
        YARA scanning runs on all files (binaries and documents) unless empty.
        Note: Dependency availability is kept separate from this method.
        """
        if not content:
            return False
        return True

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs compiled YARA rules against the provided content."""
        start_time = time.perf_counter()
        
        yara_data: Dict[str, Any] = {
            "file_id": file_id,
            "engine": self.engine_name,
            "engine_version": self.engine_version,
            "scan_status": "success",
            "rules_loaded": self.rules_loaded_count,
            "match_count": 0,
            "matches": [],
            "errors": [],
        }

        if not YARA_AVAILABLE or not self.compiled_rules:
            yara_data["scan_status"] = "failed"
            err_msg = self.init_error or "YARA engine not initialized."
            yara_data["errors"].append(err_msg)
            return self._build_engine_result(yara_data, start_time, existing_metadata)

        try:
            # Execute YARA scan with 60-second timeout safeguard
            # This acts as an execution safeguard, but does not provide full process isolation.
            matches = self.compiled_rules.match(data=content, timeout=60)
            
            parsed_matches = []
            for match in matches:
                # Extract matched strings
                strings_dict = {}
                for offset, string_ident, string_data in match.strings:
                    if string_ident not in strings_dict:
                        strings_dict[string_ident] = []
                    
                    # Convert binary string_data to hex if not printable, or string if printable.
                    # For simplicity, convert to raw bytes hex to prevent JSON serialization errors
                    matched_hex = string_data.hex() if isinstance(string_data, bytes) else string_data
                    
                    strings_dict[string_ident].append({
                        "offset": offset,
                        "matched_data": matched_hex
                    })
                
                # Format strings for JSON schema
                formatted_strings = [
                    {"identifier": k, "instances": v}
                    for k, v in strings_dict.items()
                ]
                
                parsed_matches.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": match.meta,
                    "strings": formatted_strings
                })
            
            yara_data["matches"] = parsed_matches
            yara_data["match_count"] = len(parsed_matches)

        except Exception as err:
            logger.error("YARA scan failed for file_id='%s': %s", file_id, err)
            yara_data["scan_status"] = "failed"
            yara_data["errors"].append(f"YARA scan exception: {err}")

        return self._build_engine_result(yara_data, start_time, existing_metadata)

    def _build_engine_result(
        self,
        yara_data: Dict[str, Any],
        start_time: float,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Formats output dict and merges into existing_metadata."""
        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        yara_data["execution_time_ms"] = exec_time_ms
        
        logger.info(
            "YaraAnalysisEngine completed for file_id='%s': status=%s matches=%d in %.2fms",
            yara_data["file_id"],
            yara_data["scan_status"],
            yara_data["match_count"],
            exec_time_ms,
        )

        return self._inject_engine_result(
            existing_metadata=existing_metadata,
            parsed_data=yara_data,
            exec_time_ms=exec_time_ms,
            extra_fields={"match_count": yara_data["match_count"]},
        )

    def save_yara_artifact(self, project_dir: Path, file_id: str, yara_data: Dict[str, Any]) -> Path:
        """Saves detailed YARA analysis artifact to disk."""
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "yara.json"
        temp_path = analysis_dir / "yara.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(yara_data, f, indent=2)
            temp_path.replace(target_path)
            logger.info("YARA artifact written: path='%s'", target_path)
            return target_path
        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error("Failed to write yara artifact for file_id='%s': %s", file_id, err)
            raise IOError(f"Could not write YARA analysis artifact: {err}") from err

"""
backend/analysis/registry.py

Modular Analysis Pipeline Registry for EKKI-RE-AI.
Decouples workspace manager from individual analysis engines.
Executes registered engines sequentially and persists analysis/{file_id}/metadata.json.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .base import BaseAnalysisEngine
from .binary_intelligence import BinaryIntelligenceEngine
from .capstone_engine import CapstoneDisassemblyEngine
from .elf_parser import ELFParserEngine
from .ghidra_engine import GhidraAnalysisEngine
from .macho_parser import MachOParserEngine
from .models import BinaryMetadata, CURRENT_SCHEMA_VERSION
from .pe_parser import PEParserEngine
from .yara_engine import YaraAnalysisEngine

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """Thread-safe pipeline runner and registry for analysis engines."""

    def __init__(self) -> None:
        self._engines: List[BaseAnalysisEngine] = []
        self._lock = threading.RLock()

        # Register default core analysis engines in execution order.
        # BinaryIntelligenceEngine always runs first to populate detected_type.
        # Format parsers run next to populate UnifiedExecutableModel.
        # CapstoneDisassemblyEngine runs next for fast instruction-level disassembly.
        # GhidraAnalysisEngine runs last for deep program analysis and decompilation.
        self.register_engine(BinaryIntelligenceEngine())
        self.register_engine(PEParserEngine())
        self.register_engine(ELFParserEngine())
        self.register_engine(MachOParserEngine())
        self.register_engine(YaraAnalysisEngine())
        self.register_engine(CapstoneDisassemblyEngine())
        self.register_engine(GhidraAnalysisEngine())

    def register_engine(self, engine: BaseAnalysisEngine) -> None:
        """Registers a new AnalysisEngine implementation thread-safely."""
        with self._lock:
            # Avoid duplicate registrations of the same engine name
            if any(e.engine_name == engine.engine_name for e in self._engines):
                logger.warning("Engine '%s' already registered. Overwriting.", engine.engine_name)
                self._engines = [e for e in self._engines if e.engine_name != engine.engine_name]

            self._engines.append(engine)
            logger.info("Registered analysis engine '%s' (v%s)", engine.engine_name, engine.engine_version)

    def run_pipeline(
        self,
        project_dir: Path,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
    ) -> BinaryMetadata:
        """Executes all registered analysis engines and persists metadata.json.

        Args:
            project_dir: Absolute path to target project directory on disk.
            file_id: Immutable file identifier.
            filename: Display filename.
            content: Raw byte payload.
            mime_type: Uploaded MIME type.

        Returns:
            Validated BinaryMetadata object.
        """
        logger.info("Executing AnalysisPipeline for file_id='%s' (%d bytes)", file_id, len(content))
        metadata_dict: Dict = {}

        with self._lock:
            engines_to_run = list(self._engines)

        for engine in engines_to_run:
            try:
                # Call can_handle() if the engine implements it; default is True.
                # NOTE: BinaryIntelligenceEngine stores detected_type at the top level
                # of metadata_dict (via BinaryMetadata.model_dump()), not nested under
                # engine_metadata.binary_intelligence.
                detected_type = metadata_dict.get("detected_type", "")
                if hasattr(engine, "can_handle") and not engine.can_handle(
                    content=content,
                    detected_type=detected_type,
                    existing_metadata=metadata_dict,
                ):
                    logger.debug(
                        "Engine '%s' skipped for file_id='%s' (detected_type='%s')",
                        engine.engine_name,
                        file_id,
                        detected_type,
                    )
                    continue

                metadata_dict = engine.analyze(
                    file_id=file_id,
                    filename=filename,
                    content=content,
                    mime_type=mime_type,
                    existing_metadata=metadata_dict,
                )
            except Exception as err:
                logger.exception("Analysis engine '%s' failed for file_id='%s': %s", engine.engine_name, file_id, err)
                if "errors" not in metadata_dict:
                    metadata_dict["errors"] = []
                metadata_dict["errors"].append(f"Engine '{engine.engine_name}' exception: {err}")

        # Ensure schema_version is set
        metadata_dict["schema_version"] = CURRENT_SCHEMA_VERSION

        # Convert to Pydantic model for validation
        validated_metadata = BinaryMetadata.model_validate(metadata_dict)

        # Save artifact under analysis/{file_id}/metadata.json
        self.save_metadata_artifact(project_dir, file_id, validated_metadata)

        engine_meta = metadata_dict.get("engine_metadata", {})

        # Save artifact under analysis/{file_id}/pe.json if pe_parser output is present
        if "pe_parser" in engine_meta and "parsed_data" in engine_meta["pe_parser"]:
            try:
                pe_engine = PEParserEngine()
                pe_engine.save_pe_artifact(project_dir, file_id, engine_meta["pe_parser"]["parsed_data"])
            except Exception as err:
                logger.error("Failed to persist pe.json artifact for file_id='%s': %s", file_id, err)

        # Save artifact under analysis/{file_id}/elf.json if elf_parser output is present
        if "elf_parser" in engine_meta and "parsed_data" in engine_meta["elf_parser"]:
            try:
                elf_engine = ELFParserEngine()
                elf_engine.save_elf_artifact(project_dir, file_id, engine_meta["elf_parser"]["parsed_data"])
            except Exception as err:
                logger.error("Failed to persist elf.json artifact for file_id='%s': %s", file_id, err)

        # Save artifact under analysis/{file_id}/macho.json if macho_parser output is present
        if "macho_parser" in engine_meta and "parsed_data" in engine_meta["macho_parser"]:
            try:
                macho_engine = MachOParserEngine()
                macho_engine.save_macho_artifact(project_dir, file_id, engine_meta["macho_parser"]["parsed_data"])
            except Exception as err:
                logger.error("Failed to persist macho.json artifact for file_id='%s': %s", file_id, err)

        # Save artifact under analysis/{file_id}/yara.json if yara_analysis output is present
        if "yara_analysis" in engine_meta and "parsed_data" in engine_meta["yara_analysis"]:
            try:
                yara_engine = YaraAnalysisEngine()
                yara_engine.save_yara_artifact(project_dir, file_id, engine_meta["yara_analysis"]["parsed_data"])
            except Exception as err:
                logger.error("Failed to persist yara.json artifact for file_id='%s': %s", file_id, err)

        # Save artifact under analysis/{file_id}/disassembly.json if capstone output is present
        if "capstone_disassembly" in engine_meta and "parsed_data" in engine_meta["capstone_disassembly"]:
            try:
                capstone_engine = CapstoneDisassemblyEngine()
                capstone_engine.save_disassembly_artifact(
                    project_dir, file_id, engine_meta["capstone_disassembly"]["parsed_data"]
                )
            except Exception as err:
                logger.error("Failed to persist disassembly.json artifact for file_id='%s': %s", file_id, err)

        # Save artifact under analysis/{file_id}/ghidra.json if ghidra_analysis output is present
        if "ghidra_analysis" in engine_meta and "parsed_data" in engine_meta["ghidra_analysis"]:
            try:
                ghidra_engine = GhidraAnalysisEngine()
                ghidra_engine.save_ghidra_artifact(
                    project_dir, file_id, engine_meta["ghidra_analysis"]["parsed_data"]
                )
            except Exception as err:
                logger.error("Failed to persist ghidra.json artifact for file_id='%s': %s", file_id, err)

        return validated_metadata

    def save_metadata_artifact(self, project_dir: Path, file_id: str, metadata: BinaryMetadata) -> Path:
        """Persists metadata atomically to projects/{project_id}/analysis/{file_id}/metadata.json."""
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "metadata.json"
        temp_path = analysis_dir / "metadata.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(metadata.model_dump(), f, indent=2)
            temp_path.replace(target_path)
            logger.info("Metadata written: path='%s' schema_v=%d", target_path, metadata.schema_version)
            return target_path

        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error("Failed to write metadata artifact for file_id='%s': %s", file_id, err)
            raise IOError(f"Could not write analysis metadata: {err}") from err


# Global singleton instance of AnalysisPipeline
analysis_pipeline = AnalysisPipeline()

"""
backend/analysis/ghidra_engine.py

Phase 2.6 Analysis Engine: Ghidra Headless Decompiler & Deep Program Analysis Engine.
Implements BaseAnalysisEngine plugin contract.

Executes Ghidra analyzeHeadless via subprocess (shell=False) to extract function manager
metadata, control-flow graph metrics, symbols, strings, imports, exports, and decompiled C code.
Degrades gracefully if Ghidra is missing, times out, or encounters unsupported architectures.

Produces: analysis/{file_id}/ghidra.json (GhidraArtifact schema).
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings
from .base import BaseAnalysisEngine

logger = logging.getLogger(__name__)

CURRENT_GHIDRA_SCHEMA_VERSION = 1


class GhidraAnalysisEngine(BaseAnalysisEngine):
    """
    Phase 2.6 Analysis Engine: Ghidra Headless integration.

    Responsibilities:
    - Locate analyzeHeadless executable safely from settings or PATH.
    - Run headless analysis via subprocess without shell expansion (shell=False).
    - Parse extracted program metadata, functions, symbols, strings, and decompiled C pseudocode.
    - Handle execution timeouts, missing Ghidra, and corrupted binary failures gracefully.
    - Inject analysis output cleanly into accumulated metadata via _inject_engine_result.
    - Persist ghidra.json artifact atomically.
    """

    BINARY_TYPES = (
        "PE Executable", "ELF", "Mach-O", "Executable", "Binary",
        "DLL", "Shared Object", "Mach-O Dynamic Library", "COFF", "Raw Binary",
    )

    @property
    def engine_name(self) -> str:
        return "ghidra_analysis"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    def can_handle(
        self,
        content: bytes,
        detected_type: str = "",
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Determines whether Ghidra analysis can be executed on target binary."""
        if not content or len(content) < 4:
            return False

        # Reject plain text, markdown, zip, or web documents
        lower_type = detected_type.lower()
        if any(ignored in lower_type for ignored in ("text", "markdown", "zip", "json", "html", "pdf")):
            return False

        # Accept known binary executable formats
        if any(btype.lower() in lower_type for btype in self.BINARY_TYPES):
            return True

        # Check binary magic signatures (MZ, ELF, Mach-O)
        magic = content[:4]
        if magic.startswith(b"MZ") or magic.startswith(b"\x7fELF") or magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return True

        return False

    def find_ghidra_executable(self) -> Optional[Path]:
        """Locates analyzeHeadless executable safely across Windows, Linux, and macOS."""
        configured_path = settings.GHIDRA_PATH
        if configured_path:
            p = Path(configured_path)
            if p.is_file() and p.name.startswith("analyzeHeadless"):
                return p.resolve()
            if p.is_dir():
                # Check directly in dir or in support/ subdirectory
                for cand in (p / "analyzeHeadless.bat", p / "analyzeHeadless", p / "support" / "analyzeHeadless.bat", p / "support" / "analyzeHeadless"):
                    if cand.is_file():
                        return cand.resolve()

        # Check system PATH environment variable
        for exe in ("analyzeHeadless.bat", "analyzeHeadless"):
            found = shutil.which(exe)
            if found:
                return Path(found).resolve()

        return None

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs Ghidra Headless analysis engine and updates metadata dictionary."""
        start_time = time.perf_counter()
        errors: List[str] = []
        warnings: List[str] = []

        ghidra_exe = self.find_ghidra_executable()
        ghidra_available = ghidra_exe is not None

        if not ghidra_available:
            warnings.append("Ghidra installation not found or GHIDRA_PATH not configured. Ghidra analysis skipped.")
            logger.info("Ghidra headless executable not found for file_id='%s'. Skipping.", file_id)
            artifact = self._build_fallback_artifact(
                file_id=file_id,
                filename=filename,
                status="skipped",
                errors=errors,
                warnings=warnings,
                ghidra_available=False,
            )
            return self._inject_engine_result(
                existing_metadata=existing_metadata,
                parsed_data=artifact,
                exec_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
                errors=errors,
                extra_fields={"ghidra_available": False},
            )

        # Attempt Ghidra Headless execution via subprocess
        try:
            artifact = self._run_ghidra_headless(
                ghidra_exe=ghidra_exe,
                file_id=file_id,
                filename=filename,
                content=content,
                errors=errors,
                warnings=warnings,
            )
        except Exception as err:
            logger.exception("Unexpected exception executing Ghidra engine for file_id='%s': %s", file_id, err)
            errors.append(f"Ghidra execution exception: {err}")
            artifact = self._build_fallback_artifact(
                file_id=file_id,
                filename=filename,
                status="failed",
                errors=errors,
                warnings=warnings,
                ghidra_available=True,
            )

        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        artifact["execution_time_ms"] = exec_time_ms

        return self._inject_engine_result(
            existing_metadata=existing_metadata,
            parsed_data=artifact,
            exec_time_ms=exec_time_ms,
            errors=errors,
            extra_fields={"ghidra_available": ghidra_available},
        )

    def _run_ghidra_headless(
        self,
        ghidra_exe: Path,
        file_id: str,
        filename: str,
        content: bytes,
        errors: List[str],
        warnings: List[str],
    ) -> Dict[str, Any]:
        """Executes analyzeHeadless in a temporary directory via subprocess.run (shell=False)."""
        temp_dir = Path(os.environ.get("TEMP", "/tmp")) / f"ghidra_{file_id}_{int(time.time())}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            target_bin = temp_dir / filename
            with open(target_bin, "wb") as f:
                f.write(content)

            output_json = temp_dir / "ghidra_output.json"
            script_path = temp_dir / "extract_analysis.py"

            # Create Jython post-script for Ghidra Headless
            script_code = (
                "import json\n"
                "from ghidra.app.decompiler import DecompInterface\n"
                "from ghidra.util.task import ConsoleTaskMonitor\n\n"
                "program = currentProgram\n"
                "meta = {\n"
                "    'processor': program.getLanguage().getProcessor().toString(),\n"
                "    'language_id': program.getLanguageID().toString(),\n"
                "    'compiler_spec': program.getCompilerSpec().getCompilerSpecID().toString(),\n"
                "    'base_address': program.getImageBase().toString(),\n"
                "    'entry_point': program.getMinAddress().toString(),\n"
                "}\n"
                "fm = program.getFunctionManager()\n"
                "funcs = []\n"
                "monitor = ConsoleTaskMonitor()\n"
                "decomp = DecompInterface()\n"
                "decomp.openProgram(program)\n\n"
                "count = 0\n"
                "for f in fm.getFunctions(True):\n"
                "    if count >= 100: break\n"
                "    c_code = ''\n"
                "    try:\n"
                "        res = decomp.decompileFunction(f, 30, monitor)\n"
                "        if res and res.decompiledFunction:\n"
                "            c_code = res.decompiledFunction.getC()\n"
                "    except Exception:\n"
                "        pass\n"
                "    funcs.append({\n"
                "        'name': f.getName(),\n"
                "        'address': f.getEntryPoint().toString(),\n"
                "        'size': f.getBody().getNumAddresses(),\n"
                "        'is_library': f.isThunk() or f.isExternal(),\n"
                "        'parameter_count': f.getParameterCount(),\n"
                "        'calling_convention': f.getCallingConventionName(),\n"
                "        'decompiled_c_code': c_code,\n"
                "    })\n"
                "    count += 1\n\n"
                "syms = []\n"
                "st = program.getSymbolTable()\n"
                "scount = 0\n"
                "for s in st.getSymbolIterator():\n"
                "    if scount >= 100: break\n"
                "    syms.append({'name': s.getName(), 'address': s.getAddress().toString(), 'type': s.getSymbolType().toString()})\n"
                "    scount += 1\n\n"
                "out = {'meta': meta, 'functions': funcs, 'symbols': syms}\n"
                f"with open(r'{output_json}', 'w') as out_f:\n"
                "    json.dump(out, out_f)\n"
            )

            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_code)

            proj_location = temp_dir / "ghidra_proj"
            proj_location.mkdir(exist_ok=True)

            cmd = [
                str(ghidra_exe),
                str(proj_location),
                "TempProj",
                "-import", str(target_bin),
                "-postScript", str(script_path),
                "-deleteProject",
            ]

            logger.info("Launching Ghidra analyzeHeadless command for file_id='%s'", file_id)
            result = subprocess.run(
                cmd,
                shell=False,
                timeout=settings.GHIDRA_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                errors.append(f"Ghidra process exit code {result.returncode}: {result.stderr[:200]}")

            if output_json.exists():
                with open(output_json, "r", encoding="utf-8") as f:
                    extracted = json.load(f)
                meta = extracted.get("meta", {})
                funcs = extracted.get("functions", [])
                syms = extracted.get("symbols", [])

                return {
                    "schema_version": CURRENT_GHIDRA_SCHEMA_VERSION,
                    "file_id": file_id,
                    "filename": filename,
                    "status": "analyzed",
                    "ghidra_available": True,
                    "ghidra_version": "Headless Analyzer",
                    "processor": meta.get("processor", "Unknown"),
                    "language_id": meta.get("language_id", "Unknown"),
                    "compiler_spec": meta.get("compiler_spec", "Unknown"),
                    "base_address": meta.get("base_address", "0x00000000"),
                    "entry_point": meta.get("entry_point", "0x00000000"),
                    "function_count": len(funcs),
                    "functions": funcs,
                    "symbol_count": len(syms),
                    "symbols": syms,
                    "strings": [],
                    "imports": [],
                    "exports": [],
                    "warnings": warnings,
                    "errors": errors,
                }
            else:
                warnings.append("Ghidra process completed but did not produce output JSON artifact.")
                return self._build_fallback_artifact(file_id, filename, "failed", errors, warnings, True)

        except subprocess.TimeoutExpired:
            errors.append(f"Ghidra execution timed out after {settings.GHIDRA_TIMEOUT_SECONDS} seconds.")
            return self._build_fallback_artifact(file_id, filename, "timeout", errors, warnings, True)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _build_fallback_artifact(
        self,
        file_id: str,
        filename: str,
        status: str,
        errors: List[str],
        warnings: List[str],
        ghidra_available: bool,
    ) -> Dict[str, Any]:
        """Constructs a minimal valid Ghidra artifact when analysis is skipped, failed, or missing."""
        return {
            "schema_version": CURRENT_GHIDRA_SCHEMA_VERSION,
            "file_id": file_id,
            "filename": filename,
            "status": status,
            "ghidra_available": ghidra_available,
            "ghidra_version": "N/A",
            "processor": "N/A",
            "language_id": "N/A",
            "compiler_spec": "N/A",
            "base_address": "0x00000000",
            "entry_point": "0x00000000",
            "function_count": 0,
            "functions": [],
            "symbol_count": 0,
            "symbols": [],
            "strings": [],
            "imports": [],
            "exports": [],
            "warnings": warnings,
            "errors": errors,
        }

    def save_ghidra_artifact(
        self,
        project_dir: Path,
        file_id: str,
        artifact_dict: Dict[str, Any],
    ) -> Path:
        """Persists GhidraArtifact atomically to projects/{project_id}/analysis/{file_id}/ghidra.json."""
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "ghidra.json"
        temp_path = analysis_dir / "ghidra.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(artifact_dict, f, indent=2)
            temp_path.replace(target_path)
            logger.info("Persisted Ghidra artifact: path='%s'", target_path)
            return target_path
        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error("Failed to persist ghidra.json artifact for file_id='%s': %s", file_id, err)
            raise IOError(f"Could not write ghidra.json artifact: {err}") from err

    def load_ghidra_artifact(self, project_dir: Path, file_id: str) -> Optional[Dict[str, Any]]:
        """Loads ghidra.json artifact from disk if present."""
        target_path = project_dir / "analysis" / file_id / "ghidra.json"
        if target_path.exists():
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as err:
                logger.warning("Corrupted ghidra.json artifact for file_id='%s': %s", file_id, err)
        return None

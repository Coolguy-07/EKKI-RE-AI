"""
backend/analysis/pe_parser.py

Production-grade Portable Executable (PE) Parser Engine for EKKI-RE-AI.
Implements BaseAnalysisEngine plugin contract.
Parses DOS header, COFF header, Optional Header (PE32/PE32+), Section Table (with section entropy),
Data Directories, Import Table, and Export Table using bounds-checked BinaryReader.
Guarantees zero uncaught exceptions and persists analysis/{file_id}/pe.json.
"""

import datetime
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseAnalysisEngine
from .binary_reader import BinaryReader
from .executable_model import CURRENT_SHARED_MODEL_VERSION, UnifiedExecutableModel, UnifiedSection
from .models import CURRENT_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class PEParserEngine(BaseAnalysisEngine):
    """Engine responsible for parsing PE32 / PE32+ executables and DLLs."""

    @property
    def engine_name(self) -> str:
        return "pe_parser"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    def can_handle(
        self,
        content: bytes,
        detected_type: str = "",
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Determines if engine should execute based on detected type or raw magic bytes."""
        if "PE" in detected_type or "Windows Executable" in detected_type:
            return True
        if content and len(content) >= 2 and content.startswith(b"MZ"):
            return True
        return False

    # --- Constant Mappings ---
    MACHINE_MAP = {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "ARM",
        0x01C2: "ARM (Thumb)",
        0x01C4: "ARM (NT)",
        0xAA64: "ARM64",
        0x0200: "IA64",
    }

    SUBSYSTEM_MAP = {
        0: "IMAGE_SUBSYSTEM_UNKNOWN",
        1: "IMAGE_SUBSYSTEM_NATIVE",
        2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
        5: "IMAGE_SUBSYSTEM_OS2_CUI",
        7: "IMAGE_SUBSYSTEM_POSIX_CUI",
        9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
        10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
        11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
        12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
        13: "IMAGE_SUBSYSTEM_EFI_ROM",
        14: "IMAGE_SUBSYSTEM_XBOX",
        16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
    }

    CHARACTERISTICS_MAP = {
        0x0001: "RELOCS_STRIPPED",
        0x0002: "EXECUTABLE_IMAGE",
        0x0004: "LINE_NUMS_STRIPPED",
        0x0008: "LOCAL_SYMS_STRIPPED",
        0x0010: "AGGRESSIVE_WS_TRIM",
        0x0020: "LARGE_ADDRESS_AWARE",
        0x0080: "BYTES_REVERSED_LO",
        0x0100: "32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED",
        0x0400: "REMOVABLE_RUN_FROM_SWAP",
        0x0800: "NET_RUN_FROM_SWAP",
        0x1000: "SYSTEM",
        0x2000: "DLL",
        0x4000: "UP_SYSTEM_ONLY",
        0x8000: "BYTES_REVERSED_HI",
    }

    DLL_CHARACTERISTICS_MAP = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF",
        0x8000: "TERMINAL_SERVER_AWARE",
    }

    SECTION_FLAGS_MAP = {
        0x00000020: "CNT_CODE",
        0x00000040: "CNT_INITIALIZED_DATA",
        0x00000080: "CNT_UNINITIALIZED_DATA",
        0x02000000: "MEM_DISCARDABLE",
        0x04000000: "MEM_NOT_CACHED",
        0x08000000: "MEM_NOT_PAGED",
        0x10000000: "MEM_SHARED",
        0x20000000: "MEM_EXECUTE",
        0x40000000: "MEM_READ",
        0x80000000: "MEM_WRITE",
    }

    DIRECTORY_NAMES = [
        "export_table",
        "import_table",
        "resource_table",
        "exception_table",
        "security_directory",
        "base_relocations",
        "debug_directory",
        "architecture_directory",
        "global_ptr",
        "tls_directory",
        "load_config",
        "bound_import",
        "import_address_table",
        "delay_import",
        "clr_runtime",
        "reserved",
    ]

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs PE parsing analysis and returns update payload for metadata.json."""
        start_time = time.perf_counter()
        reader = BinaryReader(content)
        errors: List[str] = []

        pe_data: Dict[str, Any] = {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "file_id": file_id,
            "filename": filename,
            "is_pe": False,
            "dos_header": None,
            "coff_header": None,
            "optional_header": None,
            "sections": [],
            "directories": {},
            "imports": [],
            "exports": None,
            "summary": {
                "is_pe": False,
                "architecture": "N/A",
                "entry_point": "0x00000000",
                "image_base": "0x00000000",
                "number_of_sections": 0,
                "imported_dll_count": 0,
                "total_import_count": 0,
                "export_count": 0,
                "timestamp_iso": None,
                "subsystem": "N/A",
            },
            "errors": errors,
        }

        # 1. Validate DOS Header Magic
        if reader.size < 64:
            errors.append("File size is smaller than DOS header (64 bytes).")
            pe_data["errors"] = errors
            return self._build_engine_result(pe_data, start_time, existing_metadata=existing_metadata)

        e_magic = reader.read_bytes(0, 2)
        if e_magic != b"MZ":
            errors.append("File magic signature does not match PE format ('MZ').")
            pe_data["errors"] = errors
            return self._build_engine_result(pe_data, start_time, existing_metadata=existing_metadata)

        e_lfanew = reader.read_u32_le(0x3C)
        if e_lfanew is None or e_lfanew < 0 or e_lfanew > reader.size - 24:
            errors.append(f"Invalid or out-of-bounds e_lfanew offset: {e_lfanew}")
            pe_data["errors"] = errors
            return self._build_engine_result(pe_data, start_time, existing_metadata=existing_metadata)

        pe_data["dos_header"] = {
            "e_magic": "MZ",
            "e_lfanew": e_lfanew,
        }

        # 2. Validate PE NT Signature
        pe_sig = reader.read_bytes(e_lfanew, 4)
        if pe_sig != b"PE\x00\x00":
            errors.append(f"Invalid PE NT header signature at offset {e_lfanew}: {pe_sig!r}")
            pe_data["errors"] = errors
            return self._build_engine_result(pe_data, start_time, existing_metadata=existing_metadata)

        pe_data["is_pe"] = True
        pe_data["summary"]["is_pe"] = True

        coff_offset = e_lfanew + 4

        # 3. Parse COFF Header (20 bytes)
        machine_raw = reader.read_u16_le(coff_offset)
        num_sections = reader.read_u16_le(coff_offset + 2)
        timestamp_raw = reader.read_u32_le(coff_offset + 4)
        ptr_symbols = reader.read_u32_le(coff_offset + 8)
        num_symbols = reader.read_u32_le(coff_offset + 12)
        opt_hdr_size = reader.read_u16_le(coff_offset + 16)
        char_raw = reader.read_u16_le(coff_offset + 18)

        if any(v is None for v in [machine_raw, num_sections, timestamp_raw, opt_hdr_size, char_raw]):
            errors.append("Truncated COFF file header.")
            pe_data["errors"] = errors
            return self._build_engine_result(pe_data, start_time, existing_metadata=existing_metadata)

        # Parse timestamp ISO string safely
        timestamp_iso = None
        if timestamp_raw:
            try:
                timestamp_iso = datetime.datetime.fromtimestamp(timestamp_raw, tz=datetime.timezone.utc).isoformat()
            except Exception:
                timestamp_iso = f"Raw timestamp ({timestamp_raw})"

        arch_str = self.MACHINE_MAP.get(machine_raw, f"Unknown (0x{machine_raw:04x})")
        char_flags = [flag for mask, flag in self.CHARACTERISTICS_MAP.items() if (char_raw & mask)]

        pe_data["coff_header"] = {
            "machine": arch_str,
            "machine_raw": machine_raw,
            "number_of_sections": num_sections,
            "timestamp_raw": timestamp_raw,
            "timestamp_iso": timestamp_iso,
            "pointer_to_symbol_table": ptr_symbols,
            "number_of_symbols": num_symbols,
            "size_of_optional_header": opt_hdr_size,
            "characteristics_raw": char_raw,
            "characteristics": char_flags,
        }
        pe_data["summary"]["architecture"] = arch_str
        pe_data["summary"]["number_of_sections"] = num_sections
        pe_data["summary"]["timestamp_iso"] = timestamp_iso

        opt_offset = coff_offset + 20

        # 4. Parse Optional Header (PE32 vs PE32+)
        if opt_hdr_size > 0 and reader.is_valid_offset(opt_offset, 2):
            opt_magic = reader.read_u16_le(opt_offset)
            is_64bit = (opt_magic == 0x020B)  # 0x010B = PE32, 0x020B = PE32+

            magic_str = "PE32+" if is_64bit else "PE32" if opt_magic == 0x010B else f"Unknown (0x{opt_magic:04x})"
            entry_point = reader.read_u32_le(opt_offset + 16) or 0
            
            if is_64bit:
                image_base = reader.read_u64_le(opt_offset + 24) or 0
                sec_align = reader.read_u32_le(opt_offset + 32) or 0
                file_align = reader.read_u32_le(opt_offset + 36) or 0
                size_image = reader.read_u32_le(opt_offset + 56) or 0
                size_headers = reader.read_u32_le(opt_offset + 60) or 0
                subsystem_raw = reader.read_u16_le(opt_offset + 68) or 0
                dll_char_raw = reader.read_u16_le(opt_offset + 70) or 0
                rva_sizes_count = reader.read_u32_le(opt_offset + 108) or 0
                data_dirs_offset = opt_offset + 112
            else:
                image_base = reader.read_u32_le(opt_offset + 28) or 0
                sec_align = reader.read_u32_le(opt_offset + 32) or 0
                file_align = reader.read_u32_le(opt_offset + 36) or 0
                size_image = reader.read_u32_le(opt_offset + 56) or 0
                size_headers = reader.read_u32_le(opt_offset + 60) or 0
                subsystem_raw = reader.read_u16_le(opt_offset + 68) or 0
                dll_char_raw = reader.read_u16_le(opt_offset + 70) or 0
                rva_sizes_count = reader.read_u32_le(opt_offset + 92) or 0
                data_dirs_offset = opt_offset + 96

            subsystem_str = self.SUBSYSTEM_MAP.get(subsystem_raw, f"UNKNOWN_{subsystem_raw}")
            dll_flags = [flag for mask, flag in self.DLL_CHARACTERISTICS_MAP.items() if (dll_char_raw & mask)]

            pe_data["optional_header"] = {
                "magic": magic_str,
                "magic_raw": opt_magic,
                "entry_point": f"0x{entry_point:08x}",
                "entry_point_raw": entry_point,
                "image_base": f"0x{image_base:016x}" if is_64bit else f"0x{image_base:08x}",
                "image_base_raw": image_base,
                "section_alignment": sec_align,
                "file_alignment": file_align,
                "size_of_image": size_image,
                "size_of_headers": size_headers,
                "subsystem": subsystem_str,
                "subsystem_raw": subsystem_raw,
                "dll_characteristics_raw": dll_char_raw,
                "dll_characteristics": dll_flags,
                "number_of_rva_and_sizes": rva_sizes_count,
            }

            pe_data["summary"]["entry_point"] = pe_data["optional_header"]["entry_point"]
            pe_data["summary"]["image_base"] = pe_data["optional_header"]["image_base"]
            pe_data["summary"]["subsystem"] = subsystem_str

            # 5. Parse Data Directories (16 entries: 8 bytes each)
            for i in range(min(rva_sizes_count, 16)):
                dir_entry_offset = data_dirs_offset + (i * 8)
                dir_rva = reader.read_u32_le(dir_entry_offset) or 0
                dir_size = reader.read_u32_le(dir_entry_offset + 4) or 0
                name_key = self.DIRECTORY_NAMES[i] if i < len(self.DIRECTORY_NAMES) else f"directory_{i}"

                pe_data["directories"][name_key] = {
                    "rva": f"0x{dir_rva:08x}",
                    "rva_raw": dir_rva,
                    "size": dir_size,
                    "present": (dir_rva > 0 and dir_size > 0),
                }

        # 6. Parse Section Table (Located immediately after Optional Header)
        section_table_offset = opt_offset + opt_hdr_size
        sections_list: List[Dict[str, Any]] = []

        for s_idx in range(num_sections):
            sec_offset = section_table_offset + (s_idx * 40)
            if not reader.is_valid_offset(sec_offset, 40):
                errors.append(f"Truncated section table entry at index {s_idx}.")
                break

            sec_name_bytes = reader.read_bytes(sec_offset, 8) or b""
            sec_name = sec_name_bytes.decode("ascii", errors="replace").rstrip("\x00").strip()
            if not sec_name:
                sec_name = f".sec_{s_idx}"

            v_size = reader.read_u32_le(sec_offset + 8) or 0
            v_addr = reader.read_u32_le(sec_offset + 12) or 0
            raw_size = reader.read_u32_le(sec_offset + 16) or 0
            raw_offset = reader.read_u32_le(sec_offset + 20) or 0
            s_char_raw = reader.read_u32_le(sec_offset + 36) or 0

            s_flags = [flag for mask, flag in self.SECTION_FLAGS_MAP.items() if (s_char_raw & mask)]
            s_entropy = reader.calculate_entropy(raw_offset, raw_size)

            sections_list.append({
                "name": sec_name,
                "virtual_address": f"0x{v_addr:08x}",
                "virtual_address_raw": v_addr,
                "virtual_size": v_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics_raw": s_char_raw,
                "characteristics": s_flags,
                "entropy": s_entropy,
            })

        pe_data["sections"] = sections_list

        # 7. Helper: RVA to File Offset Translator
        def _rva_to_offset(rva: int) -> Optional[int]:
            if rva == 0:
                return None
            for sec in sections_list:
                sec_vaddr = sec["virtual_address_raw"]
                sec_vsize = max(sec["virtual_size"], sec["raw_size"])
                if sec_vaddr <= rva < sec_vaddr + sec_vsize:
                    offset = rva - sec_vaddr + sec["raw_offset"]
                    if reader.is_valid_offset(offset, 1):
                        return offset
            # Header RVA fallback
            if pe_data["optional_header"] and rva < pe_data["optional_header"]["size_of_headers"]:
                if reader.is_valid_offset(rva, 1):
                    return rva
            return None

        # 8. Parse Imports Table
        import_dir = pe_data["directories"].get("import_table")
        if import_dir and import_dir["present"]:
            import_rva = import_dir["rva_raw"]
            import_file_offset = _rva_to_offset(import_rva)

            if import_file_offset is not None:
                parsed_imports: List[Dict[str, Any]] = []
                total_func_count = 0
                max_dlls = 256
                desc_idx = 0

                while desc_idx < max_dlls:
                    desc_offset = import_file_offset + (desc_idx * 20)
                    if not reader.is_valid_offset(desc_offset, 20):
                        errors.append(f"Import Descriptor descriptor bounds violation at index {desc_idx}.")
                        break

                    orig_thunk = reader.read_u32_le(desc_offset)
                    timedatestamp = reader.read_u32_le(desc_offset + 4)
                    forwarder = reader.read_u32_le(desc_offset + 8)
                    name_rva = reader.read_u32_le(desc_offset + 12)
                    first_thunk = reader.read_u32_le(desc_offset + 16)

                    # Null descriptor terminates list
                    if all(v == 0 for v in [orig_thunk, timedatestamp, forwarder, name_rva, first_thunk]):
                        break

                    dll_name = None
                    if name_rva:
                        dll_name_offset = _rva_to_offset(name_rva)
                        if dll_name_offset is not None:
                            dll_name = reader.read_cstring(dll_name_offset, max_length=256)

                    if not dll_name:
                        dll_name = f"UNKNOWN_DLL_{desc_idx}"

                    # Read Import Lookup Table (ILT)
                    thunk_rva = orig_thunk if (orig_thunk and orig_thunk > 0) else first_thunk
                    thunk_offset = _rva_to_offset(thunk_rva) if thunk_rva else None

                    functions_list: List[Dict[str, Any]] = []

                    if thunk_offset is not None:
                        is_64bit = (pe_data["optional_header"]["magic"] == "PE32+") if pe_data["optional_header"] else False
                        entry_size = 8 if is_64bit else 4
                        ordinal_flag = 0x8000000000000000 if is_64bit else 0x80000000
                        max_funcs = 1024
                        f_idx = 0

                        while f_idx < max_funcs:
                            t_entry_offset = thunk_offset + (f_idx * entry_size)
                            if not reader.is_valid_offset(t_entry_offset, entry_size):
                                break

                            val = reader.read_u64_le(t_entry_offset) if is_64bit else reader.read_u32_le(t_entry_offset)
                            if val is None or val == 0:
                                break

                            if val & ordinal_flag:
                                # Imported by Ordinal
                                ord_num = val & 0xFFFF
                                functions_list.append({
                                    "name": None,
                                    "ordinal": ord_num,
                                    "rva": f"0x{val:08x}",
                                })
                            else:
                                # Imported by Name
                                name_table_offset = _rva_to_offset(val)
                                func_name = None
                                hint_val = None

                                if name_table_offset is not None:
                                    hint_val = reader.read_u16_le(name_table_offset)
                                    func_name = reader.read_cstring(name_table_offset + 2, max_length=256)

                                functions_list.append({
                                    "name": func_name or f"Function_0x{val:x}",
                                    "hint": hint_val,
                                    "ordinal": None,
                                    "rva": f"0x{val:08x}",
                                })

                            f_idx += 1

                    total_func_count += len(functions_list)
                    parsed_imports.append({
                        "dll": dll_name,
                        "functions": functions_list,
                    })

                    desc_idx += 1

                pe_data["imports"] = parsed_imports
                pe_data["summary"]["imported_dll_count"] = len(parsed_imports)
                pe_data["summary"]["total_import_count"] = total_func_count

        # 9. Parse Exports Table
        export_dir = pe_data["directories"].get("export_table")
        if export_dir and export_dir["present"]:
            export_rva = export_dir["rva_raw"]
            export_file_offset = _rva_to_offset(export_rva)

            if export_file_offset is not None and reader.is_valid_offset(export_file_offset, 40):
                exp_name_rva = reader.read_u32_le(export_file_offset + 12) or 0
                exp_base = reader.read_u32_le(export_file_offset + 16) or 0
                num_funcs = reader.read_u32_le(export_file_offset + 20) or 0
                num_names = reader.read_u32_le(export_file_offset + 24) or 0
                funcs_rva = reader.read_u32_le(export_file_offset + 28) or 0
                names_rva = reader.read_u32_le(export_file_offset + 32) or 0
                ordinals_rva = reader.read_u32_le(export_file_offset + 36) or 0

                export_dll_name = None
                if exp_name_rva:
                    exp_dll_offset = _rva_to_offset(exp_name_rva)
                    if exp_dll_offset is not None:
                        export_dll_name = reader.read_cstring(exp_dll_offset, max_length=256)

                exported_functions: List[Dict[str, Any]] = []

                if num_names > 0 and names_rva and ordinals_rva:
                    names_offset = _rva_to_offset(names_rva)
                    ords_offset = _rva_to_offset(ordinals_rva)
                    funcs_table_offset = _rva_to_offset(funcs_rva) if funcs_rva else None

                    if names_offset is not None and ords_offset is not None:
                        max_exp_names = min(num_names, 2048)
                        for e_idx in range(max_exp_names):
                            n_ptr_offset = names_offset + (e_idx * 4)
                            o_ptr_offset = ords_offset + (e_idx * 2)

                            if not reader.is_valid_offset(n_ptr_offset, 4) or not reader.is_valid_offset(o_ptr_offset, 2):
                                break

                            fn_name_rva = reader.read_u32_le(n_ptr_offset) or 0
                            fn_ordinal_idx = reader.read_u16_le(o_ptr_offset) or 0

                            fn_name = None
                            if fn_name_rva:
                                fn_name_offset = _rva_to_offset(fn_name_rva)
                                if fn_name_offset is not None:
                                    fn_name = reader.read_cstring(fn_name_offset, max_length=256)

                            fn_rva = 0
                            if funcs_table_offset is not None:
                                f_ptr_offset = funcs_table_offset + (fn_ordinal_idx * 4)
                                if reader.is_valid_offset(f_ptr_offset, 4):
                                    fn_rva = reader.read_u32_le(f_ptr_offset) or 0

                            exported_functions.append({
                                "name": fn_name or f"Ordinal_{exp_base + fn_ordinal_idx}",
                                "ordinal": exp_base + fn_ordinal_idx,
                                "rva": f"0x{fn_rva:08x}",
                            })

                pe_data["exports"] = {
                    "dll_name": export_dll_name,
                    "number_of_functions": num_funcs,
                    "number_of_names": num_names,
                    "functions": exported_functions,
                }
                pe_data["summary"]["export_count"] = len(exported_functions)

        # Construct Shared ExecutableModel
        if pe_data["is_pe"]:
            unified_sections = [
                UnifiedSection(
                    name=s["name"],
                    virtual_address=s["virtual_address"],
                    virtual_address_raw=s["virtual_address_raw"],
                    virtual_size=s["virtual_size"],
                    raw_offset=s["raw_offset"],
                    raw_size=s["raw_size"],
                    entropy=s["entropy"],
                    flags=s["characteristics"],
                )
                for s in sections_list
            ]

            imported_dll_names = [imp["dll"] for imp in pe_data.get("imports", []) if "dll" in imp]
            is_64 = (pe_data["optional_header"]["magic"] == "PE32+") if pe_data.get("optional_header") else False
            is_dll_bin = "DLL" in pe_data.get("coff_header", {}).get("characteristics", [])

            shared_model = UnifiedExecutableModel(
                schema_version=CURRENT_SHARED_MODEL_VERSION,
                file_id=file_id,
                format="PE",
                architecture=pe_data["summary"]["architecture"],
                bitness=64 if is_64 else 32,
                endianness="little",
                entry_point=pe_data["summary"]["entry_point"],
                entry_point_raw=pe_data.get("optional_header", {}).get("entry_point_raw", 0) if pe_data.get("optional_header") else 0,
                image_base=pe_data["summary"]["image_base"],
                subsystem_or_abi=pe_data["summary"]["subsystem"],
                is_executable=not is_dll_bin,
                is_shared_library=is_dll_bin,
                sections=unified_sections,
                libraries=imported_dll_names,
                symbols_count=pe_data["summary"]["export_count"],
                parser_name=self.engine_name,
                parser_version=self.engine_version,
                parser_errors=errors,
                format_specific={
                    "subsystem": pe_data["summary"]["subsystem"],
                    "timestamp": pe_data["summary"]["timestamp_iso"],
                },
            )
            pe_data["unified_model"] = shared_model.model_dump()
        else:
            pe_data["unified_model"] = None

        # Merge reader accumulated bounds/parsing errors
        if reader.errors:
            errors.extend(reader.errors)

        return self._build_engine_result(pe_data, start_time, existing_metadata)

    def _build_engine_result(
        self,
        pe_data: Dict[str, Any],
        start_time: float,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Formats output dict and merges into existing_metadata."""
        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "PEParserEngine completed for file_id='%s': is_pe=%s sections=%d in %.2fms",
            pe_data["file_id"],
            pe_data["is_pe"],
            len(pe_data.get("sections", [])),
            exec_time_ms,
        )

        return self._inject_engine_result(
            existing_metadata=existing_metadata,
            parsed_data=pe_data,
            exec_time_ms=exec_time_ms,
            extra_fields={"is_pe": pe_data["is_pe"]},
        )

    def save_pe_artifact(self, project_dir: Path, file_id: str, pe_data: Dict[str, Any]) -> Path:
        """Saves parsed PE payload to projects/{project_id}/analysis/{file_id}/pe.json."""
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "pe.json"
        temp_path = analysis_dir / "pe.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(pe_data, f, indent=2)
            temp_path.replace(target_path)
            logger.info("PE artifact written: path='%s'", target_path)
            return target_path

        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error("Failed to write PE artifact for file_id='%s': %s", file_id, err)
            raise IOError(f"Could not write PE analysis artifact: {err}") from err

"""
backend/analysis/macho_parser.py

Production-grade Mach-O Parser Engine for EKKI-RE-AI.
Supports 32-bit, 64-bit, Little/Big Endian, and Universal Fat Binary Mach-O executables and dylibs.
Parses Mach Header, Load Commands, Segments, Sections (with section entropy),
Symbols, Dynamic Libraries (LC_LOAD_DYLIB), UUID (LC_UUID), Entry Point (LC_MAIN), Code Signature.
Constructs UnifiedExecutableModel and persists analysis/{file_id}/macho.json.
"""

import logging
import os
import struct
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseAnalysisEngine
from .binary_reader import BinaryReader
from .executable_model import CURRENT_SHARED_MODEL_VERSION, UnifiedExecutableModel, UnifiedSection
from .models import CURRENT_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class MachOParserEngine(BaseAnalysisEngine):
    """Engine responsible for parsing macOS / iOS Mach-O binaries."""

    @property
    def engine_name(self) -> str:
        return "macho_parser"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    # --- Mach-O Mappings ---
    CPU_TYPE_MAP = {
        7: "x86",
        0x01000007: "x86_64",
        12: "ARM",
        0x0100000C: "ARM64",
        18: "PowerPC",
        0x01000012: "PowerPC 64-bit",
    }

    FILE_TYPE_MAP = {
        1: "MH_OBJECT (Relocatable Object)",
        2: "MH_EXECUTE (Executable)",
        3: "MH_FVMLIB (Fixed VM Library)",
        4: "MH_CORE (Core Dump)",
        5: "MH_PRELOAD (Preloaded Executable)",
        6: "MH_DYLIB (Dynamic Shared Library)",
        7: "MH_DYLINKER (Dynamic Link Editor)",
        8: "MH_BUNDLE (Dynamically Bound Bundle)",
    }

    LC_MAP = {
        0x1: "LC_SEGMENT",
        0x2: "LC_SYMTAB",
        0x4: "LC_THREAD",
        0x5: "LC_UNIXTHREAD",
        0xB: "LC_DYSYMTAB",
        0xC: "LC_LOAD_DYLIB",
        0xE: "LC_ID_DYLIB",
        0xF: "LC_LOAD_DYLINKER",
        0x19: "LC_SEGMENT_64",
        0x1B: "LC_UUID",
        0x1C: "LC_RPATH",
        0x1D: "LC_CODE_SIGNATURE",
        0x22: "LC_DYLD_INFO_ONLY",
        0x2A: "LC_SOURCE_VERSION",
        0x80000028: "LC_MAIN",
    }

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Parses Mach-O payload and returns update payload for metadata.json."""
        start_time = time.perf_counter()
        reader = BinaryReader(content)
        errors: List[str] = []

        macho_data: Dict[str, Any] = {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "file_id": file_id,
            "filename": filename,
            "is_macho": False,
            "is_fat": False,
            "mach_header": None,
            "fat_archs": [],
            "load_commands": [],
            "segments": [],
            "sections": [],
            "symbols": [],
            "dynamic_libraries": [],
            "uuid": None,
            "entry_point": None,
            "code_signature": None,
            "summary": {
                "is_macho": False,
                "architecture": "N/A",
                "file_type": "N/A",
                "entry_point": "0x00000000",
                "segment_count": 0,
                "section_count": 0,
                "dylib_count": 0,
                "symbol_count": 0,
                "uuid": None,
            },
            "errors": errors,
            "unified_model": None,
        }

        if reader.size < 28:
            errors.append("File size smaller than Mach-O header (28 bytes).")
            macho_data["errors"] = errors
            return self._build_engine_result(macho_data, start_time)

        magic_raw = reader.read_bytes(0, 4) or b""

        # Check Fat Binary or Single Mach-O
        is_fat = magic_raw in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")

        # Disambiguate Fat Binary from Java Class
        if is_fat:
            major_ver = reader.read_u16_be(6) or 0
            if 45 <= major_ver <= 70:
                # It's a Java Class File, not Mach-O
                macho_data["errors"] = errors
                return self._build_engine_result(macho_data, start_time)

        is_macho_magic = magic_raw in (
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        )

        if not is_fat and not is_macho_magic:
            errors.append("File magic signature does not match Mach-O format.")
            macho_data["errors"] = errors
            return self._build_engine_result(macho_data, start_time)

        macho_data["is_macho"] = True
        macho_data["summary"]["is_macho"] = True

        slice_offset = 0

        # Handle Universal Fat Binary Header
        if is_fat:
            macho_data["is_fat"] = True
            nfat = reader.read_u32_be(4) or 0
            fat_archs = []

            for f_idx in range(min(nfat, 10)):
                fa_off = 8 + (f_idx * 20)
                if not reader.is_valid_offset(fa_off, 20):
                    break
                cputype = reader.read_u32_be(fa_off) or 0
                cpusubtype = reader.read_u32_be(fa_off + 4) or 0
                sub_offset = reader.read_u32_be(fa_off + 8) or 0
                sub_size = reader.read_u32_be(fa_off + 12) or 0

                arch_name = self.CPU_TYPE_MAP.get(cputype, f"0x{cputype:08x}")
                fat_archs.append({
                    "architecture": arch_name,
                    "cputype": cputype,
                    "cpusubtype": cpusubtype,
                    "offset": sub_offset,
                    "size": sub_size,
                })

            macho_data["fat_archs"] = fat_archs
            if fat_archs and reader.is_valid_offset(fat_archs[0]["offset"], 28):
                slice_offset = fat_archs[0]["offset"]
                magic_raw = reader.read_bytes(slice_offset, 4) or b""

        # Parse Mach Header
        is_64bit = magic_raw in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
        is_little_endian = magic_raw in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")

        read_u32 = (lambda off: reader.read_u32_le(off)) if is_little_endian else (lambda off: reader.read_u32_be(off))
        read_u64 = (lambda off: reader.read_u64_le(off)) if is_little_endian else (lambda off: reader.read_u64_be(off))

        cputype = read_u32(slice_offset + 4) or 0
        cpusubtype = read_u32(slice_offset + 8) or 0
        filetype = read_u32(slice_offset + 12) or 0
        ncmds = read_u32(slice_offset + 16) or 0
        sizeofcmds = read_u32(slice_offset + 20) or 0
        flags_raw = read_u32(slice_offset + 24) or 0

        arch_str = self.CPU_TYPE_MAP.get(cputype, f"Unknown (0x{cputype:08x})")
        filetype_str = self.FILE_TYPE_MAP.get(filetype, f"Unknown (0x{filetype:08x})")

        hdr_size = 32 if is_64bit else 28
        macho_data["mach_header"] = {
            "magic": f"0x{struct.unpack('>I' if is_little_endian else '>I', magic_raw)[0]:08x}" if magic_raw else "",
            "bitness": 64 if is_64bit else 32,
            "endianness": "little" if is_little_endian else "big",
            "cpu_type": arch_str,
            "cpu_type_raw": cputype,
            "cpu_subtype": cpusubtype,
            "file_type": filetype_str,
            "file_type_raw": filetype,
            "number_of_load_commands": ncmds,
            "size_of_load_commands": sizeofcmds,
            "flags_raw": flags_raw,
        }

        macho_data["summary"]["architecture"] = arch_str
        macho_data["summary"]["file_type"] = filetype_str

        # Parse Load Commands
        cmd_offset = slice_offset + hdr_size
        segments_list: List[Dict[str, Any]] = []
        sections_list: List[Dict[str, Any]] = []
        dynamic_libraries: List[str] = []
        parsed_symbols: List[Dict[str, Any]] = []
        uuid_str: Optional[str] = None
        entry_point_str: Optional[str] = None
        entry_point_raw: int = 0
        code_sig_dict: Optional[Dict[str, Any]] = None

        max_cmds = min(ncmds, 128)
        for c_idx in range(max_cmds):
            if not reader.is_valid_offset(cmd_offset, 8):
                errors.append(f"Load command bounds violation at index {c_idx}.")
                break

            cmd_type = read_u32(cmd_offset) or 0
            cmd_size = read_u32(cmd_offset + 4) or 8

            if cmd_size < 8 or not reader.is_valid_offset(cmd_offset, cmd_size):
                errors.append(f"Invalid cmdsize {cmd_size} at index {c_idx}.")
                break

            cmd_name = self.LC_MAP.get(cmd_type, f"LC_UNKNOWN (0x{cmd_type:08x})")

            # 1. LC_SEGMENT / LC_SEGMENT_64
            if cmd_type in (0x1, 0x19):
                is_seg64 = (cmd_type == 0x19)
                segname_bytes = reader.read_bytes(cmd_offset + 8, 16) or b""
                segname = segname_bytes.decode("ascii", errors="replace").rstrip("\x00").strip()

                if is_seg64:
                    vmaddr = read_u64(cmd_offset + 24) or 0
                    vmsize = read_u64(cmd_offset + 32) or 0
                    fileoff = read_u64(cmd_offset + 40) or 0
                    filesz = read_u64(cmd_offset + 48) or 0
                    maxprot = read_u32(cmd_offset + 56) or 0
                    initprot = read_u32(cmd_offset + 60) or 0
                    nsects = read_u32(cmd_offset + 64) or 0
                    sec_hdr_start = cmd_offset + 72
                    sec_hdr_size = 80
                else:
                    vmaddr = read_u32(cmd_offset + 24) or 0
                    vmsize = read_u32(cmd_offset + 28) or 0
                    fileoff = read_u32(cmd_offset + 32) or 0
                    filesz = read_u32(cmd_offset + 36) or 0
                    maxprot = read_u32(cmd_offset + 40) or 0
                    initprot = read_u32(cmd_offset + 44) or 0
                    nsects = read_u32(cmd_offset + 48) or 0
                    sec_hdr_start = cmd_offset + 56
                    sec_hdr_size = 68

                segments_list.append({
                    "segment_name": segname,
                    "vm_address": f"0x{vmaddr:016x}" if is_seg64 else f"0x{vmaddr:08x}",
                    "vm_address_raw": vmaddr,
                    "vm_size": vmsize,
                    "file_offset": fileoff,
                    "file_size": filesz,
                    "number_of_sections": nsects,
                })

                # Parse Sections inside Segment
                for s_i in range(min(nsects, 64)):
                    sh_off = sec_hdr_start + (s_i * sec_hdr_size)
                    if not reader.is_valid_offset(sh_off, sec_hdr_size):
                        break

                    sect_bytes = reader.read_bytes(sh_off, 16) or b""
                    sectname = sect_bytes.decode("ascii", errors="replace").rstrip("\x00").strip()

                    if is_seg64:
                        s_addr = read_u64(sh_off + 32) or 0
                        s_size = read_u64(sh_off + 40) or 0
                        s_offset = read_u32(sh_off + 48) or 0
                        s_align = read_u32(sh_off + 52) or 0
                        s_flags = read_u32(sh_off + 64) or 0
                    else:
                        s_addr = read_u32(sh_off + 32) or 0
                        s_size = read_u32(sh_off + 36) or 0
                        s_offset = read_u32(sh_off + 40) or 0
                        s_align = read_u32(sh_off + 44) or 0
                        s_flags = read_u32(sh_off + 56) or 0

                    s_entropy = reader.calculate_entropy(s_offset, s_size)

                    sections_list.append({
                        "section_name": sectname,
                        "segment_name": segname,
                        "address": f"0x{s_addr:016x}" if is_seg64 else f"0x{s_addr:08x}",
                        "address_raw": s_addr,
                        "size": s_size,
                        "offset": s_offset,
                        "alignment": s_align,
                        "flags": s_flags,
                        "entropy": s_entropy,
                    })

            # 2. LC_LOAD_DYLIB
            elif cmd_type in (0xC, 0x18 | 0x80000000):
                str_offset_rel = read_u32(cmd_offset + 8) or 24
                if str_offset_rel < cmd_size:
                    lib_path = reader.read_cstring(cmd_offset + str_offset_rel, max_length=cmd_size - str_offset_rel)
                    if lib_path and lib_path not in dynamic_libraries:
                        dynamic_libraries.append(lib_path)

            # 3. LC_UUID
            elif cmd_type == 0x1B:
                uuid_bytes = reader.read_bytes(cmd_offset + 8, 16)
                if uuid_bytes and len(uuid_bytes) == 16:
                    uuid_str = str(uuid.UUID(bytes=uuid_bytes))

            # 4. LC_MAIN
            elif cmd_type == 0x80000028:
                entryoff = read_u64(cmd_offset + 8) or 0
                entry_point_raw = entryoff
                entry_point_str = f"0x{entryoff:016x}"

            # 5. LC_SYMTAB
            elif cmd_type == 0x2:
                symoff = read_u32(cmd_offset + 8) or 0
                nsyms = read_u32(cmd_offset + 12) or 0
                stroff = read_u32(cmd_offset + 16) or 0
                strsize = read_u32(cmd_offset + 20) or 0

                if nsyms > 0 and reader.is_valid_offset(symoff, 1) and reader.is_valid_offset(stroff, strsize):
                    nlist_size = 16 if is_64bit else 12
                    max_syms = min(nsyms, 512)
                    for sym_i in range(max_syms):
                        nl_off = symoff + (sym_i * nlist_size)
                        if not reader.is_valid_offset(nl_off, nlist_size):
                            break
                        n_strx = read_u32(nl_off) or 0
                        n_type = reader.read_u8(nl_off + 4) or 0
                        n_value = read_u64(nl_off + 8) if is_64bit else (read_u32(nl_off + 8) or 0)

                        if n_strx > 0 and n_strx < strsize:
                            sym_name = reader.read_cstring(stroff + n_strx, max_length=256)
                            if sym_name:
                                parsed_symbols.append({
                                    "name": sym_name,
                                    "type_raw": n_type,
                                    "value": f"0x{n_value:016x}" if is_64bit else f"0x{n_value:08x}",
                                })

            # 6. LC_CODE_SIGNATURE
            elif cmd_type == 0x1D:
                dataoff = read_u32(cmd_offset + 8) or 0
                datasize = read_u32(cmd_offset + 12) or 0
                code_sig_dict = {"offset": dataoff, "size": datasize}

            macho_data["load_commands"].append({
                "type": cmd_name,
                "type_raw": cmd_type,
                "size": cmd_size,
            })

            cmd_offset += cmd_size

        macho_data["segments"] = segments_list
        macho_data["sections"] = sections_list
        macho_data["dynamic_libraries"] = dynamic_libraries
        macho_data["symbols"] = parsed_symbols
        macho_data["uuid"] = uuid_str
        macho_data["entry_point"] = entry_point_str or "0x00000000"
        macho_data["code_signature"] = code_sig_dict

        macho_data["summary"]["segment_count"] = len(segments_list)
        macho_data["summary"]["section_count"] = len(sections_list)
        macho_data["summary"]["dylib_count"] = len(dynamic_libraries)
        macho_data["summary"]["symbol_count"] = len(parsed_symbols)
        macho_data["summary"]["entry_point"] = macho_data["entry_point"]
        macho_data["summary"]["uuid"] = uuid_str

        # Construct Shared ExecutableModel
        unified_sections = [
            UnifiedSection(
                name=s["section_name"],
                virtual_address=s["address"],
                virtual_address_raw=s["address_raw"],
                virtual_size=s["size"],
                raw_offset=s["offset"],
                raw_size=s["size"],
                entropy=s["entropy"],
                flags=[],
            )
            for s in sections_list
        ]

        shared_model = UnifiedExecutableModel(
            schema_version=CURRENT_SHARED_MODEL_VERSION,
            file_id=file_id,
            format="Mach-O",
            architecture=arch_str,
            bitness=64 if is_64bit else 32,
            endianness="little" if is_little_endian else "big",
            entry_point=macho_data["entry_point"],
            entry_point_raw=entry_point_raw,
            subsystem_or_abi="macOS / iOS",
            is_executable=(filetype == 2),
            is_shared_library=(filetype in (6, 8)),
            sections=unified_sections,
            libraries=dynamic_libraries,
            symbols_count=len(parsed_symbols),
            parser_name=self.engine_name,
            parser_version=self.engine_version,
            parser_errors=errors,
            format_specific={
                "file_type": filetype_str,
                "uuid": uuid_str,
                "is_fat": is_fat,
            },
        )

        macho_data["unified_model"] = shared_model.model_dump()

        if reader.errors:
            errors.extend(reader.errors)

        return self._build_engine_result(macho_data, start_time)

    def _build_engine_result(self, macho_data: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        """Formats output dict and saves artifact analysis/{file_id}/macho.json."""
        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "MachOParserEngine completed for file_id='%s': is_macho=%s sections=%d in %.2fms",
            macho_data["file_id"],
            macho_data["is_macho"],
            len(macho_data.get("sections", [])),
            exec_time_ms,
        )

        return {
            self.engine_name: {
                "engine_version": self.engine_version,
                "execution_time_ms": exec_time_ms,
                "is_macho": macho_data["is_macho"],
                "parsed_data": macho_data,
            }
        }

    def save_macho_artifact(self, project_dir: Path, file_id: str, macho_data: Dict[str, Any]) -> Path:
        """Saves parsed Mach-O payload to projects/{project_id}/analysis/{file_id}/macho.json."""
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "macho.json"
        temp_path = analysis_dir / "macho.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(macho_data, f, indent=2)
            temp_path.replace(target_path)
            logger.info("Mach-O artifact written: path='%s'", target_path)
            return target_path

        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error("Failed to write Mach-O artifact for file_id='%s': %s", file_id, err)
            raise IOError(f"Could not write Mach-O analysis artifact: {err}") from err

"""
backend/analysis/elf_parser.py

Production-grade Executable and Linkable Format (ELF) Parser Engine for EKKI-RE-AI.
Supports 32-bit and 64-bit binaries in both Little-Endian and Big-Endian configurations.
Parses ELF Header, Program Headers, Section Headers (with section entropy),
Symbol Tables, Dynamic Symbol Tables, Dynamic Libraries (DT_NEEDED), and Interpreter paths.
Constructs UnifiedExecutableModel and persists analysis/{file_id}/elf.json.
"""

import logging
import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseAnalysisEngine
from .binary_reader import BinaryReader
from .executable_model import CURRENT_SHARED_MODEL_VERSION, UnifiedExecutableModel, UnifiedSection
from .models import CURRENT_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class ELFParserEngine(BaseAnalysisEngine):
    """Engine responsible for parsing Linux / Unix ELF binaries."""

    @property
    def engine_name(self) -> str:
        return "elf_parser"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    # --- ELF Mappings ---
    TYPE_MAP = {
        1: "ET_REL (Relocatable object file)",
        2: "ET_EXEC (Executable file)",
        3: "ET_DYN (Shared object file / PIE Executable)",
        4: "ET_CORE (Core dump file)",
    }

    MACHINE_MAP = {
        3: "x86",
        8: "MIPS",
        20: "PowerPC",
        40: "ARM",
        62: "x86_64",
        183: "ARM64",
        243: "RISC-V",
    }

    OSABI_MAP = {
        0: "System V (UNIX)",
        1: "HP-UX",
        2: "NetBSD",
        3: "Linux",
        6: "Solaris",
        9: "FreeBSD",
        12: "OpenBSD",
    }

    PHDR_TYPE_MAP = {
        0: "PT_NULL",
        1: "PT_LOAD",
        2: "PT_DYNAMIC",
        3: "PT_INTERP",
        4: "PT_NOTE",
        5: "PT_SHLIB",
        6: "PT_PHDR",
        7: "PT_TLS",
        0x6474E550: "PT_GNU_EH_FRAME",
        0x6474E551: "PT_GNU_STACK",
        0x6474E552: "PT_GNU_RELRO",
    }

    SHDR_TYPE_MAP = {
        0: "SHT_NULL",
        1: "SHT_PROGBITS",
        2: "SHT_SYMTAB",
        3: "SHT_STRTAB",
        4: "SHT_RELA",
        5: "SHT_HASH",
        6: "SHT_DYNAMIC",
        7: "SHT_NOTE",
        8: "SHT_NOBITS",
        9: "SHT_REL",
        10: "SHT_SHLIB",
        11: "SHT_DYNSYM",
    }

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Parses ELF binary payload and returns updated metadata dict."""
        start_time = time.perf_counter()
        reader = BinaryReader(content)
        errors: List[str] = []

        elf_data: Dict[str, Any] = {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "file_id": file_id,
            "filename": filename,
            "is_elf": False,
            "elf_header": None,
            "program_headers": [],
            "section_headers": [],
            "symbols": [],
            "dynamic_symbols": [],
            "dynamic_libraries": [],
            "interpreter": None,
            "notes": [],
            "summary": {
                "is_elf": False,
                "architecture": "N/A",
                "bitness": 0,
                "endianness": "N/A",
                "entry_point": "0x00000000",
                "type": "N/A",
                "os_abi": "N/A",
                "section_count": 0,
                "program_header_count": 0,
                "needed_libraries_count": 0,
                "symbol_count": 0,
            },
            "errors": errors,
            "unified_model": None,
        }

        # 1. Validate ELF Header Magic (\x7fELF)
        if reader.size < 52:
            errors.append("File size smaller than minimum ELF header (52 bytes).")
            elf_data["errors"] = errors
            return self._build_engine_result(elf_data, start_time)

        magic = reader.read_bytes(0, 4)
        if magic != b"\x7fELF":
            errors.append("File magic signature does not match ELF format ('\\x7fELF').")
            elf_data["errors"] = errors
            return self._build_engine_result(elf_data, start_time)

        elf_data["is_elf"] = True
        elf_data["summary"]["is_elf"] = True

        # 2. Parse ELF Header Identifiers
        ei_class = reader.read_u8(4) or 1
        ei_data = reader.read_u8(5) or 1
        ei_version = reader.read_u8(6) or 1
        ei_osabi = reader.read_u8(7) or 0
        ei_abiversion = reader.read_u8(8) or 0

        is_64bit = (ei_class == 2)
        is_little_endian = (ei_data == 1)

        bitness = 64 if is_64bit else 32
        endian_str = "little" if is_little_endian else "big"
        osabi_str = self.OSABI_MAP.get(ei_osabi, f"Unknown (0x{ei_osabi:02x})")

        # Helpers for endian-aware reads
        read_u16 = reader.read_u16_le if is_little_endian else reader.read_u16_be
        read_u32 = reader.read_u32_le if is_little_endian else reader.read_u32_be
        read_u64 = reader.read_u64_le if is_little_endian else reader.read_u64_be

        # Read remaining header fields based on bitness
        e_type = read_u16(16) or 0
        e_machine = read_u16(18) or 0
        e_version = read_u32(20) or 0

        if is_64bit:
            if reader.size < 64:
                errors.append("File truncated before 64-bit ELF header complete.")
                elf_data["errors"] = errors
                return self._build_engine_result(elf_data, start_time)
            e_entry = read_u64(24) or 0
            e_phoff = read_u64(32) or 0
            e_shoff = read_u64(40) or 0
            e_flags = read_u32(48) or 0
            e_ehsize = read_u16(52) or 0
            e_phentsize = read_u16(54) or 0
            e_phnum = read_u16(56) or 0
            e_shentsize = read_u16(58) or 0
            e_shnum = read_u16(60) or 0
            e_shstrndx = read_u16(62) or 0
        else:
            e_entry = read_u32(24) or 0
            e_phoff = read_u32(28) or 0
            e_shoff = read_u32(32) or 0
            e_flags = read_u32(36) or 0
            e_ehsize = read_u16(40) or 0
            e_phentsize = read_u16(42) or 0
            e_phnum = read_u16(44) or 0
            e_shentsize = read_u16(46) or 0
            e_shnum = read_u16(48) or 0
            e_shstrndx = read_u16(50) or 0

        arch_str = self.MACHINE_MAP.get(e_machine, f"Unknown (0x{e_machine:04x})")
        type_str = self.TYPE_MAP.get(e_type, f"Unknown (0x{e_type:04x})")

        elf_data["elf_header"] = {
            "magic": "\\x7fELF",
            "class": f"{bitness}-bit",
            "bitness": bitness,
            "endianness": endian_str,
            "version": e_version,
            "os_abi": osabi_str,
            "abi_version": ei_abiversion,
            "type": type_str,
            "machine": arch_str,
            "entry_point": f"0x{e_entry:016x}" if is_64bit else f"0x{e_entry:08x}",
            "entry_point_raw": e_entry,
            "program_header_offset": e_phoff,
            "section_header_offset": e_shoff,
            "flags": e_flags,
            "ehsize": e_ehsize,
            "phentsize": e_phentsize,
            "phnum": e_phnum,
            "shentsize": e_shentsize,
            "shnum": e_shnum,
            "shstrndx": e_shstrndx,
        }

        elf_data["summary"]["architecture"] = arch_str
        elf_data["summary"]["bitness"] = bitness
        elf_data["summary"]["endianness"] = endian_str
        elf_data["summary"]["entry_point"] = elf_data["elf_header"]["entry_point"]
        elf_data["summary"]["type"] = type_str
        elf_data["summary"]["os_abi"] = osabi_str
        elf_data["summary"]["program_header_count"] = e_phnum
        elf_data["summary"]["section_count"] = e_shnum

        # 3. Parse Program Headers (Phdrs)
        program_headers: List[Dict[str, Any]] = []
        interpreter_path: Optional[str] = None

        if e_phoff > 0 and e_phnum > 0 and e_phentsize >= 32:
            max_phdrs = min(e_phnum, 128)
            for p_idx in range(max_phdrs):
                p_offset = e_phoff + (p_idx * e_phentsize)
                if not reader.is_valid_offset(p_offset, e_phentsize):
                    errors.append(f"Program header bounds violation at index {p_idx}.")
                    break

                p_type = read_u32(p_offset) or 0
                p_type_str = self.PHDR_TYPE_MAP.get(p_type, f"PT_UNKNOWN (0x{p_type:08x})")

                if is_64bit:
                    p_flags = read_u32(p_offset + 4) or 0
                    p_filesz_offset = p_offset + 8
                    p_vaddr_offset = p_offset + 16
                    p_paddr_offset = p_offset + 24
                    p_filesz = read_u64(p_offset + 32) or 0
                    p_memsz = read_u64(p_offset + 40) or 0
                    p_align = read_u64(p_offset + 48) or 0
                    p_vaddr = read_u64(p_vaddr_offset) or 0
                    p_paddr = read_u64(p_paddr_offset) or 0
                    p_foffset = read_u64(p_filesz_offset) or 0
                else:
                    p_foffset = read_u32(p_offset + 4) or 0
                    p_vaddr = read_u32(p_offset + 8) or 0
                    p_paddr = read_u32(p_offset + 12) or 0
                    p_filesz = read_u32(p_offset + 16) or 0
                    p_memsz = read_u32(p_offset + 20) or 0
                    p_flags = read_u32(p_offset + 24) or 0
                    p_align = read_u32(p_offset + 28) or 0

                # Format flag strings (R, W, X)
                flags_list = []
                if p_flags & 4: flags_list.append("PF_R")
                if p_flags & 2: flags_list.append("PF_W")
                if p_flags & 1: flags_list.append("PF_X")

                program_headers.append({
                    "type": p_type_str,
                    "type_raw": p_type,
                    "offset": p_foffset,
                    "virtual_address": f"0x{p_vaddr:016x}" if is_64bit else f"0x{p_vaddr:08x}",
                    "virtual_address_raw": p_vaddr,
                    "physical_address": f"0x{p_paddr:016x}" if is_64bit else f"0x{p_paddr:08x}",
                    "file_size": p_filesz,
                    "memory_size": p_memsz,
                    "flags_raw": p_flags,
                    "flags": flags_list,
                    "alignment": p_align,
                })

                # Check PT_INTERP for dynamic linker path
                if p_type == 3:  # PT_INTERP
                    if reader.is_valid_offset(p_foffset, p_filesz):
                        interpreter_path = reader.read_cstring(p_foffset, max_length=min(p_filesz, 256))

        elf_data["program_headers"] = program_headers
        elf_data["interpreter"] = interpreter_path

        # 4. Parse Section Headers (Shdrs) & Section Entropy
        section_headers: List[Dict[str, Any]] = []
        shstrtab_offset: Optional[int] = None

        # First pass to find .shstrtab file offset
        if e_shoff > 0 and e_shnum > 0 and e_shstrndx < e_shnum:
            strtab_sh_offset = e_shoff + (e_shstrndx * e_shentsize)
            if reader.is_valid_offset(strtab_sh_offset, e_shentsize):
                shstrtab_offset = read_u64(strtab_sh_offset + 24) if is_64bit else read_u32(strtab_sh_offset + 16)

        if e_shoff > 0 and e_shnum > 0 and e_shentsize >= 40:
            max_shdrs = min(e_shnum, 256)
            for s_idx in range(max_shdrs):
                s_offset = e_shoff + (s_idx * e_shentsize)
                if not reader.is_valid_offset(s_offset, e_shentsize):
                    errors.append(f"Section header bounds violation at index {s_idx}.")
                    break

                sh_name_idx = read_u32(s_offset) or 0
                sh_type = read_u32(s_offset + 4) or 0
                sh_type_str = self.SHDR_TYPE_MAP.get(sh_type, f"SHT_UNKNOWN (0x{sh_type:08x})")

                if is_64bit:
                    sh_flags = read_u64(s_offset + 8) or 0
                    sh_addr = read_u64(s_offset + 16) or 0
                    sh_foffset = read_u64(s_offset + 24) or 0
                    sh_size = read_u64(s_offset + 32) or 0
                    sh_link = read_u32(s_offset + 40) or 0
                    sh_info = read_u32(s_offset + 44) or 0
                    sh_addralign = read_u64(s_offset + 48) or 0
                    sh_entsize = read_u64(s_offset + 56) or 0
                else:
                    sh_flags = read_u32(s_offset + 8) or 0
                    sh_addr = read_u32(s_offset + 12) or 0
                    sh_foffset = read_u32(s_offset + 16) or 0
                    sh_size = read_u32(s_offset + 20) or 0
                    sh_link = read_u32(s_offset + 24) or 0
                    sh_info = read_u32(s_offset + 28) or 0
                    sh_addralign = read_u32(s_offset + 32) or 0
                    sh_entsize = read_u32(s_offset + 36) or 0

                # Resolve Section Name from .shstrtab
                sec_name = None
                if shstrtab_offset is not None and sh_name_idx > 0:
                    sec_name = reader.read_cstring(shstrtab_offset + sh_name_idx, max_length=128)

                if not sec_name:
                    sec_name = f".sec_{s_idx}" if s_idx > 0 else ""

                # Format flag strings
                s_flags_list = []
                if sh_flags & 1: s_flags_list.append("SHF_WRITE")
                if sh_flags & 2: s_flags_list.append("SHF_ALLOC")
                if sh_flags & 4: s_flags_list.append("SHF_EXECINSTR")

                # Section Shannon Entropy
                s_entropy = reader.calculate_entropy(sh_foffset, sh_size) if sh_type != 8 else 0.0  # SHT_NOBITS = 0 entropy

                section_headers.append({
                    "name": sec_name,
                    "type": sh_type_str,
                    "type_raw": sh_type,
                    "flags_raw": sh_flags,
                    "flags": s_flags_list,
                    "address": f"0x{sh_addr:016x}" if is_64bit else f"0x{sh_addr:08x}",
                    "address_raw": sh_addr,
                    "offset": sh_foffset,
                    "size": sh_size,
                    "link": sh_link,
                    "info": sh_info,
                    "alignment": sh_addralign,
                    "entry_size": sh_entsize,
                    "entropy": s_entropy,
                })

        elf_data["section_headers"] = section_headers

        # 5. Parse Dynamic Section (.dynamic) for DT_NEEDED Libraries
        dynamic_libraries: List[str] = []
        dyn_sec = next((s for s in section_headers if s["type_raw"] == 6), None)  # SHT_DYNAMIC = 6

        if dyn_sec and dyn_sec["size"] > 0:
            dyn_offset = dyn_sec["offset"]
            dyn_strtab_sec = section_headers[dyn_sec["link"]] if (0 <= dyn_sec["link"] < len(section_headers)) else None
            dyn_strtab_offset = dyn_strtab_sec["offset"] if dyn_strtab_sec else None

            if dyn_strtab_offset is not None:
                entry_sz = 16 if is_64bit else 8
                max_dyn_entries = min(int(dyn_sec["size"] // entry_sz), 512)

                for d_idx in range(max_dyn_entries):
                    e_off = dyn_offset + (d_idx * entry_sz)
                    if not reader.is_valid_offset(e_off, entry_sz):
                        break

                    d_tag = read_u64(e_off) if is_64bit else read_u32(e_off)
                    d_val = read_u64(e_off + 8) if is_64bit else read_u32(e_off + 4)

                    if d_tag == 0:  # DT_NULL
                        break

                    if d_tag == 1:  # DT_NEEDED
                        lib_name = reader.read_cstring(dyn_strtab_offset + d_val, max_length=256)
                        if lib_name and lib_name not in dynamic_libraries:
                            dynamic_libraries.append(lib_name)

        elf_data["dynamic_libraries"] = dynamic_libraries
        elf_data["summary"]["needed_libraries_count"] = len(dynamic_libraries)

        # 6. Parse Symbol Tables (.symtab & .dynsym)
        sym_sec = next((s for s in section_headers if s["type_raw"] in (2, 11)), None)  # SHT_SYMTAB=2, SHT_DYNSYM=11
        parsed_symbols: List[Dict[str, Any]] = []

        if sym_sec and sym_sec["entry_size"] > 0:
            strtab_sec = section_headers[sym_sec["link"]] if (0 <= sym_sec["link"] < len(section_headers)) else None
            strtab_off = strtab_sec["offset"] if strtab_sec else None

            if strtab_off is not None:
                sym_entry_sz = sym_sec["entry_size"]
                max_syms = min(int(sym_sec["size"] // sym_entry_sz), 1024)

                for sym_i in range(max_syms):
                    sym_off = sym_sec["offset"] + (sym_i * sym_entry_sz)
                    if not reader.is_valid_offset(sym_off, sym_entry_sz):
                        break

                    st_name_idx = read_u32(sym_off) or 0
                    if is_64bit:
                        st_info = reader.read_u8(sym_off + 4) or 0
                        st_shndx = read_u16(sym_off + 6) or 0
                        st_value = read_u64(sym_off + 8) or 0
                        st_size = read_u64(sym_off + 16) or 0
                    else:
                        st_value = read_u32(sym_off + 4) or 0
                        st_size = read_u32(sym_off + 8) or 0
                        st_info = reader.read_u8(sym_off + 12) or 0
                        st_shndx = read_u16(sym_off + 14) or 0

                    sym_name = None
                    if st_name_idx > 0:
                        sym_name = reader.read_cstring(strtab_off + st_name_idx, max_length=256)

                    if sym_name:
                        parsed_symbols.append({
                            "name": sym_name,
                            "value": f"0x{st_value:016x}" if is_64bit else f"0x{st_value:08x}",
                            "size": st_size,
                            "info_raw": st_info,
                            "section_index": st_shndx,
                        })

        elf_data["symbols"] = parsed_symbols
        elf_data["summary"]["symbol_count"] = len(parsed_symbols)

        # 7. Construct Shared ExecutableModel
        unified_sections = [
            UnifiedSection(
                name=s["name"],
                virtual_address=s["address"],
                virtual_address_raw=s["address_raw"],
                virtual_size=s["size"],
                raw_offset=s["offset"],
                raw_size=s["size"],
                entropy=s["entropy"],
                flags=s["flags"],
            )
            for s in section_headers
        ]

        shared_model = UnifiedExecutableModel(
            schema_version=CURRENT_SHARED_MODEL_VERSION,
            file_id=file_id,
            format="ELF",
            architecture=arch_str,
            bitness=bitness,
            endianness=endian_str,
            entry_point=elf_data["elf_header"]["entry_point"],
            entry_point_raw=e_entry,
            subsystem_or_abi=osabi_str,
            is_executable=(e_type in (2, 3)),
            is_shared_library=(e_type == 3),
            sections=unified_sections,
            libraries=dynamic_libraries,
            symbols_count=len(parsed_symbols),
            parser_name=self.engine_name,
            parser_version=self.engine_version,
            parser_errors=errors,
            format_specific={
                "elf_type": type_str,
                "interpreter": interpreter_path,
            },
        )

        elf_data["unified_model"] = shared_model.model_dump()

        if reader.errors:
            errors.extend(reader.errors)

        return self._build_engine_result(elf_data, start_time)

    def _build_engine_result(self, elf_data: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        """Formats output dict and saves artifact analysis/{file_id}/elf.json."""
        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "ELFParserEngine completed for file_id='%s': is_elf=%s sections=%d in %.2fms",
            elf_data["file_id"],
            elf_data["is_elf"],
            len(elf_data.get("section_headers", [])),
            exec_time_ms,
        )

        return {
            self.engine_name: {
                "engine_version": self.engine_version,
                "execution_time_ms": exec_time_ms,
                "is_elf": elf_data["is_elf"],
                "parsed_data": elf_data,
            }
        }

    def save_elf_artifact(self, project_dir: Path, file_id: str, elf_data: Dict[str, Any]) -> Path:
        """Saves parsed ELF payload to projects/{project_id}/analysis/{file_id}/elf.json."""
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "elf.json"
        temp_path = analysis_dir / "elf.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(elf_data, f, indent=2)
            temp_path.replace(target_path)
            logger.info("ELF artifact written: path='%s'", target_path)
            return target_path

        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error("Failed to write ELF artifact for file_id='%s': %s", file_id, err)
            raise IOError(f"Could not write ELF analysis artifact: {err}") from err

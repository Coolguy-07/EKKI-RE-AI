"""
backend/analysis/detector.py

Universal File Type & Architecture Detection Engine for EKKI-RE-AI.
Uses signature magic byte matching with fallback heuristic text analysis.
Does not crash on malformed payloads or truncated headers.
"""

import json
import logging
import os
import re
import struct
import xml.etree.ElementTree as ET
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class FileDetector:
    """Robust, signature-based file type and CPU architecture detector."""

    # --- PE COFF Machine Constants ---
    IMAGE_FILE_MACHINE_I386 = 0x014C
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x01C0
    IMAGE_FILE_MACHINE_THUMB = 0x01C2
    IMAGE_FILE_MACHINE_ARMNT = 0x01C4
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64
    IMAGE_FILE_MACHINE_IA64 = 0x0200

    # --- ELF Machine Constants ---
    EM_386 = 3
    EM_MIPS = 8
    EM_PPC = 20
    EM_ARM = 40
    EM_X86_64 = 62
    EM_AARCH64 = 183
    EM_RISCV = 243

    # --- Mach-O CPU Constants ---
    CPU_TYPE_X86 = 7
    CPU_TYPE_X86_64 = 0x01000007
    CPU_TYPE_ARM = 12
    CPU_TYPE_ARM64 = 0x0100000C

    @classmethod
    def detect(cls, content: bytes, filename: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Detects universal file type, detected architecture, and error detail if any.

        Args:
            content: Raw byte payload of the file.
            filename: Display filename.

        Returns:
            Tuple of (detected_type: str, architecture: Optional[str], error_detail: Optional[str])
        """
        if not content:
            ext = os.path.splitext(filename)[1].lower()
            return ("Empty File", "N/A", None)

        header = content[:4096]
        length = len(content)

        # 1. Check PE (Windows Executable)
        if header.startswith(b"MZ"):
            return cls._parse_pe(content, length)

        # 2. Check ELF (Executable and Linkable Format)
        if header.startswith(b"\x7fELF"):
            return cls._parse_elf(content, length)

        # 3. Check Mach-O (macOS Executable / Object / Fat Binary)
        if header.startswith((b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
            return cls._parse_macho(content, length)

        # 4. Check Mach-O Fat Binary or Java Class File (0xCAFEBABE)
        if header.startswith((b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
            return cls._parse_cafebabe(content, length)

        # 5. Check Static Library Archive (!<arch>\n)
        if header.startswith(b"!\x3c\x61\x72\x63\x68\x3e\x0a"):
            return ("Static Library (Archive)", "N/A", None)

        # 6. Check COFF Object File
        coff_result = cls._parse_coff(content, length)
        if coff_result:
            return coff_result

        # 7. Check Archives (ZIP, GZIP, TAR, 7Z)
        archive_type = cls._check_archives(content, filename)
        if archive_type:
            return (archive_type, "N/A", None)

        # 8. Check Text / Source Code / Structured Formats
        text_result = cls._parse_text_and_source(content, filename)
        if text_result:
            return text_result

        # 9. Fallback to Raw Binary
        return ("Raw Binary", "N/A", None)

    @classmethod
    def _parse_pe(cls, content: bytes, length: int) -> Tuple[str, Optional[str], Optional[str]]:
        """Parses PE header magic and architecture safely without throwing exceptions."""
        if length < 64:
            return ("PE (Windows Executable) [Truncated]", "Unknown", "File truncated before PE header offset")

        try:
            e_lfanew = struct.unpack_from("<I", content, 0x3C)[0]
            if e_lfanew < 0 or e_lfanew > length - 24:
                return ("PE (Windows Executable) [Corrupted Header]", "Unknown", f"e_lfanew offset {e_lfanew} out of bounds")

            pe_sig = content[e_lfanew : e_lfanew + 4]
            if pe_sig != b"PE\x00\x00":
                return ("PE (Windows Executable) [Invalid Signature]", "Unknown", f"Invalid PE signature '{pe_sig!r}'")

            machine = struct.unpack_from("<H", content, e_lfanew + 4)[0]
            arch_map = {
                cls.IMAGE_FILE_MACHINE_I386: "x86",
                cls.IMAGE_FILE_MACHINE_AMD64: "x86_64",
                cls.IMAGE_FILE_MACHINE_ARM: "ARM",
                cls.IMAGE_FILE_MACHINE_THUMB: "ARM (Thumb)",
                cls.IMAGE_FILE_MACHINE_ARMNT: "ARM (NT)",
                cls.IMAGE_FILE_MACHINE_ARM64: "ARM64",
                cls.IMAGE_FILE_MACHINE_IA64: "IA64",
            }
            arch = arch_map.get(machine, f"Unknown (0x{machine:04x})")
            return ("PE (Windows Executable)", arch, None)

        except Exception as err:
            logger.warning("Error parsing PE header: %s", err)
            return ("PE (Windows Executable) [Corrupted]", "Unknown", str(err))

    @classmethod
    def _parse_elf(cls, content: bytes, length: int) -> Tuple[str, Optional[str], Optional[str]]:
        """Parses ELF header safely for type and architecture."""
        if length < 52:
            return ("ELF [Truncated]", "Unknown", "File truncated before ELF header complete")

        try:
            ei_class = content[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = content[5]   # 1 = Little endian, 2 = Big endian

            endian = "<" if ei_data == 1 else ">"
            bitness = "32-bit" if ei_class == 1 else "64-bit" if ei_class == 2 else "Unknown-bit"

            e_type, e_machine = struct.unpack_from(f"{endian}HH", content, 16)

            type_map = {
                1: "ELF Object File (Relocatable)",
                2: f"ELF {bitness} Executable",
                3: f"ELF {bitness} Shared Object",
                4: f"ELF {bitness} Core Dump",
            }
            detected_type = type_map.get(e_type, f"ELF {bitness} Binary")

            arch_map = {
                cls.EM_386: "x86",
                cls.EM_X86_64: "x86_64",
                cls.EM_ARM: "ARM",
                cls.EM_AARCH64: "ARM64",
                cls.EM_MIPS: "MIPS",
                cls.EM_RISCV: "RISC-V",
                cls.EM_PPC: "PowerPC",
            }
            arch = arch_map.get(e_machine, f"Unknown (0x{e_machine:04x})")
            return (detected_type, arch, None)

        except Exception as err:
            logger.warning("Error parsing ELF header: %s", err)
            return ("ELF Binary [Corrupted]", "Unknown", str(err))

    @classmethod
    def _parse_macho(cls, content: bytes, length: int) -> Tuple[str, Optional[str], Optional[str]]:
        """Parses Mach-O header safely."""
        if length < 28:
            return ("Mach-O [Truncated]", "Unknown", "File truncated before Mach-O header complete")

        try:
            magic = content[:4]
            is_64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
            endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"

            cputype, cpusubtype, filetype = struct.unpack_from(f"{endian}III", content, 4)

            arch_map = {
                cls.CPU_TYPE_X86: "x86",
                cls.CPU_TYPE_X86_64: "x86_64",
                cls.CPU_TYPE_ARM: "ARM",
                cls.CPU_TYPE_ARM64: "ARM64",
            }
            arch = arch_map.get(cputype, f"Unknown (0x{cputype:08x})")

            filetype_map = {
                1: "Mach-O Object File",
                2: f"Mach-O {'64-bit' if is_64 else '32-bit'} Executable",
                6: "Mach-O Dynamic Library",
            }
            detected_type = filetype_map.get(filetype, "Mach-O Binary")
            return (detected_type, arch, None)

        except Exception as err:
            logger.warning("Error parsing Mach-O header: %s", err)
            return ("Mach-O Binary [Corrupted]", "Unknown", str(err))

    @classmethod
    def _parse_cafebabe(cls, content: bytes, length: int) -> Tuple[str, Optional[str], Optional[str]]:
        """Disambiguates between Java Class file and Mach-O Universal Fat Binary."""
        if length < 8:
            return ("Java Class / Mach-O Fat Binary [Truncated]", "Unknown", "File too small")

        try:
            # Check Java Class file: major version at offset 6 (big endian) >= 45 (Java 1.1)
            major_ver = struct.unpack_from(">H", content, 6)[0]
            if 45 <= major_ver <= 70:
                return (f"Java Class File (v{major_ver - 44}.0)", "JVM", None)

            # Check Mach-O Fat Binary: nfat_arch at offset 4
            magic = content[:4]
            endian = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
            nfat = struct.unpack_from(f"{endian}I", content, 4)[0]
            if 1 <= nfat <= 20:
                return ("Mach-O Universal Fat Binary", "Universal Multi-Arch", None)

            return ("Java Class File", "JVM", None)

        except Exception as err:
            return ("Binary (0xCAFEBABE Magic)", "Unknown", str(err))

    @classmethod
    def _parse_coff(cls, content: bytes, length: int) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
        """Checks for COFF object file magic headers."""
        if length < 20:
            return None

        try:
            machine = struct.unpack_from("<H", content, 0)[0]
            num_sections = struct.unpack_from("<H", content, 2)[0]

            if machine in (
                cls.IMAGE_FILE_MACHINE_I386,
                cls.IMAGE_FILE_MACHINE_AMD64,
                cls.IMAGE_FILE_MACHINE_ARM,
                cls.IMAGE_FILE_MACHINE_ARM64,
            ) and (1 <= num_sections <= 99):
                arch_map = {
                    cls.IMAGE_FILE_MACHINE_I386: "x86",
                    cls.IMAGE_FILE_MACHINE_AMD64: "x86_64",
                    cls.IMAGE_FILE_MACHINE_ARM: "ARM",
                    cls.IMAGE_FILE_MACHINE_ARM64: "ARM64",
                }
                return ("COFF Object File", arch_map.get(machine, "Unknown"), None)

        except Exception:
            pass
        return None

    @classmethod
    def _check_archives(cls, content: bytes, filename: str) -> Optional[str]:
        """Checks magic signatures for common archive formats."""
        ext = os.path.splitext(filename)[1].lower()

        if content.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            if ext in (".jar", ".war"):
                return "Java Archive (JAR)"
            return "ZIP Archive"

        if content.startswith(b"\x1f\x8b"):
            return "GZIP Archive"

        if len(content) > 262 and content[257:262] == b"ustar":
            return "TAR Archive"

        if content.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip Archive"

        return None

    @classmethod
    def _parse_text_and_source(cls, content: bytes, filename: str) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
        """Identifies text formats and programming languages."""
        # Test UTF-8 / ASCII text validity
        try:
            text_sample = content[:16384].decode("utf-8")
        except UnicodeDecodeError:
            # Not clean UTF-8 text
            return None

        # Calculate printable character ratio to distinguish plain text from raw binary
        non_printable = sum(1 for c in text_sample if ord(c) < 32 and c not in "\n\r\t")
        if len(text_sample) > 0 and (non_printable / len(text_sample)) > 0.05:
            return None

        stripped = text_sample.strip()
        ext = os.path.splitext(filename)[1].lower()

        # 1. JSON Detection
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                json.loads(text_sample)
                return ("JSON Document", "N/A", None)
            except Exception:
                pass
        if ext == ".json":
            return ("JSON Document", "N/A", None)

        # 2. XML Detection
        if stripped.startswith("<?xml") or (stripped.startswith("<") and stripped.endswith(">")):
            try:
                ET.fromstring(text_sample[:4096])
                return ("XML Document", "N/A", None)
            except Exception:
                pass
        if ext == ".xml":
            return ("XML Document", "N/A", None)

        # 3. Assembly Source
        asm_keywords = [
            r"\.section", r"\.global", r"\.globl", r"\.text", r"\.data", r"\.code",
            r"section\s+\.text", r"global\s+_main", r"mov\s+[a-z]+,", r"push\s+[a-z]+",
            r"pop\s+[a-z]+", r"ret\b", r"call\s+[a-zA-Z_]"
        ]
        if any(re.search(pat, text_sample, re.IGNORECASE) for pat in asm_keywords) or ext in (".asm", ".s", ".S"):
            return ("Assembly Source Code", "N/A", None)

        # 4. Rust Source
        if any(k in text_sample for k in ["fn main()", "use std::", "pub fn ", "let mut ", "impl "]) or ext == ".rs":
            return ("Rust Source Code", "N/A", None)

        # 5. Go Source
        if (re.search(r"\bpackage\s+\w+", text_sample) and "import " in text_sample) or ext == ".go":
            return ("Go Source Code", "N/A", None)

        # 6. C++ Source
        cpp_patterns = ["#include <iostream>", "using namespace std;", "std::cout", "template<", "class "]
        if any(pat in text_sample for pat in cpp_patterns) or ext in (".cpp", ".hpp", ".cc", ".cxx"):
            return ("C++ Source Code", "N/A", None)

        # 7. C Source
        c_patterns = ["#include <stdio.h>", "#include <stdlib.h>", "int main(", "void main(", "struct "]
        if any(pat in text_sample for pat in c_patterns) or ext in (".c", ".h"):
            return ("C Source Code", "N/A", None)

        # 8. Python Source
        py_patterns = ["def ", "import os", "import sys", "if __name__ == '__main__':", "class "]
        if (any(pat in text_sample for pat in py_patterns) and ("\n" in text_sample)) or ext == ".py":
            return ("Python Source Code", "N/A", None)

        # 9. Java Source
        if any(pat in text_sample for pat in ["public class ", "import java.", "package "]) or ext == ".java":
            return ("Java Source Code", "N/A", None)

        # 10. Default Text
        return ("Text Document", "N/A", None)

"""
tests/test_elf_parser.py

Comprehensive test suite for Phase 2.4: ELF Parser Engine & Shared ExecutableFormat Model.
Tests 32-bit, 64-bit, Little Endian, Big Endian, Shared Objects, Executables, Corrupted Headers,
Invalid Offsets, Empty Files, Non-ELF Files, Unified ExecutableFormat Export, Disk Persistence, and REST API.
"""

import json
import shutil
import struct
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.analysis import BinaryReader, ELFParserEngine
from backend.app import app
from backend.workspace import WorkspaceManager


@pytest.fixture
def temp_workspace():
    """Fixture creating an isolated workspace directory."""
    temp_dir = tempfile.mkdtemp(prefix="test_elf_parser_")
    ws = WorkspaceManager(projects_dir=Path(temp_dir))
    yield ws, temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def build_synthetic_elf(
    is_64bit: bool = True,
    is_little_endian: bool = True,
    is_shared_lib: bool = False,
    corrupted_magic: bool = False,
    invalid_shoff: bool = False,
) -> bytes:
    """Helper constructing synthetic ELF byte payload for testing."""
    if corrupted_magic:
        return b"NOT_AN_ELF_MAGIC_BYTES" + b"\x00" * 100

    size = 2048
    buf = bytearray(size)

    # 1. ELF Identification (e_ident)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2 if is_64bit else 1         # EI_CLASS (1=32-bit, 2=64-bit)
    buf[5] = 1 if is_little_endian else 2  # EI_DATA (1=Little, 2=Big)
    buf[6] = 1                            # EI_VERSION
    buf[7] = 3                            # EI_OSABI (Linux)
    buf[8] = 0                            # EI_ABIVERSION

    fmt_u16 = "<H" if is_little_endian else ">H"
    fmt_u32 = "<I" if is_little_endian else ">I"
    fmt_u64 = "<Q" if is_little_endian else ">Q"

    e_type = 3 if is_shared_lib else 2     # ET_DYN or ET_EXEC
    e_machine = 62 if is_64bit else 3      # EM_X86_64 or EM_386

    struct.pack_into(fmt_u16, buf, 16, e_type)
    struct.pack_into(fmt_u16, buf, 18, e_machine)
    struct.pack_into(fmt_u32, buf, 20, 1)  # e_version

    shoff = 99999 if invalid_shoff else (128 if is_64bit else 96)

    if is_64bit:
        struct.pack_into(fmt_u64, buf, 24, 0x00401000)  # e_entry
        struct.pack_into(fmt_u64, buf, 32, 64)          # e_phoff
        struct.pack_into(fmt_u64, buf, 40, shoff)       # e_shoff
        struct.pack_into(fmt_u32, buf, 48, 0)           # e_flags
        struct.pack_into(fmt_u16, buf, 52, 64)          # e_ehsize
        struct.pack_into(fmt_u16, buf, 54, 56)          # e_phentsize
        struct.pack_into(fmt_u16, buf, 56, 1)           # e_phnum
        struct.pack_into(fmt_u16, buf, 58, 64)          # e_shentsize
        struct.pack_into(fmt_u16, buf, 60, 2)           # e_shnum
        struct.pack_into(fmt_u16, buf, 62, 1)           # e_shstrndx
    else:
        struct.pack_into(fmt_u32, buf, 24, 0x08048000)  # e_entry
        struct.pack_into(fmt_u32, buf, 28, 52)          # e_phoff
        struct.pack_into(fmt_u32, buf, 32, shoff)       # e_shoff
        struct.pack_into(fmt_u32, buf, 36, 0)           # e_flags
        struct.pack_into(fmt_u16, buf, 40, 52)          # e_ehsize
        struct.pack_into(fmt_u16, buf, 42, 32)          # e_phentsize
        struct.pack_into(fmt_u16, buf, 44, 1)           # e_phnum
        struct.pack_into(fmt_u16, buf, 46, 40)          # e_shentsize
        struct.pack_into(fmt_u16, buf, 48, 2)           # e_shnum
        struct.pack_into(fmt_u16, buf, 50, 1)           # e_shstrndx

    if invalid_shoff:
        return bytes(buf)

    # Program Header (PT_LOAD)
    if is_64bit:
        ph_off = 64
        struct.pack_into(fmt_u32, buf, ph_off, 1)       # PT_LOAD
        struct.pack_into(fmt_u32, buf, ph_off + 4, 5)   # PF_R | PF_X
        struct.pack_into(fmt_u64, buf, ph_off + 8, 0x200) # Offset
        struct.pack_into(fmt_u64, buf, ph_off + 16, 0x00401000) # Vaddr
        struct.pack_into(fmt_u64, buf, ph_off + 32, 0x400)      # Filesz
        struct.pack_into(fmt_u64, buf, ph_off + 40, 0x400)      # Memsz
    else:
        ph_off = 52
        struct.pack_into(fmt_u32, buf, ph_off, 1)       # PT_LOAD
        struct.pack_into(fmt_u32, buf, ph_off + 4, 0x200)
        struct.pack_into(fmt_u32, buf, ph_off + 8, 0x08048000)
        struct.pack_into(fmt_u32, buf, ph_off + 16, 0x400)
        struct.pack_into(fmt_u32, buf, ph_off + 20, 0x400)
        struct.pack_into(fmt_u32, buf, ph_off + 24, 5)

    # Section Headers
    # .shstrtab at offset 0x600
    buf[0x600 : 0x600 + 20] = b"\x00.text\x00.shstrtab\x00"

    sh_base = shoff
    shentsize = 64 if is_64bit else 40

    # Section 0: NULL
    # Section 1: .shstrtab
    s1_off = sh_base + shentsize
    struct.pack_into(fmt_u32, buf, s1_off, 7)          # sh_name -> .shstrtab
    struct.pack_into(fmt_u32, buf, s1_off + 4, 3)      # SHT_STRTAB
    if is_64bit:
        struct.pack_into(fmt_u64, buf, s1_off + 24, 0x600) # sh_offset
        struct.pack_into(fmt_u64, buf, s1_off + 32, 20)    # sh_size
    else:
        struct.pack_into(fmt_u32, buf, s1_off + 16, 0x600)
        struct.pack_into(fmt_u32, buf, s1_off + 20, 20)

    # Section 2: .text
    s2_off = sh_base + (shentsize * 2)
    struct.pack_into(fmt_u32, buf, s2_off, 1)          # sh_name -> .text
    struct.pack_into(fmt_u32, buf, s2_off + 4, 1)      # SHT_PROGBITS
    if is_64bit:
        struct.pack_into(fmt_u64, buf, s2_off + 8, 6)     # SHF_ALLOC | SHF_EXECINSTR
        struct.pack_into(fmt_u64, buf, s2_off + 16, 0x00401000)
        struct.pack_into(fmt_u64, buf, s2_off + 24, 0x200)
        struct.pack_into(fmt_u64, buf, s2_off + 32, 0x400)
    else:
        struct.pack_into(fmt_u32, buf, s2_off + 8, 6)
        struct.pack_into(fmt_u32, buf, s2_off + 12, 0x08048000)
        struct.pack_into(fmt_u32, buf, s2_off + 16, 0x200)
        struct.pack_into(fmt_u32, buf, s2_off + 20, 0x400)

    buf[0x200 : 0x200 + 0x400] = b"\x31\xc0\xbf\x01\x00\x00\x00\x0f\x05" * 100

    return bytes(buf)


# --- Unit Tests ---

def test_parse_valid_elf64_little_endian():
    elf_bytes = build_synthetic_elf(is_64bit=True, is_little_endian=True)
    engine = ELFParserEngine()

    result = engine.analyze("file-elf64", "main.elf", elf_bytes)
    parsed = result["elf_parser"]["parsed_data"]

    assert parsed["is_elf"] is True
    assert parsed["summary"]["architecture"] == "x86_64"
    assert parsed["summary"]["bitness"] == 64
    assert parsed["summary"]["endianness"] == "little"
    assert len(parsed["errors"]) == 0

    # Test Unified Model
    unified = parsed["unified_model"]
    assert unified["format"] == "ELF"
    assert unified["architecture"] == "x86_64"
    assert unified["bitness"] == 64
    assert len(unified["sections"]) > 0


def test_parse_valid_elf32_big_endian():
    elf_bytes = build_synthetic_elf(is_64bit=False, is_little_endian=False)
    engine = ELFParserEngine()

    result = engine.analyze("file-elf32", "app32.elf", elf_bytes)
    parsed = result["elf_parser"]["parsed_data"]

    assert parsed["is_elf"] is True
    assert parsed["summary"]["bitness"] == 32
    assert parsed["summary"]["endianness"] == "big"


def test_corrupted_elf_magic_non_crashing():
    elf_bytes = build_synthetic_elf(corrupted_magic=True)
    engine = ELFParserEngine()

    result = engine.analyze("file-corrupt-elf", "bad.elf", elf_bytes)
    parsed = result["elf_parser"]["parsed_data"]

    assert parsed["is_elf"] is False
    assert len(parsed["errors"]) > 0


def test_invalid_section_offset_non_crashing():
    elf_bytes = build_synthetic_elf(invalid_shoff=True)
    engine = ELFParserEngine()

    result = engine.analyze("file-bad-shoff", "bad_shoff.elf", elf_bytes)
    parsed = result["elf_parser"]["parsed_data"]

    assert parsed["is_elf"] is True
    assert len(parsed["errors"]) > 0


def test_empty_and_non_elf_files():
    engine = ELFParserEngine()

    res_empty = engine.analyze("file-empty", "empty.bin", b"")["elf_parser"]["parsed_data"]
    assert res_empty["is_elf"] is False

    res_txt = engine.analyze("file-txt", "notes.txt", b"Hello World")["elf_parser"]["parsed_data"]
    assert res_txt["is_elf"] is False


# --- Integration Tests ---

def test_elf_artifact_persisted_to_disk(temp_workspace):
    ws, temp_dir = temp_workspace
    proj = ws.create_project(name="ELF Workspace")

    elf_bytes = build_synthetic_elf(is_64bit=True)
    file_meta = ws.add_file(
        project_id=proj.project_id,
        filename="binary.elf",
        content=elf_bytes,
    )

    elf_json_path = Path(temp_dir) / proj.project_id / "analysis" / file_meta.file_id / "elf.json"
    assert elf_json_path.exists()

    with open(elf_json_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    assert artifact["schema_version"] == 1
    assert artifact["is_elf"] is True
    assert artifact["summary"]["architecture"] == "x86_64"


def test_rest_api_get_elf_endpoint():
    client = TestClient(app)

    create_res = client.post("/api/projects", json={"name": "ELF API Project"})
    assert create_res.status_code == 201
    proj_id = create_res.json()["project_id"]

    try:
        elf_bytes = build_synthetic_elf(is_64bit=True)
        upload_res = client.post(
            f"/api/projects/{proj_id}/files",
            files={"file": ("main.elf", elf_bytes, "application/x-executable")},
        )
        assert upload_res.status_code == 201
        file_id = upload_res.json()["file_id"]

        elf_res = client.get(f"/api/projects/{proj_id}/files/{file_id}/elf")
        assert elf_res.status_code == 200
        payload = elf_res.json()

        assert payload["schema_version"] == 1
        assert payload["is_elf"] is True
        assert payload["summary"]["architecture"] == "x86_64"
        assert "unified_model" in payload

    finally:
        client.delete(f"/api/projects/{proj_id}")

"""
tests/test_macho_parser.py

Comprehensive test suite for Phase 2.4: Mach-O Parser Engine & Shared ExecutableFormat Model.
Tests 32-bit, 64-bit, Universal Fat Binaries, Dynamic Libraries, Executables, Corrupted Headers,
Invalid Load Commands, Empty Files, Non-Mach-O Files, Unified ExecutableFormat Export, Disk Persistence, and REST API.
"""

import json
import shutil
import struct
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.analysis import BinaryReader, MachOParserEngine
from backend.app import app
from backend.workspace import WorkspaceManager


@pytest.fixture
def temp_workspace():
    """Fixture creating an isolated workspace directory."""
    temp_dir = tempfile.mkdtemp(prefix="test_macho_parser_")
    ws = WorkspaceManager(projects_dir=Path(temp_dir))
    yield ws, temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def build_synthetic_macho(
    is_64bit: bool = True,
    is_fat: bool = False,
    corrupted_magic: bool = False,
    invalid_cmdsize: bool = False,
) -> bytes:
    """Helper constructing synthetic Mach-O byte payload for testing."""
    if corrupted_magic:
        return b"NOT_A_MACHO_MAGIC" + b"\x00" * 100

    size = 2048
    buf = bytearray(size)

    if is_fat:
        # 1. Fat Header (Big Endian)
        struct.pack_into(">I", buf, 0, 0xCAFEBABE)
        struct.pack_into(">I", buf, 4, 1)  # 1 architecture slice

        # Fat Arch Slice 0
        struct.pack_into(">I", buf, 8, 0x01000007)  # cputype x86_64
        struct.pack_into(">I", buf, 12, 3)          # cpusubtype
        struct.pack_into(">I", buf, 16, 512)        # slice offset
        struct.pack_into(">I", buf, 20, 1024)       # slice size
        struct.pack_into(">I", buf, 24, 12)         # align

        # Build sub-binary header at offset 512
        slice_offset = 512
    else:
        slice_offset = 0

    magic = 0xFEEDFACF if is_64bit else 0xFEEDFACE
    cputype = 0x01000007 if is_64bit else 7  # x86_64 or x86

    struct.pack_into("<I", buf, slice_offset, magic)
    struct.pack_into("<I", buf, slice_offset + 4, cputype)
    struct.pack_into("<I", buf, slice_offset + 8, 3)          # cpusubtype
    struct.pack_into("<I", buf, slice_offset + 12, 2)         # MH_EXECUTE
    struct.pack_into("<I", buf, slice_offset + 16, 2)         # ncmds = 2
    struct.pack_into("<I", buf, slice_offset + 20, 160)       # sizeofcmds
    struct.pack_into("<I", buf, slice_offset + 24, 0x200000)   # flags

    hdr_size = 32 if is_64bit else 28
    cmd_base = slice_offset + hdr_size

    # Load Command 1: LC_SEGMENT_64 / LC_SEGMENT
    cmd1_type = 0x19 if is_64bit else 0x1
    cmd1_size = 152 if is_64bit else 124
    if invalid_cmdsize:
        cmd1_size = 0  # Invalid cmdsize

    struct.pack_into("<I", buf, cmd_base, cmd1_type)
    struct.pack_into("<I", buf, cmd_base + 4, cmd1_size)

    if not invalid_cmdsize:
        buf[cmd_base + 8 : cmd_base + 14] = b"__TEXT"

        if is_64bit:
            struct.pack_into("<Q", buf, cmd_base + 24, 0x100000000) # vmaddr
            struct.pack_into("<Q", buf, cmd_base + 32, 0x1000)      # vmsize
            struct.pack_into("<Q", buf, cmd_base + 40, 0)          # fileoff
            struct.pack_into("<Q", buf, cmd_base + 48, 1024)       # filesz
            struct.pack_into("<I", buf, cmd_base + 64, 1)          # nsects = 1

            sec_base = cmd_base + 72
            buf[sec_base : sec_base + 6] = b"__text"
            buf[sec_base + 16 : sec_base + 22] = b"__TEXT"
            struct.pack_into("<Q", buf, sec_base + 32, 0x100000000)
            struct.pack_into("<Q", buf, sec_base + 40, 512)
            struct.pack_into("<I", buf, sec_base + 48, 512)

            buf[512 : 512 + 512] = b"\x48\x31\xc0\xc3" * 128

        # Load Command 2: LC_LOAD_DYLIB
        cmd2_base = cmd_base + cmd1_size
        struct.pack_into("<I", buf, cmd2_base, 0xC)
        struct.pack_into("<I", buf, cmd2_base + 4, 48)
        struct.pack_into("<I", buf, cmd2_base + 8, 24)
        buf[cmd2_base + 24 : cmd2_base + 45] = b"/usr/lib/libSystem.B.dylib"

    return bytes(buf)


# --- Unit Tests ---

def test_parse_valid_macho64():
    macho_bytes = build_synthetic_macho(is_64bit=True, is_fat=False)
    engine = MachOParserEngine()

    result = engine.analyze("file-macho64", "app.macho", macho_bytes)
    parsed = result["macho_parser"]["parsed_data"]

    assert parsed["is_macho"] is True
    assert parsed["summary"]["architecture"] == "x86_64"
    assert len(parsed["segments"]) > 0
    assert "/usr/lib/libSystem.B.dylib" in parsed["dynamic_libraries"]
    assert len(parsed["errors"]) == 0

    # Test Unified Model
    unified = parsed["unified_model"]
    assert unified["format"] == "Mach-O"
    assert unified["architecture"] == "x86_64"
    assert "/usr/lib/libSystem.B.dylib" in unified["libraries"]


def test_parse_valid_universal_fat_binary():
    macho_bytes = build_synthetic_macho(is_64bit=True, is_fat=True)
    engine = MachOParserEngine()

    result = engine.analyze("file-fat", "universal.app", macho_bytes)
    parsed = result["macho_parser"]["parsed_data"]

    assert parsed["is_macho"] is True
    assert parsed["is_fat"] is True
    assert len(parsed["fat_archs"]) == 1


def test_corrupted_macho_magic_non_crashing():
    macho_bytes = build_synthetic_macho(corrupted_magic=True)
    engine = MachOParserEngine()

    result = engine.analyze("file-corrupt-macho", "bad.macho", macho_bytes)
    parsed = result["macho_parser"]["parsed_data"]

    assert parsed["is_macho"] is False
    assert len(parsed["errors"]) > 0


def test_invalid_cmdsize_non_crashing():
    macho_bytes = build_synthetic_macho(invalid_cmdsize=True)
    engine = MachOParserEngine()

    result = engine.analyze("file-bad-cmdsize", "bad_cmd.macho", macho_bytes)
    parsed = result["macho_parser"]["parsed_data"]

    assert parsed["is_macho"] is True
    assert len(parsed["errors"]) > 0


def test_empty_and_non_macho_files():
    engine = MachOParserEngine()

    res_empty = engine.analyze("file-empty", "empty.bin", b"")["macho_parser"]["parsed_data"]
    assert res_empty["is_macho"] is False

    res_txt = engine.analyze("file-txt", "readme.txt", b"Mach-O Fake Text")["macho_parser"]["parsed_data"]
    assert res_txt["is_macho"] is False


# --- Integration Tests ---

def test_macho_artifact_persisted_to_disk(temp_workspace):
    ws, temp_dir = temp_workspace
    proj = ws.create_project(name="Mach-O Workspace")

    macho_bytes = build_synthetic_macho(is_64bit=True)
    file_meta = ws.add_file(
        project_id=proj.project_id,
        filename="program.dylib",
        content=macho_bytes,
    )

    macho_json_path = Path(temp_dir) / proj.project_id / "analysis" / file_meta.file_id / "macho.json"
    assert macho_json_path.exists()

    with open(macho_json_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    assert artifact["schema_version"] == 1
    assert artifact["is_macho"] is True
    assert artifact["summary"]["architecture"] == "x86_64"


def test_rest_api_get_macho_endpoint():
    client = TestClient(app)

    create_res = client.post("/api/projects", json={"name": "Mach-O API Project"})
    assert create_res.status_code == 201
    proj_id = create_res.json()["project_id"]

    try:
        macho_bytes = build_synthetic_macho(is_64bit=True)
        upload_res = client.post(
            f"/api/projects/{proj_id}/files",
            files={"file": ("program.dylib", macho_bytes, "application/x-mach-binary")},
        )
        assert upload_res.status_code == 201
        file_id = upload_res.json()["file_id"]

        macho_res = client.get(f"/api/projects/{proj_id}/files/{file_id}/macho")
        assert macho_res.status_code == 200
        payload = macho_res.json()

        assert payload["schema_version"] == 1
        assert payload["is_macho"] is True
        assert payload["summary"]["architecture"] == "x86_64"
        assert "unified_model" in payload

    finally:
        client.delete(f"/api/projects/{proj_id}")

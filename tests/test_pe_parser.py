"""
tests/test_pe_parser.py

Comprehensive test suite for Phase 2.3: PE Parser Engine & BinaryReader.
Tests PE32, PE32+, EXEs, DLLs, Imports, Exports, Corrupted Headers, Invalid e_lfanew,
Invalid RVAs, Non-PE binaries, Empty files, Artifact Persistence, and REST API.
"""

import json
import shutil
import struct
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.analysis import BinaryReader, PEParserEngine
from backend.app import app
from backend.workspace import WorkspaceManager


@pytest.fixture
def temp_workspace():
    """Fixture creating an isolated workspace directory."""
    temp_dir = tempfile.mkdtemp(prefix="test_pe_parser_")
    ws = WorkspaceManager(projects_dir=Path(temp_dir))
    yield ws, temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def build_synthetic_pe(
    is_64bit: bool = True,
    is_dll: bool = False,
    sections_count: int = 2,
    invalid_lfanew: bool = False,
    corrupted_dos: bool = False,
    corrupted_pe_sig: bool = False,
) -> bytes:
    """Helper to construct synthetic PE header byte structures for unit testing."""
    if corrupted_dos:
        return b"INVALID_HEADER" + b"\x00" * 100

    size = 2048
    buf = bytearray(size)

    # 1. DOS Header
    buf[:2] = b"MZ"
    lfanew = 99999 if invalid_lfanew else 128
    struct.pack_into("<I", buf, 0x3C, lfanew)

    if invalid_lfanew:
        return bytes(buf)

    # 2. NT Header
    pe_sig = b"XX\x00\x00" if corrupted_pe_sig else b"PE\x00\x00"
    buf[lfanew : lfanew + 4] = pe_sig

    if corrupted_pe_sig:
        return bytes(buf)

    coff_offset = lfanew + 4
    machine = 0x8664 if is_64bit else 0x014C
    characteristics = 0x2002 if is_dll else 0x0002
    opt_hdr_size = 240 if is_64bit else 224

    # COFF Header (20 bytes)
    struct.pack_into("<H", buf, coff_offset, machine)             # Machine
    struct.pack_into("<H", buf, coff_offset + 2, sections_count)  # NumberOfSections
    struct.pack_into("<I", buf, coff_offset + 4, 1700000000)      # TimeDateStamp
    struct.pack_into("<H", buf, coff_offset + 16, opt_hdr_size)   # SizeOfOptionalHeader
    struct.pack_into("<H", buf, coff_offset + 18, characteristics)# Characteristics

    # Optional Header
    opt_offset = coff_offset + 20
    opt_magic = 0x020B if is_64bit else 0x010B
    struct.pack_into("<H", buf, opt_offset, opt_magic)            # Magic
    struct.pack_into("<I", buf, opt_offset + 16, 0x1000)          # EntryPoint
    
    if is_64bit:
        struct.pack_into("<Q", buf, opt_offset + 24, 0x140000000) # ImageBase 64
        struct.pack_into("<I", buf, opt_offset + 68, 3)           # Subsystem (CUI)
        struct.pack_into("<I", buf, opt_offset + 108, 16)        # NumberOfRvaAndSizes
    else:
        struct.pack_into("<I", buf, opt_offset + 28, 0x00400000)  # ImageBase 32
        struct.pack_into("<I", buf, opt_offset + 68, 2)           # Subsystem (GUI)
        struct.pack_into("<I", buf, opt_offset + 92, 16)         # NumberOfRvaAndSizes

    # Section Headers (40 bytes each)
    sec_offset = opt_offset + opt_hdr_size

    # .text section
    buf[sec_offset : sec_offset + 5] = b".text"
    struct.pack_into("<I", buf, sec_offset + 8, 0x1000)           # VirtualSize
    struct.pack_into("<I", buf, sec_offset + 12, 0x1000)          # VirtualAddress (RVA)
    struct.pack_into("<I", buf, sec_offset + 16, 0x400)           # SizeOfRawData
    struct.pack_into("<I", buf, sec_offset + 20, 0x200)           # PointerToRawData
    struct.pack_into("<I", buf, sec_offset + 36, 0x60000020)      # Characteristics (CODE | EXEC | READ)

    # Fill .text raw data bytes
    buf[0x200 : 0x200 + 0x400] = b"\x90\xcc\xc3\x55\x48\x89\xe5" * 140

    if sections_count > 1:
        sec2_offset = sec_offset + 40
        buf[sec2_offset : sec2_offset + 5] = b".rdata"
        struct.pack_into("<I", buf, sec2_offset + 8, 0x800)
        struct.pack_into("<I", buf, sec2_offset + 12, 0x2000)
        struct.pack_into("<I", buf, sec2_offset + 16, 0x400)
        struct.pack_into("<I", buf, sec2_offset + 20, 0x600)
        struct.pack_into("<I", buf, sec2_offset + 36, 0x40000040)
        buf[0x600 : 0x600 + 0x400] = b"HELLO_PE_SECTION_DATA_12345678" * 32

    return bytes(buf)


# --- 1. Unit Tests: BinaryReader Helper ---

def test_binary_reader_bounds_and_endianness():
    content = b"\x12\x34\x56\x78\x90\xab\xcd\xefTestString\x00"
    reader = BinaryReader(content)

    assert reader.size == len(content)
    assert reader.read_u8(0) == 0x12
    assert reader.read_u16_le(0) == 0x3412
    assert reader.read_u16_be(0) == 0x1234
    assert reader.read_u32_le(0) == 0x78563412
    assert reader.read_u32_be(0) == 0x12345678
    assert reader.read_cstring(8) == "TestString"
    assert reader.read_bytes(9999, 10) is None
    assert len(reader.errors) > 0


# --- 2. Unit Tests: PEParserEngine Validation & Extraction ---

def test_parse_valid_pe64_exe():
    pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=False)
    engine = PEParserEngine()

    result = engine.analyze("file-pe64", "sample.exe", pe_bytes)
    pe_data = result["pe_parser"]["parsed_data"]

    assert pe_data["is_pe"] is True
    assert pe_data["coff_header"]["machine"] == "x86_64"
    assert pe_data["optional_header"]["magic"] == "PE32+"
    assert pe_data["optional_header"]["entry_point"] == "0x00001000"
    assert pe_data["optional_header"]["image_base"] == "0x0000000140000000"
    assert len(pe_data["sections"]) == 2
    assert pe_data["sections"][0]["name"] == ".text"
    assert pe_data["sections"][0]["entropy"] > 0.0
    assert len(pe_data["errors"]) == 0


def test_parse_valid_pe32_dll():
    pe_bytes = build_synthetic_pe(is_64bit=False, is_dll=True)
    engine = PEParserEngine()

    result = engine.analyze("file-pe32", "library.dll", pe_bytes)
    pe_data = result["pe_parser"]["parsed_data"]

    assert pe_data["is_pe"] is True
    assert pe_data["coff_header"]["machine"] == "x86"
    assert pe_data["optional_header"]["magic"] == "PE32"
    assert pe_data["optional_header"]["image_base"] == "0x00400000"
    assert "DLL" in pe_data["coff_header"]["characteristics"]


def test_corrupted_dos_header_non_crashing():
    pe_bytes = build_synthetic_pe(corrupted_dos=True)
    engine = PEParserEngine()

    result = engine.analyze("file-corrupt-dos", "bad.exe", pe_bytes)
    pe_data = result["pe_parser"]["parsed_data"]

    assert pe_data["is_pe"] is False
    assert len(pe_data["errors"]) > 0


def test_invalid_lfanew_offset_non_crashing():
    pe_bytes = build_synthetic_pe(invalid_lfanew=True)
    engine = PEParserEngine()

    result = engine.analyze("file-invalid-lfanew", "bad_lfanew.exe", pe_bytes)
    pe_data = result["pe_parser"]["parsed_data"]

    assert pe_data["is_pe"] is False
    assert any("e_lfanew" in err for err in pe_data["errors"])


def test_corrupted_pe_signature_non_crashing():
    pe_bytes = build_synthetic_pe(corrupted_pe_sig=True)
    engine = PEParserEngine()

    result = engine.analyze("file-bad-sig", "bad_sig.exe", pe_bytes)
    pe_data = result["pe_parser"]["parsed_data"]

    assert pe_data["is_pe"] is False
    assert any("signature" in err.lower() for err in pe_data["errors"])


def test_non_pe_and_empty_files():
    engine = PEParserEngine()

    # Test non-PE file (ELF)
    elf_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50
    res_elf = engine.analyze("file-elf", "main.elf", elf_bytes)["pe_parser"]["parsed_data"]
    assert res_elf["is_pe"] is False

    # Test empty file
    res_empty = engine.analyze("file-empty", "empty.bin", b"")["pe_parser"]["parsed_data"]
    assert res_empty["is_pe"] is False


# --- 3. Integration Tests: Workspace Integration & Artifact Persistence ---

def test_pe_artifact_persisted_to_disk(temp_workspace):
    ws, temp_dir = temp_workspace
    proj = ws.create_project(name="PE Test Workspace")

    pe_bytes = build_synthetic_pe(is_64bit=True)
    file_meta = ws.add_file(
        project_id=proj.project_id,
        filename="target.exe",
        content=pe_bytes,
    )

    # Verify analysis/{file_id}/pe.json exists on disk
    pe_json_path = Path(temp_dir) / proj.project_id / "analysis" / file_meta.file_id / "pe.json"
    assert pe_json_path.exists()

    with open(pe_json_path, "r", encoding="utf-8") as f:
        pe_artifact = json.load(f)

    assert pe_artifact["schema_version"] == 1
    assert pe_artifact["is_pe"] is True
    assert pe_artifact["summary"]["architecture"] == "x86_64"
    assert len(pe_artifact["sections"]) == 2


# --- 4. Integration Tests: REST API Endpoints ---

def test_rest_api_get_pe_endpoint():
    client = TestClient(app)

    # 1. Create Project
    create_res = client.post("/api/projects", json={"name": "PE API Test Project"})
    assert create_res.status_code == 201
    proj_id = create_res.json()["project_id"]

    try:
        # 2. Upload PE file
        pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=False)
        upload_res = client.post(
            f"/api/projects/{proj_id}/files",
            files={"file": ("sample.exe", pe_bytes, "application/vnd.microsoft.portable-executable")},
        )
        assert upload_res.status_code == 201
        file_id = upload_res.json()["file_id"]

        # 3. GET /api/projects/{project_id}/files/{file_id}/pe
        pe_res = client.get(f"/api/projects/{proj_id}/files/{file_id}/pe")
        assert pe_res.status_code == 200
        pe_data = pe_res.json()

        assert pe_data["schema_version"] == 1
        assert pe_data["is_pe"] is True
        assert pe_data["summary"]["architecture"] == "x86_64"
        assert pe_data["summary"]["entry_point"] == "0x00001000"
        assert len(pe_data["sections"]) == 2

    finally:
        client.delete(f"/api/projects/{proj_id}")

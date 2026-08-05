"""
tests/test_binary_intelligence.py

Comprehensive test suite for Phase 2.2: Binary Intelligence Layer.
Tests plugin architecture, magic-byte detection, architecture identification,
entropy calculation, hash generation, error handling, metadata persistence,
and REST API endpoints.
"""

import hashlib
import json
import os
import shutil
import struct
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.analysis import (
    BaseAnalysisEngine,
    BinaryIntelligenceEngine,
    BinaryMetadata,
    SchemaVersion,
    analysis_pipeline,
)
from backend.analysis.detector import FileDetector
from backend.app import app
from backend.workspace import WorkspaceManager, workspace_manager


@pytest.fixture
def temp_workspace():
    """Fixture creating an isolated workspace directory."""
    temp_dir = tempfile.mkdtemp(prefix="test_binary_intel_")
    ws = WorkspaceManager(projects_dir=Path(temp_dir))
    yield ws, temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


# --- 1. Unit Tests: Hash & Entropy Verification ---

def test_single_pass_hashes_and_entropy():
    engine = BinaryIntelligenceEngine()
    data = b"Hello, Reverse Engineering World! 12345"

    res = engine.analyze(
        file_id="file-test1",
        filename="test.txt",
        content=data,
    )

    assert res["md5"] == hashlib.md5(data).hexdigest()
    assert res["sha1"] == hashlib.sha1(data).hexdigest()
    assert res["sha256"] == hashlib.sha256(data).hexdigest()
    assert res["sha512"] == hashlib.sha512(data).hexdigest()
    assert res["file_size"] == len(data)
    assert res["schema_version"] == 1
    assert 0.0 < res["entropy"] < 8.0
    assert res["status"] == "analyzed"


def test_empty_file_handling():
    engine = BinaryIntelligenceEngine()
    data = b""

    res = engine.analyze(
        file_id="file-empty",
        filename="empty.bin",
        content=data,
    )

    assert res["file_size"] == 0
    assert res["entropy"] == 0.0
    assert res["md5"] == hashlib.md5(b"").hexdigest()
    assert res["detected_type"] == "Empty File"
    assert res["detected_architecture"] == "N/A"
    assert res["status"] == "analyzed"


def test_very_small_file():
    engine = BinaryIntelligenceEngine()
    data = b"\x7f"

    res = engine.analyze(
        file_id="file-small",
        filename="small.bin",
        content=data,
    )

    assert res["file_size"] == 1
    assert res["entropy"] == 0.0
    assert res["status"] == "analyzed"


def test_high_entropy_random_bytes():
    engine = BinaryIntelligenceEngine()
    # Uniformly distributed bytes across 0x00-0xFF -> Max entropy ~ 8.0
    data = bytes(i % 256 for i in range(1024))

    res = engine.analyze(
        file_id="file-random",
        filename="random.dat",
        content=data,
    )

    assert res["entropy"] == 8.0


def test_markdown_file_detection_and_entropy():
    engine = BinaryIntelligenceEngine()
    # 5.67 KB synthetic Markdown text payload
    md_content = (
        "# EKKI-RE-AI Reverse Engineering Report\n\n"
        "## Summary of Binary Analysis\n\n"
        "The uploaded binary file was analyzed using the universal intelligence pipeline.\n"
        "- MD5: c4ca4238a0b923820dcc509a6f75849b\n"
        "- SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n"
        "```python\ndef analyze():\n    return 'Analyzed'\n```\n"
    ).encode("utf-8") * 15  # ~5.67 KB

    res = engine.analyze(
        file_id="file-md-doc",
        filename="README.md",
        content=md_content,
    )

    assert res["file_size"] == len(md_content)
    assert res["detected_type"] == "Markdown Document"
    assert res["detected_architecture"] == "N/A"
    assert res["status"] == "analyzed"
    assert 4.0 < res["entropy"] < 6.0
    assert len(res["md5"]) == 32
    assert len(res["sha1"]) == 40
    assert len(res["sha256"]) == 64
    assert len(res["sha512"]) == 128


# --- 2. Unit Tests: File Type Signature & Architecture Detection ---

def test_pe_x86_64_detection():
    # Construct minimal valid PE header for x86_64
    pe_header = bytearray(512)
    pe_header[:2] = b"MZ"
    struct.pack_into("<I", pe_header, 0x3C, 0x80)  # e_lfanew = 0x80
    pe_header[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", pe_header, 0x84, 0x8664)  # Machine = AMD64 (x86_64)

    det_type, arch, err = FileDetector.detect(bytes(pe_header), "test.exe")
    assert det_type == "PE (Windows Executable)"
    assert arch == "x86_64"
    assert err is None


def test_pe_x86_detection():
    pe_header = bytearray(512)
    pe_header[:2] = b"MZ"
    struct.pack_into("<I", pe_header, 0x3C, 0x80)
    pe_header[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", pe_header, 0x84, 0x014C)  # Machine = i386 (x86)

    det_type, arch, err = FileDetector.detect(bytes(pe_header), "sample.dll")
    assert det_type == "PE (Windows Executable)"
    assert arch == "x86"
    assert err is None


def test_elf_x86_64_detection():
    elf_header = bytearray(64)
    elf_header[:4] = b"\x7fELF"
    elf_header[4] = 2  # 64-bit
    elf_header[5] = 1  # Little endian
    struct.pack_into("<H", elf_header, 16, 2)   # e_type = ET_EXEC
    struct.pack_into("<H", elf_header, 18, 62)  # e_machine = EM_X86_64

    det_type, arch, err = FileDetector.detect(bytes(elf_header), "binary.elf")
    assert "ELF 64-bit Executable" in det_type
    assert arch == "x86_64"
    assert err is None


def test_elf_arm64_object_detection():
    elf_header = bytearray(64)
    elf_header[:4] = b"\x7fELF"
    elf_header[4] = 2   # 64-bit
    elf_header[5] = 1   # Little endian
    struct.pack_into("<H", elf_header, 16, 1)    # e_type = ET_REL (Object File)
    struct.pack_into("<H", elf_header, 18, 183)  # e_machine = EM_AARCH64 (ARM64)

    det_type, arch, err = FileDetector.detect(bytes(elf_header), "module.o")
    assert det_type == "ELF Object File (Relocatable)"
    assert arch == "ARM64"
    assert err is None


def test_macho_64bit_detection():
    macho_header = bytearray(32)
    macho_header[:4] = b"\xcf\xfa\xed\xfe"  # Mach-O 64-bit MH_CIGAM_64
    struct.pack_into("<I", macho_header, 4, 0x01000007)  # CPU = x86_64
    struct.pack_into("<I", macho_header, 12, 2)           # Filetype = MH_EXECUTE

    det_type, arch, err = FileDetector.detect(bytes(macho_header), "macho_bin")
    assert "Mach-O" in det_type
    assert arch == "x86_64"
    assert err is None


def test_static_library_archive_detection():
    data = b"!\x3c\x61\x72\x63\x68\x3e\x0a/               0           0     0     64        `\n"
    det_type, arch, err = FileDetector.detect(data, "libsample.a")
    assert det_type == "Static Library (Archive)"
    assert arch == "N/A"


def test_archives_zip_gzip_tar():
    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00"
    det_type, _, _ = FileDetector.detect(zip_bytes, "archive.zip")
    assert det_type == "ZIP Archive"

    gzip_bytes = b"\x1f\x8b\x08\x00\x00\x00\x00\x00"
    det_type, _, _ = FileDetector.detect(gzip_bytes, "data.tar.gz")
    assert det_type == "GZIP Archive"


def test_java_class_detection():
    java_class = bytearray(10)
    java_class[:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">H", java_class, 6, 52)  # Major version 52 (Java 8)

    det_type, arch, _ = FileDetector.detect(bytes(java_class), "App.class")
    assert "Java Class File" in det_type
    assert arch == "JVM"


def test_source_code_detection():
    c_code = b"#include <stdio.h>\nint main() { printf(\"Hello\"); return 0; }\n"
    det_type, _, _ = FileDetector.detect(c_code, "main.c")
    assert det_type == "C Source Code"

    cpp_code = b"#include <iostream>\nusing namespace std;\nint main() { cout << \"Hi\"; }\n"
    det_type, _, _ = FileDetector.detect(cpp_code, "main.cpp")
    assert det_type == "C++ Source Code"

    rust_code = b"fn main() {\n    let mut x = 5;\n    println!(\"{}\", x);\n}\n"
    det_type, _, _ = FileDetector.detect(rust_code, "main.rs")
    assert det_type == "Rust Source Code"

    go_code = b"package main\nimport \"fmt\"\nfunc main() {\n    fmt.Println(\"Go\")\n}\n"
    det_type, _, _ = FileDetector.detect(go_code, "main.go")
    assert det_type == "Go Source Code"

    py_code = b"import sys\nimport os\n\ndef run():\n    print(sys.version)\n"
    det_type, _, _ = FileDetector.detect(py_code, "script.py")
    assert det_type == "Python Source Code"

    asm_code = b".section .text\n.global _start\n_start:\n    mov eax, 1\n    ret\n"
    det_type, _, _ = FileDetector.detect(asm_code, "start.s")
    assert det_type == "Assembly Source Code"


def test_json_and_xml_detection():
    json_data = b'{"name": "EKKI-RE-AI", "phase": 2.2}'
    det_type, _, _ = FileDetector.detect(json_data, "config.json")
    assert det_type == "JSON Document"

    xml_data = b'<?xml version="1.0"?><root><item>test</item></root>'
    det_type, _, _ = FileDetector.detect(xml_data, "data.xml")
    assert det_type == "XML Document"


def test_raw_binary_fallback():
    raw_bytes = bytes([0x90, 0xCC, 0xEB, 0xFE, 0x12, 0x34, 0x56, 0x78] * 10)
    det_type, arch, _ = FileDetector.detect(raw_bytes, "unknown.bin")
    assert det_type == "Raw Binary"
    assert arch == "N/A"


# --- 3. Unit Tests: Resilience & Corrupted Header Handling ---

def test_corrupted_pe_header():
    # PE MZ magic present but e_lfanew points to invalid offset out of bounds
    corrupted_pe = bytearray(100)
    corrupted_pe[:2] = b"MZ"
    struct.pack_into("<I", corrupted_pe, 0x3C, 9999)  # Out of bounds offset

    engine = BinaryIntelligenceEngine()
    res = engine.analyze(
        file_id="file-corrupted-pe",
        filename="corrupted.exe",
        content=bytes(corrupted_pe),
    )

    assert "Corrupted Header" in res["detected_type"]
    assert len(res["errors"]) > 0
    assert res["status"] == "analyzed"  # Engine does not crash!


# --- 4. Integration Tests: Workspace Integration & Artifact Persistence ---

def test_workspace_add_file_persists_analysis_artifact(temp_workspace):
    ws, temp_dir = temp_workspace
    proj = ws.create_project(name="Binary Intel Test Proj")

    payload = b"\x7fELF" + b"\x02\x01" + b"\x00" * 10 + struct.pack("<H", 2) + struct.pack("<H", 62) + b"\x00" * 40
    file_meta = ws.add_file(
        project_id=proj.project_id,
        filename="sample_elf.bin",
        content=payload,
    )

    # Check analysis artifact path: projects/{project_id}/analysis/{file_id}/metadata.json
    artifact_path = Path(temp_dir) / proj.project_id / "analysis" / file_meta.file_id / "metadata.json"
    assert artifact_path.exists()

    with open(artifact_path, "r", encoding="utf-8") as f:
        artifact_data = json.load(f)

    assert artifact_data["schema_version"] == 1
    assert artifact_data["file_id"] == file_meta.file_id
    assert "ELF" in artifact_data["detected_type"]
    assert artifact_data["detected_architecture"] == "x86_64"
    assert artifact_data["sha256"] == file_meta.sha256


# --- 5. Integration Tests: REST API Endpoints ---

def test_rest_api_get_metadata_and_analyze_endpoint():
    client = TestClient(app)

    # 1. Create Project via API
    create_res = client.post("/api/projects", json={"name": "API Binary Intel Test"})
    assert create_res.status_code == 201
    proj_id = create_res.json()["project_id"]

    try:
        # 2. Upload file via API
        file_payload = b"#include <stdio.h>\nint main() { printf(\"Test\"); return 0; }\n"
        upload_res = client.post(
            f"/api/projects/{proj_id}/files",
            files={"file": ("main.c", file_payload, "text/x-c")},
        )
        assert upload_res.status_code == 201
        file_id = upload_res.json()["file_id"]

        # 3. GET /api/projects/{project_id}/files/{file_id}/metadata
        meta_res = client.get(f"/api/projects/{proj_id}/files/{file_id}/metadata")
        assert meta_res.status_code == 200
        meta = meta_res.json()

        assert meta["schema_version"] == 1
        assert meta["file_id"] == file_id
        assert meta["detected_type"] == "C Source Code"
        assert meta["file_size"] == len(file_payload)
        assert meta["sha256"] == hashlib.sha256(file_payload).hexdigest()

        # 4. POST /api/projects/{project_id}/files/{file_id}/analyze
        reanalyze_res = client.post(f"/api/projects/{proj_id}/files/{file_id}/analyze")
        assert reanalyze_res.status_code == 200
        re_meta = reanalyze_res.json()
        assert re_meta["file_id"] == file_id
        assert re_meta["detected_type"] == "C Source Code"

    finally:
        # Clean up created project
        client.delete(f"/api/projects/{proj_id}")

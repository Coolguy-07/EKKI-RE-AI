"""
tests/test_capstone_engine.py

Comprehensive test suite for Phase 2.5: Capstone Disassembly Engine.
Tests can_handle() gating, architecture selection, section filtering,
instruction annotation, basic block reconstruction, loop detection,
artifact persistence, graceful degradation, and REST API endpoint.
"""

import json
import shutil
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.analysis.capstone_engine import CapstoneDisassemblyEngine, CAPSTONE_AVAILABLE
from backend.analysis.disassembly_model import (
    CURRENT_DISASSEMBLY_SCHEMA_VERSION,
    DisassemblyArtifact,
    BasicBlock,
    DisassembledInstruction,
    LoopDetectionResult,
    SectionDisassembly,
)
from backend.app import app
from backend.workspace import WorkspaceManager


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def engine():
    """Returns a fresh CapstoneDisassemblyEngine instance."""
    return CapstoneDisassemblyEngine()


@pytest.fixture
def temp_workspace():
    """Fixture creating an isolated workspace directory."""
    temp_dir = tempfile.mkdtemp(prefix="test_capstone_engine_")
    ws = WorkspaceManager(projects_dir=Path(temp_dir))
    yield ws, temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def build_synthetic_pe_for_disasm(code_bytes: bytes = b"") -> bytes:
    """
    Builds a minimal synthetic PE64 with a .text section containing the given
    machine code bytes, suitable for testing the Capstone disassembly pipeline.
    """
    size = 4096
    buf = bytearray(size)

    # DOS Header
    buf[:2] = b"MZ"
    lfanew = 128
    struct.pack_into("<I", buf, 0x3C, lfanew)

    # NT Header
    buf[lfanew : lfanew + 4] = b"PE\x00\x00"
    coff_offset = lfanew + 4

    # COFF Header (x86_64, 1 section)
    struct.pack_into("<H", buf, coff_offset, 0x8664)       # Machine: AMD64
    struct.pack_into("<H", buf, coff_offset + 2, 1)         # NumberOfSections
    struct.pack_into("<I", buf, coff_offset + 4, 1700000000) # TimeDateStamp
    struct.pack_into("<H", buf, coff_offset + 16, 240)      # SizeOfOptionalHeader
    struct.pack_into("<H", buf, coff_offset + 18, 0x0022)   # Characteristics

    # Optional Header (PE32+)
    opt_offset = coff_offset + 20
    struct.pack_into("<H", buf, opt_offset, 0x020B)         # Magic: PE32+
    struct.pack_into("<I", buf, opt_offset + 16, 0x1000)    # EntryPoint
    struct.pack_into("<Q", buf, opt_offset + 24, 0x140000000) # ImageBase
    struct.pack_into("<I", buf, opt_offset + 32, 0x1000)    # SectionAlignment
    struct.pack_into("<I", buf, opt_offset + 36, 0x200)     # FileAlignment
    struct.pack_into("<I", buf, opt_offset + 56, 0x3000)    # SizeOfImage
    struct.pack_into("<I", buf, opt_offset + 60, 0x200)     # SizeOfHeaders
    struct.pack_into("<I", buf, opt_offset + 108, 16)       # NumberOfRvaAndSizes

    # Section: .text
    sec_offset = opt_offset + 240
    buf[sec_offset : sec_offset + 6] = b".text\x00"
    text_va = 0x1000
    text_raw_offset = 0x200
    text_raw_size = len(code_bytes) if code_bytes else 0x100
    struct.pack_into("<I", buf, sec_offset + 8, text_raw_size)   # VirtualSize
    struct.pack_into("<I", buf, sec_offset + 12, text_va)         # VirtualAddress
    struct.pack_into("<I", buf, sec_offset + 16, text_raw_size)   # SizeOfRawData
    struct.pack_into("<I", buf, sec_offset + 20, text_raw_offset) # PointerToRawData
    struct.pack_into("<I", buf, sec_offset + 36, 0x60000020)      # Characteristics: CODE|EXEC|READ

    # Fill .text section with code bytes or NOPs
    if code_bytes:
        buf[text_raw_offset : text_raw_offset + len(code_bytes)] = code_bytes
    else:
        buf[text_raw_offset : text_raw_offset + text_raw_size] = b"\x90" * text_raw_size

    return bytes(buf)


def _build_mock_existing_metadata(
    arch: str = "x86_64",
    bitness: int = 64,
    endianness: str = "little",
    sections: list = None,
    detected_type: str = "PE Executable",
) -> dict:
    """Constructs a mock existing_metadata dict as produced by the pipeline
    after BinaryIntelligenceEngine + PEParserEngine have executed."""
    if sections is None:
        sections = [{
            "name": ".text",
            "virtual_address_raw": 0x1000,
            "raw_offset": 0x200,
            "raw_size": 0x100,
            "entropy": 5.0,
        }]
    return {
        "detected_type": detected_type,
        "file_id": "test-file-id",
        "filename": "test.exe",
        "engine_metadata": {
            "binary_intelligence": {
                "engine_version": "1.0.0",
            },
            "pe_parser": {
                "engine_version": "1.0.0",
                "is_pe": True,
                "parsed_data": {
                    "sections": sections,
                    "unified_model": {
                        "architecture": arch,
                        "bitness": bitness,
                        "endianness": endianness,
                    },
                    "entry_point": "0x00001000",
                },
            },
        },
    }


# ===========================================================================
# 1. Engine Identity Tests
# ===========================================================================

def test_engine_name_and_version(engine):
    assert engine.engine_name == "capstone_disassembly"
    assert engine.engine_version == "1.0.0"


# ===========================================================================
# 2. can_handle() Gating Tests
# ===========================================================================

def test_can_handle_pe_executable(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"MZ", detected_type="PE Executable (x86_64)", existing_metadata={}) is True


def test_can_handle_elf_executable(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"\x7fELF", detected_type="ELF 64-bit LSB executable", existing_metadata={}) is True


def test_can_handle_macho_executable(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"\xcf\xfa\xed\xfe", detected_type="Mach-O 64-bit x86_64", existing_metadata={}) is True


def test_can_handle_rejects_plaintext(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"Hello", detected_type="ASCII Text", existing_metadata={}) is False


def test_can_handle_rejects_markdown(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"# Title", detected_type="Markdown Document", existing_metadata={}) is False


def test_can_handle_rejects_archive(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"PK", detected_type="ZIP Archive", existing_metadata={}) is False


def test_can_handle_rejects_empty(engine):
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    assert engine.can_handle(content=b"", detected_type="", existing_metadata={}) is False


# ===========================================================================
# 3. Architecture Mapping Tests
# ===========================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_select_mode_x86_64(engine):
    errors = []
    cs_arch, cs_mode, arch_label, mode_label = engine._select_capstone_mode("x86_64", 64, "little", errors)
    assert cs_arch is not None
    assert "X86" in arch_label
    assert "64" in mode_label
    assert len(errors) == 0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_select_mode_x86_32(engine):
    errors = []
    cs_arch, cs_mode, arch_label, mode_label = engine._select_capstone_mode("i386", 32, "little", errors)
    assert cs_arch is not None
    assert "X86" in arch_label
    assert "32" in mode_label


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_select_mode_arm64(engine):
    errors = []
    cs_arch, cs_mode, arch_label, mode_label = engine._select_capstone_mode("aarch64", 64, "little", errors)
    assert cs_arch is not None
    assert "ARM64" in arch_label


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_select_mode_unsupported_arch(engine):
    errors = []
    cs_arch, cs_mode, arch_label, mode_label = engine._select_capstone_mode("SPARC", 64, "big", errors)
    assert cs_arch is None
    assert len(errors) == 1
    assert "not supported" in errors[0]


# ===========================================================================
# 4. Executable Section Filtering Tests
# ===========================================================================

def test_is_executable_section_text(engine):
    assert engine._is_executable_section(".text", {"raw_size": 1024}) is True


def test_is_executable_section_code(engine):
    assert engine._is_executable_section("CODE", {"raw_size": 1024}) is True


def test_is_executable_section_init(engine):
    assert engine._is_executable_section(".init", {"raw_size": 256}) is True


def test_is_executable_section_rejects_data(engine):
    assert engine._is_executable_section(".data", {"raw_size": 1024}) is False


def test_is_executable_section_rejects_bss(engine):
    assert engine._is_executable_section(".bss", {"raw_size": 4096}) is False


def test_is_executable_section_rejects_rodata(engine):
    assert engine._is_executable_section(".rodata", {"raw_size": 512}) is False


# ===========================================================================
# 5. Memory Heuristic Tests
# ===========================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_memory_read_heuristic_mov_source(engine):
    """MOV eax, [rbp-0x4] should set reads_memory=True."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    # MOV eax, dword ptr [rbp - 4]  → 8b 45 fc
    code = bytes([0x8b, 0x45, 0xfc])
    instructions = list(md.disasm(code, 0x1000))
    assert len(instructions) > 0
    insn = instructions[0]
    result = engine._annotate_instruction(insn, {0x1000}, 0x1000, 0x100)
    assert result.reads_memory is True
    assert result.writes_memory is False


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_memory_write_heuristic_mov_dest(engine):
    """MOV [rbp-0x4], eax should set writes_memory=True."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    # MOV dword ptr [rbp - 4], eax  → 89 45 fc
    code = bytes([0x89, 0x45, 0xfc])
    instructions = list(md.disasm(code, 0x1000))
    assert len(instructions) > 0
    insn = instructions[0]
    result = engine._annotate_instruction(insn, {0x1000}, 0x1000, 0x100)
    assert result.writes_memory is True
    assert result.reads_memory is False


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_memory_read_heuristic_add(engine):
    """ADD eax, [rbp-0x8] should set reads_memory=True."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    # ADD eax, dword ptr [rbp - 8]  → 03 45 f8
    code = bytes([0x03, 0x45, 0xf8])
    instructions = list(md.disasm(code, 0x1000))
    assert len(instructions) > 0
    insn = instructions[0]
    result = engine._annotate_instruction(insn, {0x1000}, 0x1000, 0x100)
    assert result.reads_memory is True


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_no_memory_flag_for_push_register(engine):
    """PUSH rbp should NOT set reads_memory or writes_memory."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    # PUSH rbp  → 55
    code = bytes([0x55])
    instructions = list(md.disasm(code, 0x1000))
    assert len(instructions) > 0
    insn = instructions[0]
    result = engine._annotate_instruction(insn, {0x1000}, 0x1000, 0x100)
    assert result.reads_memory is False
    assert result.writes_memory is False


# ===========================================================================
# 6. Basic Block Reconstruction Tests
# ===========================================================================

def test_reconstruct_single_block(engine):
    """A flat sequence of non-branching instructions forms a single block."""
    insns = [
        DisassembledInstruction(address=0x1000, address_hex="0x1000", mnemonic="PUSH", op_str="rbp", size=1, bytes_hex="55"),
        DisassembledInstruction(address=0x1001, address_hex="0x1001", mnemonic="MOV", op_str="rbp, rsp", size=3, bytes_hex="4889e5"),
        DisassembledInstruction(address=0x1004, address_hex="0x1004", mnemonic="NOP", op_str="", size=1, bytes_hex="90"),
    ]
    blocks = engine._reconstruct_basic_blocks(insns, {0x1000, 0x1001, 0x1004})
    assert len(blocks) == 1
    assert blocks[0].instruction_count == 3
    assert blocks[0].start_address == 0x1000


def test_reconstruct_blocks_with_branch(engine):
    """A conditional branch should split into two blocks."""
    insns = [
        DisassembledInstruction(address=0x1000, address_hex="0x1000", mnemonic="CMP", op_str="eax, 0", size=3, bytes_hex="83f800"),
        DisassembledInstruction(address=0x1003, address_hex="0x1003", mnemonic="JZ", op_str="0x100a", size=2, bytes_hex="7405",
                                is_branch=True, is_conditional_branch=True, branch_target=0x100a, branch_target_hex="0x100a"),
        DisassembledInstruction(address=0x1005, address_hex="0x1005", mnemonic="MOV", op_str="eax, 1", size=5, bytes_hex="b801000000"),
        DisassembledInstruction(address=0x100a, address_hex="0x100a", mnemonic="RET", op_str="", size=1, bytes_hex="c3", is_ret=True),
    ]
    instruction_starts = {0x1000, 0x1003, 0x1005, 0x100a}
    blocks = engine._reconstruct_basic_blocks(insns, instruction_starts)
    assert len(blocks) == 3  # [CMP, JZ] → [MOV] → [RET]


def test_reconstruct_empty_list(engine):
    blocks = engine._reconstruct_basic_blocks([], set())
    assert blocks == []


# ===========================================================================
# 7. Loop Detection Tests
# ===========================================================================

def test_detect_loop_with_back_edge(engine):
    """A block ending with a backward branch should be detected as a loop."""
    insns = [
        DisassembledInstruction(address=0x1005, address_hex="0x1005", mnemonic="ADD", op_str="eax, 1", size=3, bytes_hex="83c001"),
        DisassembledInstruction(address=0x1008, address_hex="0x1008", mnemonic="CMP", op_str="eax, 0xa", size=3, bytes_hex="83f80a"),
        DisassembledInstruction(address=0x100b, address_hex="0x100b", mnemonic="JL", op_str="0x1000", size=2, bytes_hex="7cf3",
                                is_branch=True, is_conditional_branch=True, branch_target=0x1000, branch_target_hex="0x1000"),
    ]
    block = BasicBlock(
        block_id="bb_0x1005",
        start_address=0x1005,
        end_address=0x100b,
        instruction_count=3,
        byte_span=8,
        instructions=insns,
    )
    result = engine._detect_loop(block, {0x1000, 0x1005, 0x1008, 0x100b})
    assert result.detected is True
    assert result.loop_header_address == 0x1000
    assert result.branch_mnemonic == "JL"
    assert result.is_signed_comparison is True
    assert result.cmp_mnemonic == "CMP"
    assert result.cmp_lhs == "EAX"
    assert result.cmp_rhs == "0xa"
    assert result.loop_bound_immediate == 10
    assert result.bound_type == "constant"


def test_no_loop_without_back_edge(engine):
    """A forward branch should NOT be detected as a loop."""
    insns = [
        DisassembledInstruction(address=0x1000, address_hex="0x1000", mnemonic="JZ", op_str="0x1010", size=2, bytes_hex="7410",
                                is_branch=True, is_conditional_branch=True, branch_target=0x1010, branch_target_hex="0x1010"),
    ]
    block = BasicBlock(
        block_id="bb_0x1000",
        start_address=0x1000,
        end_address=0x1000,
        instruction_count=1,
        byte_span=2,
        instructions=insns,
    )
    result = engine._detect_loop(block, {0x1000, 0x1010})
    assert result.detected is False


def test_loop_detection_boundary_anomaly(engine):
    """Back-edge to non-instruction boundary should flag anomaly."""
    insns = [
        DisassembledInstruction(address=0x1005, address_hex="0x1005", mnemonic="JMP", op_str="0x1002", size=2, bytes_hex="ebfb",
                                is_branch=True, is_unconditional_branch=True, branch_target=0x1002, branch_target_hex="0x1002"),
    ]
    block = BasicBlock(
        block_id="bb_0x1005",
        start_address=0x1005,
        end_address=0x1005,
        instruction_count=1,
        byte_span=2,
        instructions=insns,
    )
    # 0x1002 is NOT in the instruction start set
    result = engine._detect_loop(block, {0x1000, 0x1005})
    assert result.detected is True
    assert "branch_target_not_on_instruction_boundary" in result.anomalies


# ===========================================================================
# 8. Context Resolution Tests
# ===========================================================================

def test_resolve_binary_context_pe(engine):
    """Should extract architecture from PE parser unified_model."""
    meta = _build_mock_existing_metadata(arch="x86_64", bitness=64, endianness="little")
    arch, bitness, endianness, sections = engine._resolve_binary_context(meta)
    assert arch == "x86_64"
    assert bitness == 64
    assert endianness == "little"
    assert ".text" in sections
    assert sections[".text"]["raw_offset"] == 0x200


def test_resolve_binary_context_elf(engine):
    """Should extract architecture from ELF parser using 'section_headers' key."""
    meta = {
        "detected_type": "ELF 64-bit",
        "engine_metadata": {
            "elf_parser": {
                "engine_version": "1.0.0",
                "is_elf": True,
                "parsed_data": {
                    "section_headers": [
                        {
                            "name": ".text",
                            "address_raw": 0x401000,
                            "offset": 0x1000,
                            "size": 0x500,
                            "entropy": 6.5,
                        }
                    ],
                    "unified_model": {
                        "architecture": "x86_64",
                        "bitness": 64,
                        "endianness": "little",
                    },
                },
            },
        },
    }
    arch, bitness, endianness, sections = engine._resolve_binary_context(meta)
    assert arch == "x86_64"
    assert ".text" in sections
    assert sections[".text"]["raw_offset"] == 0x1000
    assert sections[".text"]["raw_size"] == 0x500


def test_resolve_binary_context_fallback(engine):
    """Without any format parser data, should fallback to defaults."""
    meta = {"engine_metadata": {"binary_intelligence": {}}}
    arch, bitness, endianness, sections = engine._resolve_binary_context(meta)
    assert arch == "x86_64"
    assert bitness == 64
    assert sections == {}


# ===========================================================================
# 9. Full analyze() Integration Tests
# ===========================================================================

@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_analyze_with_nop_sled():
    """Disassemble a section of NOP instructions and verify output structure."""
    engine = CapstoneDisassemblyEngine()
    nop_bytes = b"\x90" * 16  # 16 NOP instructions
    content = bytearray(0x300)
    content[0x200:0x210] = nop_bytes

    meta = _build_mock_existing_metadata(
        sections=[{
            "name": ".text",
            "virtual_address_raw": 0x1000,
            "raw_offset": 0x200,
            "raw_size": 16,
            "entropy": 0.0,
        }]
    )

    result = engine.analyze(
        file_id="test-nop",
        filename="nops.exe",
        content=bytes(content),
        existing_metadata=meta,
    )

    assert "engine_metadata" in result
    assert "capstone_disassembly" in result["engine_metadata"]
    engine_out = result["engine_metadata"]["capstone_disassembly"]
    assert engine_out["capstone_available"] is True
    parsed = engine_out["parsed_data"]
    assert parsed["total_instructions"] == 16
    assert parsed["architecture"] == "x86_64"


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_analyze_skips_data_section():
    """Sections named .data should not be disassembled."""
    engine = CapstoneDisassemblyEngine()
    content = bytearray(0x400)
    content[0x200:0x210] = b"\x90" * 16

    meta = _build_mock_existing_metadata(
        sections=[{
            "name": ".data",
            "virtual_address_raw": 0x2000,
            "raw_offset": 0x200,
            "raw_size": 16,
            "entropy": 3.0,
        }]
    )

    result = engine.analyze(
        file_id="test-data",
        filename="data.exe",
        content=bytes(content),
        existing_metadata=meta,
    )

    parsed = result["engine_metadata"]["capstone_disassembly"]["parsed_data"]
    assert parsed["total_instructions"] == 0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not installed")
def test_analyze_out_of_bounds_section():
    """Section with raw bounds exceeding content should be skipped with error."""
    engine = CapstoneDisassemblyEngine()
    content = b"\x00" * 0x100  # Only 256 bytes

    meta = _build_mock_existing_metadata(
        sections=[{
            "name": ".text",
            "virtual_address_raw": 0x1000,
            "raw_offset": 0x500,   # Beyond content
            "raw_size": 0x100,
            "entropy": 0.0,
        }]
    )

    result = engine.analyze(
        file_id="test-oob",
        filename="oob.exe",
        content=content,
        existing_metadata=meta,
    )

    parsed = result["engine_metadata"]["capstone_disassembly"]["parsed_data"]
    assert parsed["total_instructions"] == 0
    assert any("raw bounds" in e for e in parsed["parser_errors"])


# ===========================================================================
# 10. Graceful Degradation Tests
# ===========================================================================

def test_analyze_without_capstone_installed(engine):
    """When CAPSTONE_AVAILABLE is False, engine should return gracefully."""
    with patch("backend.analysis.capstone_engine.CAPSTONE_AVAILABLE", False):
        result = engine.analyze(
            file_id="test-no-capstone",
            filename="test.exe",
            content=b"\x00" * 100,
            existing_metadata={"engine_metadata": {}},
        )
        assert "capstone_disassembly" in result["engine_metadata"]
        assert result["engine_metadata"]["capstone_disassembly"]["capstone_available"] is False


def test_analyze_unsupported_architecture(engine):
    """Unsupported arch should return early with error, not crash."""
    if not CAPSTONE_AVAILABLE:
        pytest.skip("Capstone not installed")
    meta = _build_mock_existing_metadata(arch="SPARC")
    result = engine.analyze(
        file_id="test-sparc",
        filename="sparc.exe",
        content=b"\x00" * 0x300,
        existing_metadata=meta,
    )
    assert "errors" in result
    assert any("not supported" in e for e in result["errors"])


# ===========================================================================
# 11. Artifact Persistence Tests
# ===========================================================================

def test_save_disassembly_artifact_atomic(engine, tmp_path):
    """Verify atomic write pattern: temp file should not remain on success."""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()

    artifact_dict = {
        "schema_version": CURRENT_DISASSEMBLY_SCHEMA_VERSION,
        "file_id": "test-file",
        "total_instructions": 42,
    }

    result_path = engine.save_disassembly_artifact(project_dir, "test-file", artifact_dict)
    assert result_path.exists()
    assert not (result_path.parent / "disassembly.json.tmp").exists()

    with open(result_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["total_instructions"] == 42


# ===========================================================================
# 12. Pydantic Schema Validation Tests
# ===========================================================================

def test_disassembly_artifact_model_validates():
    """DisassemblyArtifact should validate a minimal complete artifact."""
    artifact = DisassemblyArtifact(
        schema_version=CURRENT_DISASSEMBLY_SCHEMA_VERSION,
        file_id="test-123",
        filename="test.exe",
        architecture="x86_64",
        bitness=64,
        endianness="little",
        capstone_version="5.0.1",
        sections={},
        total_instructions=0,
        total_basic_blocks=0,
        total_loops_detected=0,
        engine_name="capstone_disassembly",
        engine_version="1.0.0",
        execution_time_ms=12.5,
    )
    dumped = artifact.model_dump()
    assert dumped["architecture"] == "x86_64"
    assert dumped["schema_version"] == CURRENT_DISASSEMBLY_SCHEMA_VERSION


def test_loop_detection_result_model():
    """LoopDetectionResult should serialize correctly."""
    result = LoopDetectionResult(
        detected=True,
        loop_latch_address=0x1005,
        loop_header_address=0x1000,
        branch_mnemonic="JL",
        branch_type="signed_lt",
        is_signed_comparison=True,
        cmp_mnemonic="CMP",
        cmp_lhs="EAX",
        cmp_rhs="0xa",
        loop_bound_immediate=10,
        bound_type="constant",
    )
    dumped = result.model_dump()
    assert dumped["detected"] is True
    assert dumped["bound_type"] == "constant"


# ===========================================================================
# 13. REST API Integration Test
# ===========================================================================

def test_rest_api_get_disassembly_endpoint():
    """Verify GET /api/projects/{id}/files/{file_id}/disassembly returns valid response."""
    client = TestClient(app)

    create_res = client.post("/api/projects", json={"name": "Disasm API Test"})
    assert create_res.status_code == 201
    proj_id = create_res.json()["project_id"]

    try:
        pe_bytes = build_synthetic_pe_for_disasm(
            code_bytes=b"\x55\x48\x89\xe5\x90\x90\x90\x5d\xc3"  # push rbp; mov rbp,rsp; nop*3; pop rbp; ret
        )
        upload_res = client.post(
            f"/api/projects/{proj_id}/files",
            files={"file": ("test.exe", pe_bytes, "application/vnd.microsoft.portable-executable")},
        )
        assert upload_res.status_code == 201
        file_id = upload_res.json()["file_id"]

        # GET disassembly endpoint
        disasm_res = client.get(f"/api/projects/{proj_id}/files/{file_id}/disassembly")
        assert disasm_res.status_code == 200
        data = disasm_res.json()

        # The response should be a dict (even if disassembly wasn't produced, the fallback returns a dict)
        assert isinstance(data, dict)
        assert "file_id" in data

    finally:
        client.delete(f"/api/projects/{proj_id}")


def test_rest_api_disassembly_404_invalid_file():
    """GET /disassembly with invalid file_id should return 404."""
    client = TestClient(app)

    create_res = client.post("/api/projects", json={"name": "Disasm 404 Test"})
    assert create_res.status_code == 201
    proj_id = create_res.json()["project_id"]

    try:
        res = client.get(f"/api/projects/{proj_id}/files/nonexistent-id/disassembly")
        assert res.status_code == 404
    finally:
        client.delete(f"/api/projects/{proj_id}")

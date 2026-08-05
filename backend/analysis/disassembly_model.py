"""
backend/analysis/disassembly_model.py

Versioned Pydantic domain models for the Capstone Disassembly Engine artifact.
Stored under analysis/{file_id}/disassembly.json.

Schema covers: per-instruction data-flow annotations, basic block boundaries,
branch target validation results, and loop detection heuristic output.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

CURRENT_DISASSEMBLY_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Instruction-level model
# ---------------------------------------------------------------------------

class DisassembledInstruction(BaseModel):
    """Represents a single decoded instruction with control-flow annotations."""

    address: int = Field(..., description="Absolute virtual address of the instruction.")
    address_hex: str = Field(..., description="Hex string of virtual address (e.g. '0x401008').")
    mnemonic: str = Field(..., description="Instruction mnemonic (e.g. 'MOV', 'JLE', 'CALL').")
    op_str: str = Field(..., description="Operand string as disassembled (e.g. 'eax, [rbp-0x4]').")
    size: int = Field(..., description="Instruction size in bytes.")
    bytes_hex: str = Field(..., description="Raw instruction bytes as hex string (e.g. '8b45fc').")

    # Capstone group membership flags
    is_branch: bool = Field(False, description="True if this instruction is any branch (conditional or unconditional).")
    is_conditional_branch: bool = Field(False, description="True if this is a conditional branch (JE, JNE, JLE, etc.).")
    is_unconditional_branch: bool = Field(False, description="True if this is an unconditional jump (JMP).")
    is_call: bool = Field(False, description="True if this is a CALL instruction.")
    is_ret: bool = Field(False, description="True if this is a RET/RETN/RETF instruction.")
    is_privileged: bool = Field(False, description="True if this is a privileged/ring0 instruction.")

    # Branch target information
    branch_target: Optional[int] = Field(
        None,
        description="Resolved absolute branch target address (None for indirect/unresolved).",
    )
    branch_target_hex: Optional[str] = Field(
        None,
        description="Hex string of resolved branch target address.",
    )
    branch_target_in_section: Optional[bool] = Field(
        None,
        description="True if the branch target falls within the current section's VA range.",
    )
    branch_target_on_boundary: Optional[bool] = Field(
        None,
        description="True if the branch target aligns to a known instruction start address.",
    )
    branch_type: Optional[str] = Field(
        None,
        description="Branch classification: 'conditional_back_edge', 'conditional_forward', "
                    "'unconditional', 'indirect', 'call', or None.",
    )

    # Data-flow annotations (populated by post-processing pass, not Capstone directly)
    reads_registers: List[str] = Field(
        default_factory=list,
        description="Registers read by this instruction (e.g. ['EAX', 'RBP']).",
    )
    writes_registers: List[str] = Field(
        default_factory=list,
        description="Registers written by this instruction (e.g. ['EAX', 'EFLAGS']).",
    )
    reads_memory: bool = Field(False, description="True if instruction reads from memory.")
    writes_memory: bool = Field(False, description="True if instruction writes to memory.")
    memory_operand: Optional[str] = Field(
        None,
        description="Memory operand expression string if applicable (e.g. '[rbp-0x4]').",
    )


# ---------------------------------------------------------------------------
# Basic block model
# ---------------------------------------------------------------------------

class BasicBlock(BaseModel):
    """A maximal sequence of instructions with a single entry and single exit."""

    block_id: str = Field(
        ...,
        description="Unique block identifier string (e.g. 'bb_0x401008').",
    )
    start_address: int = Field(..., description="Address of the first instruction in this block.")
    end_address: int = Field(
        ...,
        description="Address of the last instruction in this block (inclusive).",
    )
    instruction_count: int = Field(..., description="Number of instructions in this block.")
    byte_span: int = Field(
        ...,
        description="Total byte size from start to end of last instruction.",
    )
    instructions: List[DisassembledInstruction] = Field(
        default_factory=list,
        description="Ordered list of decoded instructions in this block.",
    )

    # Control-flow graph edges
    successors: List[int] = Field(
        default_factory=list,
        description="Absolute addresses of successor basic blocks (fall-through and/or branch targets).",
    )
    predecessors: List[int] = Field(
        default_factory=list,
        description="Absolute addresses of predecessor basic blocks.",
    )

    # Loop participation flags
    is_loop_header: bool = Field(
        False,
        description="True if this block is the entry point of a detected loop.",
    )
    is_loop_latch: bool = Field(
        False,
        description="True if this block contains the back-edge branch closing a loop.",
    )
    back_edge_targets: List[int] = Field(
        default_factory=list,
        description="Addresses targeted by back-edge branches originating in this block.",
    )


# ---------------------------------------------------------------------------
# Loop detection result model
# ---------------------------------------------------------------------------

class LoopDetectionResult(BaseModel):
    """
    Structured output from the loop-detection heuristic pass over a basic block.
    Captures comparison operands, branch direction, and bound classification.
    """

    detected: bool = Field(..., description="True if a loop pattern was identified.")

    # Addresses
    loop_latch_address: int = Field(
        ...,
        description="Address of the basic block containing the back-edge branch.",
    )
    loop_header_address: Optional[int] = Field(
        None,
        description="Address of the inferred loop header (back-edge target).",
    )

    # Branch classification
    branch_mnemonic: Optional[str] = Field(
        None,
        description="Mnemonic of the closing branch instruction (e.g. 'JLE', 'JNZ').",
    )
    branch_type: Optional[str] = Field(
        None,
        description="'signed_le', 'signed_lt', 'signed_ge', 'signed_gt', "
                    "'unsigned_be', 'unsigned_lt', 'zero_test', 'nonzero_test', 'unknown'.",
    )
    is_signed_comparison: Optional[bool] = Field(
        None,
        description="True if the closing branch uses a signed comparison mnemonic.",
    )

    # Comparison operands (from the CMP/TEST preceding the branch)
    cmp_mnemonic: Optional[str] = Field(
        None,
        description="Mnemonic of the comparison instruction (e.g. 'CMP', 'TEST').",
    )
    cmp_lhs: Optional[str] = Field(
        None,
        description="Left-hand operand of the comparison (e.g. 'EAX').",
    )
    cmp_rhs: Optional[str] = Field(
        None,
        description="Right-hand operand of the comparison (e.g. '0xa', 'ECX').",
    )
    loop_bound_immediate: Optional[int] = Field(
        None,
        description="Immediate integer bound value if cmp_rhs is a constant (e.g. 10 for '0xa').",
    )
    loop_bound_register: Optional[str] = Field(
        None,
        description="Register name if the bound is variable (e.g. 'ECX'). None if bound is immediate.",
    )

    # Classification
    bound_type: Optional[str] = Field(
        None,
        description="'constant' if loop bound is an immediate, 'variable' if register-held, 'unknown'.",
    )
    anomalies: List[str] = Field(
        default_factory=list,
        description="List of detected anomalies (e.g. 'missing_write_back', "
                    "'branch_target_not_on_instruction_boundary', 'byte_encoding_mismatch').",
    )


# ---------------------------------------------------------------------------
# Per-section disassembly model
# ---------------------------------------------------------------------------

class SectionDisassembly(BaseModel):
    """Disassembly results for a single executable section."""

    section_name: str = Field(..., description="Section name (e.g. '.text', '__text').")
    virtual_address: int = Field(..., description="Section virtual address (raw integer).")
    virtual_address_hex: str = Field(..., description="Section VA as hex string.")
    raw_offset: int = Field(..., description="Physical file offset of section data.")
    raw_size: int = Field(..., description="Physical size of section data in bytes.")
    capstone_arch: str = Field(..., description="Capstone architecture string used (e.g. 'CS_ARCH_X86').")
    capstone_mode: str = Field(..., description="Capstone mode string used (e.g. 'CS_MODE_64').")

    instructions: List[DisassembledInstruction] = Field(
        default_factory=list,
        description="Flat ordered list of all decoded instructions in this section.",
    )
    basic_blocks: List[BasicBlock] = Field(
        default_factory=list,
        description="Reconstructed basic blocks from instruction stream.",
    )
    loops: List[LoopDetectionResult] = Field(
        default_factory=list,
        description="Loop patterns identified in this section.",
    )

    # Coverage statistics
    total_instructions: int = Field(0, description="Total decoded instruction count.")
    total_basic_blocks: int = Field(0, description="Total reconstructed basic block count.")
    total_loops_detected: int = Field(0, description="Count of identified loop patterns.")
    coverage_bytes: int = Field(
        0,
        description="Total bytes successfully decoded (may be < raw_size if gaps/data exist).",
    )
    coverage_percent: float = Field(
        0.0,
        description="Fraction of raw_size covered by decoded instructions (0.0–100.0).",
    )
    section_errors: List[str] = Field(
        default_factory=list,
        description="Section-level decode errors (e.g. invalid opcode regions).",
    )


# ---------------------------------------------------------------------------
# Top-level disassembly artifact model (disassembly.json)
# ---------------------------------------------------------------------------

class DisassemblyArtifact(BaseModel):
    """
    Root model for analysis/{file_id}/disassembly.json.
    Produced by CapstoneDisassemblyEngine and consumed by the AI Context Builder (Phase 2.8).
    """

    schema_version: int = Field(
        default=CURRENT_DISASSEMBLY_SCHEMA_VERSION,
        description="Schema version of this disassembly artifact.",
    )
    file_id: str = Field(..., description="Immutable file identifier.")
    filename: str = Field(..., description="Display filename.")

    # Binary context (sourced from UnifiedExecutableModel)
    architecture: str = Field(..., description="Target architecture (e.g. 'x86_64', 'ARM64').")
    bitness: int = Field(..., description="Architecture bitness: 32 or 64.")
    endianness: str = Field(..., description="Endianness: 'little' or 'big'.")
    entry_point_hex: Optional[str] = Field(
        None,
        description="Entry point hex address from the format parser.",
    )

    # Capstone version metadata
    capstone_version: str = Field(
        ...,
        description="Capstone library version string (e.g. '5.0.1').",
    )

    # Per-section disassembly results
    sections: Dict[str, SectionDisassembly] = Field(
        default_factory=dict,
        description="Map of section_name → SectionDisassembly results.",
    )

    # Aggregate statistics
    total_instructions: int = Field(0, description="Aggregate instruction count across all sections.")
    total_basic_blocks: int = Field(0, description="Aggregate basic block count across all sections.")
    total_loops_detected: int = Field(0, description="Aggregate loop count across all sections.")

    # Engine metadata
    engine_name: str = Field("capstone_disassembly", description="Producing engine name.")
    engine_version: str = Field(..., description="Producing engine version string.")
    execution_time_ms: float = Field(0.0, description="Wall-clock analysis time in milliseconds.")
    parser_errors: List[str] = Field(
        default_factory=list,
        description="Top-level errors encountered during analysis.",
    )
    summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Human-readable summary dict for quick display (section names, counts, loops).",
    )

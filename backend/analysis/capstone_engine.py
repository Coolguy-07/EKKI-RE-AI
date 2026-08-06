"""
backend/analysis/capstone_engine.py

Capstone Disassembly Engine for EKKI-RE-AI — Phase 2.5.

Implements BaseAnalysisEngine. Decodes executable sections using the Capstone
disassembly framework, reconstructs basic blocks, performs branch boundary
validation, and runs the loop-detection heuristic pass.

Produces: analysis/{file_id}/disassembly.json (DisassemblyArtifact schema).
Reads:    existing_metadata["engine_metadata"]["binary_intelligence"] for detected_type.
          existing_metadata["engine_metadata"]["pe_parser"|"elf_parser"|"macho_parser"]
          for UnifiedExecutableModel (architecture, entry_point, sections).
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseAnalysisEngine
from .disassembly_model import (
    CURRENT_DISASSEMBLY_SCHEMA_VERSION,
    BasicBlock,
    DisassembledInstruction,
    DisassemblyArtifact,
    LoopDetectionResult,
    SectionDisassembly,
)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Capstone import guard — engine degrades gracefully if Capstone is not installed.
# Install with: pip install capstone
# ---------------------------------------------------------------------------
try:
    import capstone
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_PPC,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_MIPS32,
        CS_MODE_MIPS64,
        CS_MODE_THUMB,
        CS_GRP_CALL,
        CS_GRP_INT,
        CS_GRP_IRET,
        CS_GRP_JUMP,
        CS_GRP_PRIVILEGE,
        CS_GRP_RET,
    )
    # CS_GRP_BRANCH_RELATIVE was introduced in Capstone 5.x.
    # Provide a safe fallback for Capstone 4.x installations.
    try:
        from capstone import CS_GRP_BRANCH_RELATIVE  # noqa: F811
    except ImportError:
        CS_GRP_BRANCH_RELATIVE = None  # type: ignore[assignment]

    def _get_capstone_version() -> str:
        """Safely detects Capstone library version across 4.x and 5.x releases."""
        if hasattr(capstone, "__version__") and capstone.__version__:
            return str(capstone.__version__)
        if hasattr(capstone, "version_bind") and callable(capstone.version_bind):
            try:
                ver = capstone.version_bind()
                if isinstance(ver, (tuple, list)):
                    return ".".join(str(x) for x in ver)
            except Exception:
                pass
        if hasattr(capstone, "cs_version") and callable(capstone.cs_version):
            try:
                ver = capstone.cs_version()
                if isinstance(ver, (tuple, list)):
                    return ".".join(str(x) for x in ver)
            except Exception:
                pass
        return "unknown"

    CAPSTONE_AVAILABLE = True
    CAPSTONE_VERSION = _get_capstone_version()
except ImportError:
    CAPSTONE_AVAILABLE = False
    CAPSTONE_VERSION = "unavailable"
    logger.warning(
        "Capstone library not installed. CapstoneDisassemblyEngine will be skipped. "
        "Install with: pip install capstone"
    )


# ---------------------------------------------------------------------------
# Signed conditional branch mnemonics (x86_64)
# ---------------------------------------------------------------------------
_SIGNED_BRANCHES = frozenset({
    "JL", "JLE", "JG", "JGE",         # signed comparisons
    "JNGE", "JNG", "JNLE", "JNL",     # aliased signed comparisons
})

_UNSIGNED_BRANCHES = frozenset({
    "JB", "JBE", "JA", "JAE",         # unsigned comparisons (below/above)
    "JC", "JNC",                        # carry flag
    "JNAE", "JNB", "JNBE", "JNA",     # aliases
})

_ZERO_BRANCHES = frozenset({"JZ", "JE", "JNZ", "JNE"})

# Map mnemonic → (branch_type_str, is_signed)
_BRANCH_TYPE_MAP: Dict[str, Tuple[str, bool]] = {
    "JL":    ("signed_lt",   True),
    "JLE":   ("signed_le",   True),
    "JG":    ("signed_gt",   True),
    "JGE":   ("signed_ge",   True),
    "JNGE":  ("signed_lt",   True),
    "JNG":   ("signed_le",   True),
    "JNLE":  ("signed_gt",   True),
    "JNL":   ("signed_ge",   True),
    "JB":    ("unsigned_lt", False),
    "JBE":   ("unsigned_le", False),
    "JA":    ("unsigned_gt", False),
    "JAE":   ("unsigned_ge", False),
    "JC":    ("unsigned_lt", False),
    "JNC":   ("unsigned_ge", False),
    "JNAE":  ("unsigned_lt", False),
    "JNB":   ("unsigned_ge", False),
    "JNBE":  ("unsigned_gt", False),
    "JNA":   ("unsigned_le", False),
    "JZ":    ("zero_test",   False),
    "JE":    ("zero_test",   False),
    "JNZ":   ("nonzero_test", False),
    "JNE":   ("nonzero_test", False),
    "JMP":   ("unconditional", False),
    "JMPQ":  ("unconditional", False),
}


class CapstoneDisassemblyEngine(BaseAnalysisEngine):
    """
    Phase 2.5 Analysis Engine: static disassembly via Capstone.

    Responsibilities:
    - Determine Capstone arch/mode from UnifiedExecutableModel in existing_metadata.
    - Decode each executable section byte-by-byte using Capstone linear sweep.
    - Reconstruct basic blocks by identifying branch terminators.
    - Validate all branch targets against section VA boundaries and instruction start sets.
    - Run the loop-detection heuristic pass over each basic block.
    - Serialize results to DisassemblyArtifact and persist disassembly.json atomically.
    """

    # Maximum instructions to disassemble per section (memory/time guard).
    MAX_INSTRUCTIONS_PER_SECTION = 100_000

    # Executable section name prefixes that contain code.
    EXECUTABLE_SECTION_NAMES = frozenset({
        ".text", "__text", ".init", ".fini", ".plt", ".plt.got",
        "CODE", ".code", "text",
    })

    @property
    def engine_name(self) -> str:
        return "capstone_disassembly"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    # ------------------------------------------------------------------
    # can_handle — only run on confirmed binary executables/libraries
    # ------------------------------------------------------------------

    def can_handle(
        self,
        content: bytes,
        detected_type: str,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Returns True only for binary formats that contain machine code.
        Skips source code, archives, scripts, documents, and empty files.
        """
        if not CAPSTONE_AVAILABLE:
            return False
        executable_markers = ("PE", "ELF", "Mach-O", "COFF")
        return any(marker in detected_type for marker in executable_markers)

    # ------------------------------------------------------------------
    # analyze — pipeline entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes Capstone disassembly pipeline and returns enriched metadata dict.

        The returned dict is the same existing_metadata with
        engine_metadata["capstone_disassembly"] populated.
        """
        start_time = time.perf_counter()
        existing_metadata = existing_metadata or {}
        errors: List[str] = []

        if not CAPSTONE_AVAILABLE:
            errors.append("Capstone library not installed — engine skipped.")
            return self._inject_engine_result(existing_metadata, {}, errors, start_time)

        # Resolve Capstone arch/mode from format parser output
        arch_str, bitness, endianness, sections_meta = self._resolve_binary_context(
            existing_metadata
        )
        cs_arch, cs_mode, arch_label, mode_label = self._select_capstone_mode(
            arch_str, bitness, endianness, errors
        )

        if cs_arch is None:
            return self._inject_engine_result(existing_metadata, {}, errors, start_time)

        # Initialise Capstone disassembler
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True  # Enable register read/write tracking

        section_results: Dict[str, SectionDisassembly] = {}
        total_instructions = 0
        total_basic_blocks = 0
        total_loops = 0

        # Disassemble each executable section
        for section_name, section_info in sections_meta.items():
            if not self._is_executable_section(section_name, section_info):
                continue

            va = section_info.get("virtual_address_raw", 0)
            raw_offset = section_info.get("raw_offset", 0)
            raw_size = section_info.get("raw_size", 0)

            if raw_size == 0 or raw_offset + raw_size > len(content):
                errors.append(
                    f"Section '{section_name}': raw bounds [{raw_offset}:{raw_offset+raw_size}] "
                    f"exceed content size {len(content)}."
                )
                continue

            section_bytes = content[raw_offset: raw_offset + raw_size]

            sec_result = self._disassemble_section(
                md=md,
                section_name=section_name,
                section_bytes=section_bytes,
                va=va,
                raw_offset=raw_offset,
                raw_size=raw_size,
                arch_label=arch_label,
                mode_label=mode_label,
            )
            section_results[section_name] = sec_result
            total_instructions += sec_result.total_instructions
            total_basic_blocks += sec_result.total_basic_blocks
            total_loops += sec_result.total_loops_detected

        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        artifact = DisassemblyArtifact(
            schema_version=CURRENT_DISASSEMBLY_SCHEMA_VERSION,
            file_id=file_id,
            filename=filename,
            architecture=arch_str,
            bitness=bitness,
            endianness=endianness,
            entry_point_hex=self._get_entry_point(existing_metadata),
            capstone_version=CAPSTONE_VERSION,
            sections=section_results,
            total_instructions=total_instructions,
            total_basic_blocks=total_basic_blocks,
            total_loops_detected=total_loops,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            execution_time_ms=exec_time_ms,
            parser_errors=errors,
            summary={
                "sections_disassembled": list(section_results.keys()),
                "total_instructions": total_instructions,
                "total_basic_blocks": total_basic_blocks,
                "total_loops_detected": total_loops,
                "capstone_available": True,
            },
        )

        logger.info(
            "CapstoneDisassemblyEngine completed for file_id='%s': "
            "%d instructions, %d blocks, %d loops in %.2fms",
            file_id,
            total_instructions,
            total_basic_blocks,
            total_loops,
            exec_time_ms,
        )

        return self._inject_engine_result(
            existing_metadata, artifact.model_dump(), errors, start_time
        )

    # ------------------------------------------------------------------
    # Section disassembly
    # ------------------------------------------------------------------

    def _disassemble_section(
        self,
        md: "capstone.Cs",
        section_name: str,
        section_bytes: bytes,
        va: int,
        raw_offset: int,
        raw_size: int,
        arch_label: str,
        mode_label: str,
    ) -> SectionDisassembly:
        """Linear sweep disassembly of a single section, with block and loop recovery."""
        instructions: List[DisassembledInstruction] = []
        section_errors: List[str] = []

        # First pass: decode all instructions and collect start addresses.
        instruction_start_set: set = set()
        raw_instructions = []

        count = 0
        for insn in md.disasm(section_bytes, va):
            if count >= self.MAX_INSTRUCTIONS_PER_SECTION:
                section_errors.append(
                    f"Instruction cap ({self.MAX_INSTRUCTIONS_PER_SECTION}) reached — "
                    "section truncated."
                )
                break
            raw_instructions.append(insn)
            instruction_start_set.add(insn.address)
            count += 1

        # Second pass: annotate instructions with control-flow metadata.
        for insn in raw_instructions:
            decoded = self._annotate_instruction(insn, instruction_start_set, va, raw_size)
            instructions.append(decoded)

        # Reconstruct basic blocks.
        basic_blocks = self._reconstruct_basic_blocks(instructions, instruction_start_set)

        # Run loop detection over each block.
        loops: List[LoopDetectionResult] = []
        for block in basic_blocks:
            result = self._detect_loop(block, instruction_start_set)
            if result.detected:
                loops.append(result)
                # Back-annotate the block with loop participation flags.
                block.is_loop_latch = True
                block.back_edge_targets = [result.loop_header_address] if result.loop_header_address else []
                # Mark the header block if it exists in the block list.
                if result.loop_header_address is not None:
                    for b in basic_blocks:
                        if b.start_address == result.loop_header_address:
                            b.is_loop_header = True
                            if block.start_address not in b.predecessors:
                                b.predecessors.append(block.start_address)

        coverage_bytes = sum(i.size for i in instructions)
        coverage_percent = round((coverage_bytes / raw_size) * 100, 2) if raw_size > 0 else 0.0

        return SectionDisassembly(
            section_name=section_name,
            virtual_address=va,
            virtual_address_hex=f"0x{va:016x}",
            raw_offset=raw_offset,
            raw_size=raw_size,
            capstone_arch=arch_label,
            capstone_mode=mode_label,
            instructions=instructions,
            basic_blocks=basic_blocks,
            loops=loops,
            total_instructions=len(instructions),
            total_basic_blocks=len(basic_blocks),
            total_loops_detected=len(loops),
            coverage_bytes=coverage_bytes,
            coverage_percent=coverage_percent,
            section_errors=section_errors,
        )

    # ------------------------------------------------------------------
    # Instruction annotation
    # ------------------------------------------------------------------

    def _annotate_instruction(
        self,
        insn: "capstone.CsInsn",
        instruction_start_set: set,
        section_va: int,
        section_raw_size: int,
    ) -> DisassembledInstruction:
        """Annotates a raw Capstone instruction with control-flow metadata."""
        groups = insn.groups if hasattr(insn, "groups") else []

        is_jump = CS_GRP_JUMP in groups
        is_branch_rel = (
            CS_GRP_BRANCH_RELATIVE is not None and CS_GRP_BRANCH_RELATIVE in groups
        )
        is_call = CS_GRP_CALL in groups
        is_ret = CS_GRP_RET in groups or CS_GRP_IRET in groups
        is_privileged = CS_GRP_PRIVILEGE in groups
        is_branch = is_jump or is_branch_rel

        mnemonic_upper = insn.mnemonic.upper()
        is_conditional = mnemonic_upper in _SIGNED_BRANCHES | _UNSIGNED_BRANCHES | _ZERO_BRANCHES
        is_unconditional = mnemonic_upper in ("JMP", "JMPQ") and not is_conditional

        # Resolve branch target for direct branches.
        branch_target: Optional[int] = None
        branch_target_hex: Optional[str] = None
        branch_target_in_section: Optional[bool] = None
        branch_target_on_boundary: Optional[bool] = None
        branch_type_str: Optional[str] = None

        if is_branch or is_call:
            op_str = insn.op_str.strip()
            # Only resolve numeric (direct) targets; skip register-indirect targets.
            if op_str.startswith("0x") or op_str.lstrip("-").isdigit():
                try:
                    target = int(op_str, 16) if op_str.startswith("0x") else int(op_str)
                    branch_target = target
                    branch_target_hex = f"0x{target:016x}"
                    section_end = section_va + section_raw_size
                    branch_target_in_section = section_va <= target < section_end
                    branch_target_on_boundary = target in instruction_start_set

                    if is_call:
                        branch_type_str = "call"
                    elif is_unconditional:
                        branch_type_str = (
                            "unconditional_back_edge" if target < insn.address else "unconditional"
                        )
                    elif is_conditional:
                        branch_type_str = (
                            "conditional_back_edge" if target < insn.address else "conditional_forward"
                        )
                    else:
                        branch_type_str = "indirect"
                except (ValueError, OverflowError):
                    branch_type_str = "indirect"

        # Extract register reads/writes from Capstone detail.
        reads_regs: List[str] = []
        writes_regs: List[str] = []
        try:
            if hasattr(insn, "regs_read") and insn.regs_read:
                reads_regs = [insn.reg_name(r).upper() for r in insn.regs_read]
            if hasattr(insn, "regs_write") and insn.regs_write:
                writes_regs = [insn.reg_name(r).upper() for r in insn.regs_write]
        except Exception:
            pass

        # Detect memory operand from op_str heuristically.
        # Bracket presence indicates a memory dereference.
        # For x86: destination is the first operand, source is the second.
        #   MOV [rbp-4], eax  → writes_memory  (bracket in first operand)
        #   MOV eax, [rbp-4]  → reads_memory   (bracket in second operand)
        #   ADD eax, [rbp-8]  → reads_memory
        #   CMP eax, [rbp-4]  → reads_memory
        #   PUSH rbp          → no bracket → no memory flag (stack ops handled by register tracking)
        op_str = insn.op_str
        has_bracket = "[" in op_str
        reads_memory = False
        writes_memory = False
        if has_bracket:
            comma_pos = op_str.find(",")
            bracket_pos = op_str.find("[")
            if comma_pos == -1:
                # Single-operand instruction with bracket (e.g., PUSH [rbp-4], JMP [rax])
                reads_memory = True
            elif bracket_pos < comma_pos:
                # Bracket is in the destination (first) operand → memory write
                writes_memory = True
            else:
                # Bracket is in the source (second) operand → memory read
                reads_memory = True
        memory_operand: Optional[str] = None
        if "[" in op_str:
            start = op_str.index("[")
            end = op_str.index("]", start) + 1
            memory_operand = op_str[start:end]

        return DisassembledInstruction(
            address=insn.address,
            address_hex=f"0x{insn.address:016x}",
            mnemonic=insn.mnemonic.upper(),
            op_str=insn.op_str,
            size=insn.size,
            bytes_hex=insn.bytes.hex(),
            is_branch=is_branch,
            is_conditional_branch=is_conditional,
            is_unconditional_branch=is_unconditional,
            is_call=is_call,
            is_ret=is_ret,
            is_privileged=is_privileged,
            branch_target=branch_target,
            branch_target_hex=branch_target_hex,
            branch_target_in_section=branch_target_in_section,
            branch_target_on_boundary=branch_target_on_boundary,
            branch_type=branch_type_str,
            reads_registers=reads_regs,
            writes_registers=writes_regs,
            reads_memory=reads_memory,
            writes_memory=writes_memory,
            memory_operand=memory_operand,
        )

    # ------------------------------------------------------------------
    # Basic block reconstruction
    # ------------------------------------------------------------------

    def _reconstruct_basic_blocks(
        self,
        instructions: List[DisassembledInstruction],
        instruction_start_set: set,
    ) -> List[BasicBlock]:
        """
        Reconstructs basic blocks from a flat instruction list using leader detection.

        Leaders (block entry points) are:
        1. The first instruction in the section.
        2. Any instruction that is the target of a branch.
        3. Any instruction that immediately follows a branch/call/ret.
        """
        if not instructions:
            return []

        # Collect leader addresses.
        leaders: set = {instructions[0].address}
        for insn in instructions:
            if insn.is_branch or insn.is_call or insn.is_ret:
                # The instruction after this one is a leader.
                next_addr = insn.address + insn.size
                if next_addr in instruction_start_set:
                    leaders.add(next_addr)
                # The branch target is a leader.
                if insn.branch_target and insn.branch_target in instruction_start_set:
                    leaders.add(insn.branch_target)

        # Partition instructions into blocks.
        blocks: List[BasicBlock] = []
        current_block_insns: List[DisassembledInstruction] = []

        for insn in instructions:
            if insn.address in leaders and current_block_insns:
                blocks.append(self._finalize_block(current_block_insns))
                current_block_insns = []
            current_block_insns.append(insn)

        if current_block_insns:
            blocks.append(self._finalize_block(current_block_insns))

        # Build successor/predecessor edges.
        block_start_map: Dict[int, BasicBlock] = {b.start_address: b for b in blocks}
        for i, block in enumerate(blocks):
            last = block.instructions[-1]
            # Fall-through successor (if block doesn't end in unconditional branch/ret).
            if not last.is_ret and not last.is_unconditional_branch:
                fall_addr = last.address + last.size
                if fall_addr in block_start_map:
                    block.successors.append(fall_addr)
                    block_start_map[fall_addr].predecessors.append(block.start_address)
            # Branch target successor.
            if last.branch_target and last.branch_target in block_start_map:
                if last.branch_target not in block.successors:
                    block.successors.append(last.branch_target)
                    block_start_map[last.branch_target].predecessors.append(block.start_address)

        return blocks

    def _finalize_block(self, insns: List[DisassembledInstruction]) -> BasicBlock:
        """Creates a BasicBlock from an instruction list."""
        start = insns[0].address
        last = insns[-1]
        end = last.address
        byte_span = (last.address + last.size) - start
        return BasicBlock(
            block_id=f"bb_0x{start:016x}",
            start_address=start,
            end_address=end,
            instruction_count=len(insns),
            byte_span=byte_span,
            instructions=insns,
        )

    # ------------------------------------------------------------------
    # Loop detection heuristic
    # ------------------------------------------------------------------

    def _detect_loop(
        self,
        block: BasicBlock,
        instruction_start_set: set,
    ) -> LoopDetectionResult:
        """
        Identifies loop patterns in a basic block by detecting back-edge branches.

        Algorithm:
        1. Examine the terminating branch instruction of the block.
        2. A back-edge is defined as: branch_target < block.start_address.
        3. If a back-edge exists, scan backwards through the block for the closest
           CMP or TEST instruction to extract the comparison operands and bound.
        4. Classify the branch mnemonic to determine signed/unsigned comparison type.
        5. Validate the back-edge target against the instruction start address set.

        Anomaly detection:
        - 'branch_target_not_on_instruction_boundary': target not in instruction_start_set.
        - 'missing_write_back': no write to a memory location ([...]) in the block
          when a register-to-memory operand was read by the opening MOV.
        - 'byte_encoding_mismatch': branch target from op_str doesn't match
          the target computed from raw bytes (requires byte re-decode, flagged
          as a validation hint only — not computed here to avoid double-decoding).
        """
        no_loop = LoopDetectionResult(
            detected=False,
            loop_latch_address=block.start_address,
        )

        if not block.instructions:
            return no_loop

        terminator = block.instructions[-1]

        # Condition 1: must be a branch instruction with a resolved direct target.
        if not terminator.is_branch or terminator.branch_target is None:
            return no_loop

        # Condition 2: back-edge — target is at or before the start of this block.
        if terminator.branch_target >= block.start_address:
            return no_loop

        # Back-edge confirmed. Determine branch type classification.
        mnemonic_upper = terminator.mnemonic.upper()
        branch_type_str, is_signed = _BRANCH_TYPE_MAP.get(
            mnemonic_upper, ("unknown", False)
        )

        # Scan backwards for the closest CMP or TEST instruction.
        cmp_mnemonic: Optional[str] = None
        cmp_lhs: Optional[str] = None
        cmp_rhs: Optional[str] = None
        loop_bound_immediate: Optional[int] = None
        loop_bound_register: Optional[str] = None
        bound_type: Optional[str] = None

        for insn in reversed(block.instructions[:-1]):
            if insn.mnemonic.upper() in ("CMP", "TEST", "CMPL", "CMPQ", "CMPW", "CMPB"):
                cmp_mnemonic = insn.mnemonic.upper()
                parts = [p.strip() for p in insn.op_str.split(",")]
                if len(parts) == 2:
                    cmp_lhs = parts[0].upper()
                    cmp_rhs_raw = parts[1]
                    # Determine if RHS is an immediate or a register.
                    try:
                        if cmp_rhs_raw.startswith("0x"):
                            loop_bound_immediate = int(cmp_rhs_raw, 16)
                        else:
                            loop_bound_immediate = int(cmp_rhs_raw, 10)
                        cmp_rhs = cmp_rhs_raw
                        bound_type = "constant"
                    except ValueError:
                        # RHS is a register or complex expression.
                        cmp_rhs = cmp_rhs_raw.upper()
                        loop_bound_register = cmp_rhs
                        bound_type = "variable"
                break

        # Anomaly: does the back-edge target land on a known instruction boundary?
        anomalies: List[str] = []
        if terminator.branch_target not in instruction_start_set:
            anomalies.append("branch_target_not_on_instruction_boundary")

        # Anomaly: missing write-back — block reads [rbp±N] but never writes [rbp±N].
        mem_reads = {i.memory_operand for i in block.instructions if i.reads_memory and i.memory_operand}
        mem_writes = {i.memory_operand for i in block.instructions if i.writes_memory and i.memory_operand}
        if mem_reads and not (mem_reads & mem_writes):
            anomalies.append("missing_write_back")

        return LoopDetectionResult(
            detected=True,
            loop_latch_address=block.start_address,
            loop_header_address=terminator.branch_target,
            branch_mnemonic=mnemonic_upper,
            branch_type=branch_type_str,
            is_signed_comparison=is_signed,
            cmp_mnemonic=cmp_mnemonic,
            cmp_lhs=cmp_lhs,
            cmp_rhs=cmp_rhs,
            loop_bound_immediate=loop_bound_immediate,
            loop_bound_register=loop_bound_register,
            bound_type=bound_type,
            anomalies=anomalies,
        )

    # ------------------------------------------------------------------
    # Artifact persistence
    # ------------------------------------------------------------------

    def save_disassembly_artifact(
        self,
        project_dir: Path,
        file_id: str,
        artifact_dict: Dict[str, Any],
    ) -> Path:
        """
        Persists the DisassemblyArtifact atomically to
        projects/{project_id}/analysis/{file_id}/disassembly.json.
        """
        analysis_dir = project_dir / "analysis" / file_id
        analysis_dir.mkdir(parents=True, exist_ok=True)

        target_path = analysis_dir / "disassembly.json"
        temp_path = analysis_dir / "disassembly.json.tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(artifact_dict, f, indent=2)
            temp_path.replace(target_path)
            logger.info("Disassembly artifact written: path='%s'", target_path)
            return target_path
        except Exception as err:
            if temp_path.exists():
                temp_path.unlink()
            logger.error(
                "Failed to write disassembly artifact for file_id='%s': %s", file_id, err
            )
            raise IOError(f"Could not write disassembly artifact: {err}") from err

    # ------------------------------------------------------------------
    # Context resolution helpers
    # ------------------------------------------------------------------

    def _resolve_binary_context(
        self,
        existing_metadata: Dict[str, Any],
    ) -> Tuple[str, int, str, Dict[str, Any]]:
        """
        Extracts architecture, bitness, endianness, and section metadata
        from the UnifiedExecutableModel populated by a prior parser engine.

        Checks PE → ELF → Mach-O → BinaryIntelligence fallback in that order.
        Returns (arch_str, bitness, endianness, sections_dict).
        """
        engine_meta = existing_metadata.get("engine_metadata", {})

        for engine_key in ("pe_parser", "elf_parser", "macho_parser"):
            parsed = engine_meta.get(engine_key, {}).get("parsed_data", {})
            unified = parsed.get("unified_model")
            if unified and unified.get("architecture") and unified["architecture"] != "Unknown":
                # PE and Mach-O store sections under "sections";
                # ELF stores them under "section_headers".
                sections_raw = parsed.get("sections") or parsed.get("section_headers") or []
                # Convert list of section dicts to name-keyed dict.
                sections_dict: Dict[str, Any] = {}
                for sec in sections_raw:
                    name = sec.get("name") or sec.get("section_name") or "unknown"
                    sections_dict[name] = {
                        "virtual_address_raw": sec.get("address_raw", sec.get("virtual_address_raw", 0)),
                        "raw_offset": sec.get("raw_offset", sec.get("offset", 0)),
                        "raw_size": sec.get("raw_size", sec.get("size", 0)),
                        "entropy": sec.get("entropy", 0.0),
                    }
                return (
                    unified["architecture"],
                    unified.get("bitness", 64),
                    unified.get("endianness", "little"),
                    sections_dict,
                )

        # Fallback: use BinaryIntelligenceEngine fields.
        bi = engine_meta.get("binary_intelligence", {})
        arch = bi.get("detected_architecture", "x86_64") or "x86_64"
        return arch, 64, "little", {}

    def _get_entry_point(self, existing_metadata: Dict[str, Any]) -> Optional[str]:
        """Extracts entry point hex string from the first available format parser."""
        engine_meta = existing_metadata.get("engine_metadata", {})
        for engine_key in ("pe_parser", "elf_parser", "macho_parser"):
            parsed = engine_meta.get(engine_key, {}).get("parsed_data", {})
            ep = parsed.get("entry_point")
            if ep:
                return ep
        return None

    def _select_capstone_mode(
        self,
        arch_str: str,
        bitness: int,
        endianness: str,
        errors: List[str],
    ) -> Tuple[Optional[int], Optional[int], str, str]:
        """
        Maps architecture string and bitness to Capstone arch/mode constants.
        Returns (cs_arch, cs_mode, arch_label, mode_label) or (None, None, ...) on failure.
        """
        endian_mode = CS_MODE_BIG_ENDIAN if endianness == "big" else CS_MODE_LITTLE_ENDIAN
        arch_lower = arch_str.lower()

        if "x86_64" in arch_lower or "amd64" in arch_lower:
            return CS_ARCH_X86, CS_MODE_64, "CS_ARCH_X86", "CS_MODE_64"

        if "x86" in arch_lower or "i386" in arch_lower or "i686" in arch_lower:
            return CS_ARCH_X86, CS_MODE_32, "CS_ARCH_X86", "CS_MODE_32"

        if "arm64" in arch_lower or "aarch64" in arch_lower:
            return CS_ARCH_ARM64, CS_MODE_ARM, "CS_ARCH_ARM64", "CS_MODE_ARM"

        if "arm" in arch_lower:
            mode = CS_MODE_THUMB if "thumb" in arch_lower else CS_MODE_ARM
            mode_label = "CS_MODE_THUMB" if "thumb" in arch_lower else "CS_MODE_ARM"
            return CS_ARCH_ARM, mode | endian_mode, "CS_ARCH_ARM", mode_label

        if "mips64" in arch_lower:
            return CS_ARCH_MIPS, CS_MODE_MIPS64 | endian_mode, "CS_ARCH_MIPS", "CS_MODE_MIPS64"

        if "mips" in arch_lower:
            return CS_ARCH_MIPS, CS_MODE_MIPS32 | endian_mode, "CS_ARCH_MIPS", "CS_MODE_MIPS32"

        if "powerpc" in arch_lower or "ppc" in arch_lower:
            return CS_ARCH_PPC, endian_mode, "CS_ARCH_PPC", "CS_MODE_BIG_ENDIAN"

        errors.append(
            f"Architecture '{arch_str}' is not supported by CapstoneDisassemblyEngine."
        )
        return None, None, arch_str, "unsupported"

    def _is_executable_section(
        self,
        section_name: str,
        section_info: Dict[str, Any],
    ) -> bool:
        """
        Determines whether a section should be disassembled.
        Matches known code section names; skips .data, .rodata, .bss, etc.
        """
        name = section_name.strip().lower()
        # Accept known executable section names.
        for known in self.EXECUTABLE_SECTION_NAMES:
            if name == known.lower() or name.startswith(known.lower()):
                return True
        # Accept sections with non-zero raw size.
        # Additional filter: exclude obvious data sections.
        data_sections = {".data", ".rodata", ".bss", ".got", ".got.plt", ".rdata",
                         "__data", "__bss", "__rodata", ".idata", ".edata", ".rsrc", ".reloc"}
        if name in {s.lower() for s in data_sections}:
            return False
        # Default: attempt disassembly if raw_size > 0.
        return section_info.get("raw_size", 0) > 0

    # ------------------------------------------------------------------
    # Result injection helper (mirrors other engines' return pattern)
    # ------------------------------------------------------------------

    def _inject_engine_result(
        self,
        existing_metadata: Dict[str, Any],
        artifact_dict: Dict[str, Any],
        errors: List[str],
        start_time: float,
    ) -> Dict[str, Any]:
        """Merges engine output into the accumulated metadata dict."""
        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        engine_meta = existing_metadata.get("engine_metadata", {})
        engine_meta[self.engine_name] = {
            "engine_version": self.engine_version,
            "execution_time_ms": exec_time_ms,
            "capstone_available": CAPSTONE_AVAILABLE,
            "parsed_data": artifact_dict,
        }
        existing_metadata["engine_metadata"] = engine_meta

        if errors:
            existing_metadata.setdefault("errors", []).extend(errors)

        return existing_metadata

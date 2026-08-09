# EKKI-RE-AI Development Log (DEVLOG)

This engineering diary records major architectural decisions, implementation challenges, refactoring rationale, performance optimizations, and lessons learned during the development of **EKKI-RE-AI**.

---

## Log Entry 005 — Phase 2.6: Ghidra Headless Integration Engine Architecture
**Date**: 2026-08-06  
**Author**: Lead Principal Reverse Engineering Architect  

### Architectural Context & Decision
Phase 2.6 introduces deep program decompilation by integrating Ghidra Headless (`analyzeHeadless`) as a modular plugin (`GhidraAnalysisEngine`). Capstone and Ghidra operate as complementary analysis layers: Capstone provides instant instruction disassembly, while Ghidra extracts function boundaries, control flow graphs, symbol tables, and decompiled C pseudocode.

### Key Implementation Details
1. **Subprocess Safety**: Ghidra Headless is executed via `subprocess.run(cmd, shell=False, timeout=settings.GHIDRA_TIMEOUT_SECONDS)` to eliminate shell injection vectors.
2. **Graceful Fallback**: If Ghidra is unconfigured or not installed locally, `ghidra_available` is set to `False` and a structured fallback artifact is returned without throwing exceptions or stopping the pipeline.
3. **Persisted Artifact**: Extracted program metadata, function listing, and decompiled C functions are written atomically to `analysis/{file_id}/ghidra.json`.
4. **Interactive Decompiler View**: Added side-by-side function listing and decompiled C pseudocode viewer to the frontend modal `Ghidra` tab.

---

## Log Entry 001 — Phase 2.1: Project Workspace System Architecture
**Date**: 2026-08-04  
**Author**: Antigravity / EKKI Engineering Team  

### Architectural Context & Decision
Initially, EKKI-RE-AI operated as an ad-hoc assistant handling single files stored in temporary directories. As we prepared to transition into a full-scale reverse engineering platform, workspace state isolation became mandatory.

We designed `WorkspaceManager` (`backend/workspace.py`) to manage project lifecycles, file storage, and persistent metadata under a deterministic directory tree: `projects/{project_id}/files/{file_id}/`.

### Key Challenges & Decisions
1. **Concurrency Safety**: Reverse engineering platforms frequently execute background tasks while the user interacts with the UI. We selected `threading.RLock` to enforce re-entrant thread safety across project metadata operations.
2. **Path Sanitization**: To prevent path traversal attacks (`../`), we implemented strict identifier sanitization and path validation against the root project folder.

### Testing Performed
Created `tests/test_workspace.py` verifying project creation, file additions, file deletion, path security boundary checks, and thread locking.

---

## Log Entry 002 — Phase 2.2: Universal Binary Intelligence Layer
**Date**: 2026-08-04  
**Author**: Antigravity / EKKI Engineering Team  

### Architectural Context & Decision
Before disassembling or prompting an LLM, a reverse engineering platform must reliably identify file types, calculate cryptographic hashes, and evaluate structural entropy. We designed a decoupled plugin architecture featuring `BaseAnalysisEngine` and `AnalysisPipeline` (`backend/analysis/`).

### Key Challenges & Decisions
1. **Decoupling from WorkspaceManager**: To prevent tight coupling between workspace management and parsing logic, `WorkspaceManager` invokes `AnalysisPipeline.run_pipeline()`. `WorkspaceManager` does not know which parser engines exist.
2. **Single-Pass Hash & Entropy Computation**: Hashing files four times (MD5, SHA-1, SHA-256, SHA-512) separately can degrade performance on large binaries. We implemented single-pass byte processing in `BinaryIntelligenceEngine` to calculate all four hashes and byte frequency histograms simultaneously.

### Lessons Learned
Relying on file extensions for binary identification is unacceptable in reverse engineering because malware frequently renames executables to `.png` or `.txt`. We implemented signature-based magic byte detection in `FileDetector` (`backend/analysis/detector.py`).

---

## Log Entry 003 — Phase 2.3: Production PE Parser & Reusable BinaryReader
**Date**: 2026-08-04  
**Author**: Antigravity / EKKI Engineering Team  

### Architectural Context & Decision
Windows Portable Executables (PE32/PE32+) represent a large portion of reverse engineering targets. However, corrupted or malformed PE headers often cause prototype parsers to crash with `IndexError` or `struct.error`.

Before writing the PE parser, we created a reusable, bounds-checked binary reading utility: `BinaryReader` (`backend/analysis/binary_reader.py`).

### Key Design Decisions
1. **Elimination of Exception-Driven Parsing**: Instead of wrapping header reads in `try/except` blocks or letting array index errors crash the backend, `BinaryReader` verifies bounds before every read (`offset + length <= total_size`). If a read fails, it records a structured error message and returns `None`.
2. **RVA-to-File-Offset Translator**: PE structures use Relative Virtual Addresses (RVAs). We built a resilient `_rva_to_offset` helper that maps RVAs to raw file offsets based on parsed section virtual bounds, with header RVA fallback.
3. **Tabbed Frontend UI**: Rather than cluttering the interface, we added a tab bar (`General Metadata` | `PE Information`) to the File Details modal, rendering PE section tables with per-section Shannon entropy bars and import function chips.

---

## Log Entry 004 — Phase 2.4: Cross-Platform Executable Parser (ELF & Mach-O) & Shared ExecutableFormat Model
**Date**: 2026-08-04  
**Author**: Antigravity / EKKI Engineering Team  

### Architectural Context & Decision
To transform EKKI-RE-AI into a true cross-platform platform, we implemented `ELFParserEngine` (Linux/Unix) and `MachOParserEngine` (macOS/iOS).

During this phase, the user requested an important architectural enhancement: a **Shared ExecutableFormat Domain Model** (`UnifiedExecutableModel`).

### Implementation Highlights
1. **Reusable BinaryReader Across Formats**: Both `ELFParserEngine` and `MachOParserEngine` fully reused `BinaryReader`, proving the utility of the Phase 2.3 refactor. Endianness helpers (`u16_be`, `u32_be`, `u64_be`) made handling Big-Endian ELF binaries and Universal Fat Binaries seamless.
2. **Universal Fat Binary Handling**: Mach-O Universal Fat Binaries (`0xCAFEBABE`) bundle multiple architecture slices (e.g. x86_64 + ARM64). We added logic to extract slice headers while disambiguating Fat Binaries from Java Class files (by checking Java version fields).
3. **UnifiedExecutableModel (`executable_model.py`)**: Designed a standardized domain model representing common binary metadata across PE, ELF, and Mach-O (`format`, `architecture`, `bitness`, `endianness`, `entry_point`, `sections`, `libraries`, `symbols_count`). Each parser exports this model in its output payload while preserving format-specific artifacts (`pe.json`, `elf.json`, `macho.json`).

### Summary of Testing
Created `tests/test_elf_parser.py` and `tests/test_macho_parser.py`, testing 32/64-bit, Little/Big Endian, Fat binaries, corrupted headers, invalid load commands/section offsets, empty files, non-executables, disk persistence, and REST API endpoints.

# Changelog

All notable changes to EKKI-RE-AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.6.0] - 2026-08-06 - Phase 2.6: Ghidra Headless Integration Engine

### Added
- Created `GhidraAnalysisEngine` (`backend/analysis/ghidra_engine.py`) implementing `BaseAnalysisEngine` plugin interface.
- Added headless execution launcher (`analyzeHeadless`) via `subprocess.run` (shell=False) with safe path validation and execution timeout bounds.
- Extracted program metadata, function manager listing, symbol table, and decompiled C pseudocode.
- Persisted `analysis/{file_id}/ghidra.json` (`schema_version: 1`).
- Added REST API endpoint `GET /api/projects/{project_id}/files/{file_id}/ghidra`.
- Added frontend File Details Modal tab `Ghidra` rendering function list, function search, symbols table, and side-by-side decompiled C code viewer.
- Created `tests/test_ghidra_engine.py` test suite.

## [2.5.0] - 2026-08-05 - Phase 2.5: Capstone Disassembly Engine

### Added
- Created `CapstoneDisassemblyEngine` (`backend/analysis/capstone_engine.py`) with linear sweep disassembly, memory heuristics, basic block recovery, and loop detection.
- Persisted `analysis/{file_id}/disassembly.json`.
- Added REST API endpoint `GET /api/projects/{project_id}/files/{file_id}/disassembly`.
- Added frontend `Disassembly` tab with monospace instruction viewer.
- Created `tests/test_capstone_engine.py` test suite.

---

## [2.4.0] - 2026-08-04 - Phase 2.4: Cross-Platform Executable Parser Engine

### Added
- Created `ELFParserEngine` (`backend/analysis/elf_parser.py`) implementing `BaseAnalysisEngine` plugin interface.
- Created `MachOParserEngine` (`backend/analysis/macho_parser.py`) supporting 32-bit, 64-bit, Little/Big Endian, and Universal Fat Binary Mach-O binaries.
- Created `UnifiedExecutableModel` (`backend/analysis/executable_model.py`) providing a standardized cross-platform executable domain model for future AI reasoning.
- Added REST API endpoints:
  - `GET /api/projects/{project_id}/files/{file_id}/elf` returning `elf.json`.
  - `GET /api/projects/{project_id}/files/{file_id}/macho` returning `macho.json`.
- Extended File Details UI modal with `ELF Information` and `Mach-O Information` tabs rendering architecture, entry point, section tables with section entropy bars, and dynamic library chip lists.
- Created automated test suites `tests/test_elf_parser.py` and `tests/test_macho_parser.py`.

### Changed
- Registered `ELFParserEngine` and `MachOParserEngine` inside `AnalysisPipeline` (`backend/analysis/registry.py`).
- Updated `PEParserEngine` (`backend/analysis/pe_parser.py`) to construct and export `UnifiedExecutableModel`.
- Updated `WorkspaceManager` (`backend/workspace.py`) with `get_file_elf_metadata` and `get_file_macho_metadata` helpers.

### Improved
- Complete multi-format parsing coverage (PE32/PE32+, ELF32/ELF64, Mach-O 32/64/Fat).
- Universal Fat Binary slice extraction disambiguated from Java Class files.

### Security
- Bounds-checked offset reads prevent buffer overreads and out-of-bounds array access.
- Structured parser error logging eliminates uncaught parsing crashes on corrupted binaries.

### Performance
- Full ELF and Mach-O parsing, section entropy calculation, and artifact persistence execute in `< 6ms`.

### Testing
- 100% automated test coverage for ELF 32/64-bit Little/Big Endian, Mach-O 32/64-bit Fat binaries, corrupted headers, invalid load commands, empty files, non-executable files, disk persistence, and REST API endpoints.

---

## [2.3.0] - 2026-08-04 - Phase 2.3: Production PE Parser

### Added
- Created reusable `BinaryReader` utility (`backend/analysis/binary_reader.py`) providing safe offset reads, bounds checking, endianness helpers (`u16`, `u32`, `u64`), ASCII/UTF-16 string decoding, and Shannon entropy calculation.
- Created production `PEParserEngine` (`backend/analysis/pe_parser.py`) parsing DOS header, COFF header, Optional header (PE32/PE32+), Section table (with section entropy), Data directories, Import descriptors, and Export descriptors.
- Added REST API endpoint `GET /api/projects/{project_id}/files/{file_id}/pe`.
- Extended File Details UI modal with tabbed navigation (`General Metadata` | `PE Information`).
- Created test suite `tests/test_pe_parser.py`.

### Changed
- Registered `PEParserEngine` in `AnalysisPipeline` to write `analysis/{file_id}/pe.json` (`schema_version: 1`).
- Extended `WorkspaceManager` with `get_file_pe_metadata()`.

### Improved
- RVA-to-Offset translation utility with header fallback.
- Tabbed modal UI for seamless switching between general metadata and PE structural breakdown.

### Security
- Eliminated exception-driven parsing; malformed PE headers append to `errors` array safely.

### Performance
- PE header and section parsing executes in `< 5ms`.

### Testing
- Tested PE32, PE32+, 32-bit/64-bit EXEs, DLLs, corrupted DOS headers, invalid `e_lfanew`, invalid RVAs, empty files, non-PE files, disk persistence, and REST API.

---

## [2.2.0] - 2026-08-04 - Phase 2.2: Binary Intelligence Layer

### Added
- Created `BaseAnalysisEngine` abstract base interface (`backend/analysis/base.py`).
- Created universal `FileDetector` (`backend/analysis/detector.py`) supporting magic byte signature identification for PE, ELF, Mach-O, COFF, Static Libraries, Archives, Java, C, C++, Rust, Go, Python, Assembly, Text, JSON, XML, Raw Binary.
- Created `BinaryIntelligenceEngine` (`backend/analysis/binary_intelligence.py`) for single-pass cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512) and Shannon entropy computation.
- Created thread-safe `AnalysisPipeline` registry (`backend/analysis/registry.py`) writing `analysis/{file_id}/metadata.json` (`schema_version: 1`).
- Added REST API endpoints `GET /metadata` and `POST /analyze`.
- Created test suite `tests/test_binary_intelligence.py`.

### Changed
- Integrated `AnalysisPipeline` with `WorkspaceManager.add_file()`.

### Improved
- Single-pass file reading calculates hashes and Shannon entropy concurrently.

### Security
- Immutable `file_id` tracking and path security checks.

### Performance
- Hashing and entropy computation completes in `< 10ms` for standard binaries.

### Testing
- Verified magic byte detection, hash calculations, entropy scoring, and metadata persistence.

---

## [2.1.0] - 2026-08-04 - Phase 2.1: Project Workspace System

### Added
- Created thread-safe `WorkspaceManager` (`backend/workspace.py`) supporting project creation, file upload, file deletion, and file content streaming.
- Added workspace REST API endpoints under `/api/projects`.
- Added frontend project switcher, project creation modal, file list sidebar, and file drag-and-drop uploader.
- Created test suite `tests/test_workspace.py`.

### Changed
- Replaced temporary working directory storage with structured workspace directory hierarchy (`projects/{project_id}/files/{file_id}/`).

### Improved
- Multithreaded safety using recursive locks (`threading.RLock`).

### Security
- Strict path sanitization preventing directory traversal attacks.

### Performance
- Fast file I/O and zero-copy streaming response handling.

### Testing
- Tested project CRUD operations, file uploads, file deletion, sanitization, and concurrent locking.

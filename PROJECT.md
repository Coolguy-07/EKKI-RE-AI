# PROJECT: EKKI-RE-AI

## Project Overview

**EKKI-RE-AI** is a production-grade, AI-assisted reverse engineering platform designed to inspect, identify, and analyze binary files across multiple operating systems (**Windows PE**, **Linux ELF**, and **macOS Mach-O**) prior to disassembly or LLM reasoning.

The core philosophy of EKKI-RE-AI is **Binary Intelligence First**: raw uploaded files are systematically ingested, validated, hashed, and structurally parsed into structured JSON metadata artifacts. AI models consume these structured metadata artifacts rather than raw binary blobs.

---

## Current Features

### 1. Project Workspace System (Phase 2.1)
- Thread-safe project workspace management (`WorkspaceManager`).
- Isolated directory hierarchy per project and file: `projects/{project_id}/files/{file_id}/`.
- REST API for project CRUD operations, file uploads, file deletion, and file content streaming.
- Frontend sidebar with active project switcher, drag-and-drop binary uploader, and file list view.

### 2. Universal Binary Intelligence Layer (Phase 2.2)
- Automatic magic-byte file signature identification supporting PE, ELF, Mach-O, COFF, Static Libraries, Archives, Java, C/C++, Rust, Go, Python, Assembly, Text, JSON, XML, and Raw Binary.
- Single-pass cryptographic hash calculation (MD5, SHA-1, SHA-256, SHA-512).
- Full-file Shannon entropy computation ($0.0 - 8.0$) with color-coded UI progress bar.
- Metadata persistence under `projects/{project_id}/analysis/{file_id}/metadata.json` (`schema_version: 1`).

### 3. Reusable Binary Reader Utility (Phase 2.3)
- Bounds-checked binary reading utility (`BinaryReader`) enforcing safe offset reads (`offset + length <= total_size`).
- Endian-aware integer unpackers (`u8`, `u16_le`, `u16_be`, `u32_le`, `u32_be`, `u64_le`, `u64_be`).
- Null-terminated ASCII string extraction and UTF-16 string decoding.
- Slice Shannon entropy calculation over arbitrary byte ranges.
- Structured parser error tracking eliminating uncaught parsing crashes.

### 4. Production PE Parser Engine (Phase 2.3)
- Structural parsing for Windows Portable Executables (PE32 & PE32+).
- DOS Header (`e_magic`, `e_lfanew`), COFF Header (Machine, NumberOfSections, TimeDateStamp, Characteristics), Optional Header (Magic, EntryPoint, ImageBase, Subsystem, DllCharacteristics).
- Section Table parsing with per-section Shannon entropy calculation.
- Data Directories, Import Table (DLL names, imported function names/ordinals), and Export Table.
- Persisted artifact under `projects/{project_id}/analysis/{file_id}/pe.json`.

### 5. Cross-Platform Executable Parser Engine (Phase 2.4)
- **ELF Parser Engine (`ELFParserEngine`)**:
  - 32-bit & 64-bit, Little-Endian & Big-Endian ELF binaries.
  - ELF Header (magic, class, endianness, OS ABI, type, machine, entry point).
  - Program Headers (`PT_LOAD`, `PT_INTERP` interpreter path, `PT_DYNAMIC`, `PT_NOTE`, `PT_GNU_STACK`).
  - Section Headers with per-section Shannon entropy.
  - Dynamic Section `DT_NEEDED` shared library dependencies.
  - Symbols table (`.symtab` / `.dynsym`).
  - Persisted artifact under `projects/{project_id}/analysis/{file_id}/elf.json`.
- **Mach-O Parser Engine (`MachOParserEngine`)**:
  - 32-bit (`0xFEEDFACE`), 64-bit (`0xFEEDFACF`), Little/Big Endian, and Universal Fat Binaries (`0xCAFEBABE`).
  - Mach Header (magic, cpu_type, cpu_subtype, file_type, flags).
  - Load Commands (`LC_SEGMENT`, `LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_UUID`, `LC_MAIN`, `LC_SYMTAB`, `LC_CODE_SIGNATURE`).
  - Segments & Sections with per-section Shannon entropy.
  - Dynamic Libraries (`LC_LOAD_DYLIB`), 128-bit UUID, Entry Point (`LC_MAIN`), Code Signature.
  - Persisted artifact under `projects/{project_id}/analysis/{file_id}/macho.json`.

### 6. Shared ExecutableFormat Model (Phase 2.4)
- Standardized cross-platform executable domain model (`UnifiedExecutableModel`) representing common metadata across PE, ELF, and Mach-O executables for future AI reasoning.

### 7. Multi-Agent AI System (Phase 1)
- Isolated session conversation memory (`SessionMemory`).
- Intent routing (`IntentRouter`) classifying prompts to specialized agents (`BINARY_ANALYSIS`, `CODE_ANALYSIS`, `GENERAL`).
- Multi-agent collaboration orchestrator (`AgentOrchestrator`).
- Ollama local LLM client integration (`OllamaClient`).

---

## Supported Binary Formats

| Format | Bitness | Endianness | Architectures | Parsed Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **PE (Windows)** | 32-bit (PE32), 64-bit (PE32+) | Little Endian | x86, x86_64, ARM, ARM64 | `pe.json` |
| **ELF (Linux/Unix)** | 32-bit (ELF32), 64-bit (ELF64) | Little Endian, Big Endian | x86, x86_64, ARM, ARM64, RISC-V, MIPS, PPC | `elf.json` |
| **Mach-O (macOS/iOS)** | 32-bit, 64-bit, Universal Fat | Little Endian, Big Endian | x86, x86_64, ARM, ARM64 | `macho.json` |

---

## Current Analysis Pipeline Architecture

```
File Upload
    │
    ▼
WorkspaceManager.add_file()
    │
    ▼
AnalysisPipeline.run_pipeline()
    ├── 1. BinaryIntelligenceEngine ──> metadata.json
    ├── 2. PEParserEngine ─────────────> pe.json + UnifiedExecutableModel
    ├── 3. ELFParserEngine ────────────> elf.json + UnifiedExecutableModel
    └── 4. MachOParserEngine ──────────> macho.json + UnifiedExecutableModel
```

---

## REST API Overview

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/projects` | `GET`, `POST` | List projects or create a new workspace project |
| `/api/projects/{id}` | `GET`, `DELETE` | Retrieve or delete a project workspace |
| `/api/projects/{id}/files` | `GET`, `POST` | List files or upload a binary to trigger analysis pipeline |
| `/api/projects/{id}/files/{id}` | `GET`, `DELETE` | Download binary payload or delete file |
| `/api/projects/{id}/files/{id}/metadata` | `GET` | Retrieve structured `metadata.json` |
| `/api/projects/{id}/files/{id}/pe` | `GET` | Retrieve structured `pe.json` |
| `/api/projects/{id}/files/{id}/elf` | `GET` | Retrieve structured `elf.json` |
| `/api/projects/{id}/files/{id}/macho` | `GET` | Retrieve structured `macho.json` |
| `/chat` | `POST` | Single-agent chat interaction via Ollama |
| `/chat/stream` | `POST` | SSE streaming chat interface |
| `/chat/orchestrate` | `POST` | Multi-agent collaborative chat interface |

---

## Technology Stack

- **Backend**: Python 3.10+, FastAPI, Pydantic v2, Uvicorn, PyTest.
- **Frontend**: Vanilla HTML5, CSS3 (Custom Dark Cyber Theme), JavaScript ES6.
- **Binary I/O**: `BinaryReader` custom struct unpacking utility.
- **AI / LLM Integration**: Ollama local LLM client.

---

## Project Structure

```
EKKI-RE-AI/
├── backend/
│   ├── app.py                      # FastAPI REST application & endpoints
│   ├── workspace.py                # Project workspace manager & path security
│   ├── session_memory.py           # Thread-safe session memory manager
│   ├── intent_router.py            # AI intent classification router
│   ├── orchestrator.py             # Multi-agent collaboration orchestrator
│   ├── ollama_client.py            # Local Ollama client interface
│   └── analysis/
│       ├── __init__.py             # Analysis package exports
│       ├── base.py                 # Abstract BaseAnalysisEngine plugin interface
│       ├── binary_reader.py        # Reusable bounds-checked BinaryReader
│       ├── detector.py             # Universal file signature detector
│       ├── binary_intelligence.py  # Hashes & file entropy engine
│       ├── pe_parser.py            # Production PE parser engine
│       ├── elf_parser.py           # Production ELF parser engine
│       ├── macho_parser.py         # Production Mach-O parser engine
│       ├── executable_model.py     # Shared ExecutableFormat model
│       ├── models.py               # Pydantic schema models
│       └── registry.py             # AnalysisPipeline plugin runner
├── frontend/
│   ├── index.html                  # Main SPA interface & tabbed details modal
│   ├── script.js                   # Client logic, API client, tab switcher
│   └── style.css                   # Cyber dark design system & tables
├── tests/
│   ├── test_workspace.py           # Workspace manager tests
│   ├── test_binary_intelligence.py # Intelligence layer tests
│   ├── test_pe_parser.py           # PE parser engine tests
│   ├── test_elf_parser.py          # ELF parser engine tests
│   └── test_macho_parser.py        # Mach-O parser engine tests
├── ARCHITECTURE.md                 # System architecture documentation
├── CHANGELOG.md                    # Keep a Changelog history
├── DEVLOG.md                       # Engineering development log
├── PROJECT.md                      # Project capabilities documentation
└── ROADMAP.md                      # Milestone roadmap & planned phases
```

---

## Current Development Status

- **Phase 1 (Multi-Agent AI)**: ✅ **COMPLETED**
- **Phase 2.1 (Workspace System)**: ✅ **COMPLETED**
- **Phase 2.2 (Binary Intelligence)**: ✅ **COMPLETED**
- **Phase 2.3 (Production PE Parser)**: ✅ **COMPLETED**
- **Phase 2.4 (Cross-Platform Executable Parser)**: ✅ **COMPLETED & FROZEN**

---

## Future Vision

Upcoming phases will integrate assembly disassembly engines (**Capstone**), decompiler frameworks (**Ghidra**), pattern scanners (**YARA**), context builders, and multi-agent debate engines to make EKKI-RE-AI an industry-grade autonomous reverse engineering platform.

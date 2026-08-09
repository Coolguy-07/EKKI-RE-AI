# EKKI-RE-AI System Architecture

This document describes the software architecture, design patterns, component interactions, and data flow of **EKKI-RE-AI**, a production-grade reverse engineering and binary analysis platform.

---

## 1. System Overview & Data Flow

When a user uploads a binary file to EKKI-RE-AI, the binary flows through a decoupled, multi-layered processing pipeline before any LLM reasoning occurs:

```
                  ┌─────────────────────────────────────────┐
                  │            Web Browser UI               │
                  │   Vanilla HTML5 / CSS3 / JavaScript    │
                  └────────────────────┬────────────────────┘
                                       │ HTTP / REST API
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │             FastAPI Backend             │
                  │              (backend/app.py)           │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │            WorkspaceManager             │
                  │          (backend/workspace.py)         │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │            AnalysisPipeline             │
                  │           (backend/analysis/registry)   │
                  └─────┬──────────────┬──────────────┬─────┘
                        │              │              │
       ┌────────────────┴┐     ┌───────┴───────┐     ┌┴────────────────┐
       │BinaryIntelEngine│     │ PEParserEngine│     │ ELFParserEngine │ ... MachOParserEngine
       └────────┬────────┘     └───────┬───────┘     └────────┬────────┘
                │                      │                      │
                └──────────────────────┼──────────────────────┘
                                       ▼
                         ┌───────────────────────────┐
                         │   BinaryReader Utility    │
                         │(backend/analysis/binary_r)│
                         └─────────────┬─────────────┘
                                       │
                                       ▼
                         ┌───────────────────────────┐
                         │ Shared ExecutableFormat   │
                         │(UnifiedExecutableModel)   │
                         └─────────────┬─────────────┘
                                       │
                                       ▼
                         ┌───────────────────────────┐
                         │ Analysis Artifact Storage │
                         │ analysis/{file_id}/       │
                         │ ├─ metadata.json          │
                         │ ├─ pe.json                │
                         │ ├─ elf.json               │
                         │ ├─ macho.json             │
                         │ ├─ disassembly.json       │
                         │ └─ ghidra.json            │
                         └───────────────────────────┘
```

---

## 2. Core Components

### 2.1 Web Frontend (`frontend/`)
- **UI Architecture**: Single Page Application (SPA) built with Vanilla HTML5, CSS3 (CSS variables, dark-theme cyber aesthetic), and JavaScript (ES6 Modules).
- **File Details Modal System**: Tabbed modal supporting:
  - `General Metadata`: Cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512), Shannon entropy meter, file dimensions, MIME type.
  - `PE Information`: DOS header, COFF header, Optional header, PE section table with per-section entropy bars, imported DLLs & function chips.
  - `ELF Information`: ELF header (32/64-bit, Little/Big endian), Program headers, Section headers with per-section entropy bars, `PT_INTERP` interpreter path, `DT_NEEDED` dynamic libraries.
  - `Mach-O Information`: Mach header (32/64-bit, Universal Fat binary slices), Load commands, Segments & Sections with per-section entropy bars, `LC_LOAD_DYLIB` dynamic libraries, `LC_UUID`, Code Signature.
  - `Disassembly`: Monospace assembly instruction viewer, branch/call color highlights, basic block statistics, and loop detection results.
  - `Ghidra`: Function listing, recovered symbols table, processor/language summary, and side-by-side decompiled C pseudocode viewer.

### 2.2 FastAPI Backend (`backend/app.py`)
- **API Engine**: FastAPI app with CORS middleware, asynchronous request handling, and exception mapping.
- **REST Endpoints**:
  - `POST /api/projects`: Create project workspace.
  - `GET /api/projects`: List active projects.
  - `POST /api/projects/{id}/files`: Upload binary file and automatically run `AnalysisPipeline`.
  - `GET /api/projects/{id}/files/{id}/metadata`: Fetch `metadata.json`.
  - `GET /api/projects/{id}/files/{id}/pe`: Fetch `pe.json`.
  - `GET /api/projects/{id}/files/{id}/elf`: Fetch `elf.json`.
  - `GET /api/projects/{id}/files/{id}/macho`: Fetch `macho.json`.
  - `GET /api/projects/{id}/files/{id}/disassembly`: Fetch `disassembly.json`.
  - `GET /api/projects/{id}/files/{id}/ghidra`: Fetch `ghidra.json`.
  - `POST /chat`, `POST /chat/stream`, `POST /chat/orchestrate`: Multi-agent chat interfaces.

### 2.3 Workspace Manager (`backend/workspace.py`)
- **Thread Safety**: Uses recursive locks (`threading.RLock`) for concurrent project and file operations.
- **Path Security**: Prevents directory traversal attacks by validating all target paths against the workspace boundary.
- **Directory Structure**:
  ```
  projects/
  └── {project_id}/
      ├── project.json
      ├── files/
      │   └── {file_id}/
      │       └── sample_binary.exe
      └── analysis/
          └── {file_id}/
              ├── metadata.json
              ├── pe.json
              ├── elf.json
              ├── macho.json
              ├── disassembly.json
              └── ghidra.json
  ```

### 2.4 Reusable Binary Reader (`backend/analysis/binary_reader.py`)
- **`BinaryReader`**: Centralized, bounds-checked binary I/O utility.
- **Features**:
  - Safe offset reads with boundary validation (`offset + length <= total_size`).
  - Endian-aware integer unpackers (`u8`, `u16_le`, `u16_be`, `u32_le`, `u32_be`, `u64_le`, `u64_be`).
  - Null-terminated ASCII string extraction and UTF-16 decoding.
  - Shannon entropy calculation over arbitrary byte slices ($0.0 - 8.0$).
  - Accumulated error tracking without throwing uncaught Python exceptions.

### 2.5 Analysis Pipeline & Engine Plugin Architecture (`backend/analysis/`)
- **`BaseAnalysisEngine`**: Abstract base class enforcing `engine_name`, `engine_version`, and `analyze()` signature.
- **`AnalysisPipeline`**: Thread-safe plugin registry. Runs registered engines sequentially:
  1. `BinaryIntelligenceEngine`: Magic byte signature identification (PE, ELF, Mach-O, COFF, Archives, Scripts, Code, Raw Binary), single-pass cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512), and overall file entropy.
  2. `PEParserEngine`: Parses DOS header, COFF header, Optional header (PE32/PE32+), Section table (with per-section entropy), Data directories, Import descriptors, and Export descriptors.
  3. `ELFParserEngine`: Parses ELF header (32/64-bit, Little/Big endian), Program headers (`PT_LOAD`, `PT_INTERP`, `PT_DYNAMIC`), Section headers (with per-section entropy), Dynamic section (`DT_NEEDED`), Symbols, and Notes.
  4. `MachOParserEngine`: Parses Mach header (32/64-bit, Universal Fat binary slices), Load commands (`LC_SEGMENT`, `LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_UUID`, `LC_MAIN`), Segments, Sections (with per-section entropy), Symbols, and Code Signature.

### 2.6 Shared ExecutableFormat Model (`backend/analysis/executable_model.py`)
- **`UnifiedExecutableModel`**: Standardized domain model representing common binary metadata across PE, ELF, and Mach-O executables for future AI consumption:
  - `format`, `architecture`, `bitness`, `endianness`, `entry_point`, `image_base`, `subsystem_or_abi`, `is_executable`, `is_shared_library`, `sections`, `libraries`, `symbols_count`, `parser_name`, `parser_version`, `parser_errors`.

### 2.7 AI Multi-Agent Subsystem (`backend/`)
- **`SessionMemory`**: Thread-safe isolated conversation memory for workspace sessions.
- **`IntentRouter`**: Classifies user queries into specialized agent domains (`BINARY_ANALYSIS`, `CODE_ANALYSIS`, `GENERAL`).
- **`AgentOrchestrator`**: Coordinates multi-agent collaboration between specialized agents.
- **`OllamaClient`**: Manages communication with local Ollama LLM instances.

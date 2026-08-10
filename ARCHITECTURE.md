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

---

## 3. Verified Hermes Integration & Controlled Execution Architecture

EKKI-RE-AI integrates **Hermes Agent CLI** (`v0.20.0`) through a multi-tiered security gateway, allowing controlled terminal and tool execution while enforcing complete user control and strict sandboxing.

### 3.1 Verified System Architecture Diagram

```
User / Web Browser UI (Permission Selector & Modal)
        │
        ▼ (HTTP / REST API)
FastAPI Backend (backend/app.py)
        │
        ▼
AgentOrchestrator (Multi-Agent Reasoning)
        │
        ▼ (Tool Request)
ToolRouter (Security Gateway & Allowlist)
        │
        ├──► PermissionManager (SAFE / ASK / FULL CONTROL)
        ├──► WorkspacePolicy (Path Containment Boundary)
        └──► AuditLogger (Secret Redaction & Audit Trail)
                │
                ▼ (Safe Subprocess Bridge)
        HermesBridge (Process Lifecycle & AppLocker Bypass)
                │
                ▼ (CLI Process: --safe-mode -t terminal,file)
        Hermes Agent CLI (v0.20.0)
                │
                ▼ (Local REST API: http://localhost:11434)
        Ollama Local Inference Server
```

---

### 3.2 Component Responsibilities

- **`IntentRouter`**: Classifies user prompts and routes them to specialized LLM domains based on analysis intent.
- **`AgentOrchestrator`**: Coordinates reasoning across specialist models, tracks session context, synthesizes findings, and delegates required tool requests to `ToolRouter`.
- **Specialist Models**: Domain-specific Ollama models providing high-level analysis without direct system or tool execution privileges.
- **`ToolRouter`**: Centralized security gateway enforcing tool allowlisting (`file_list`, `file_read`, `file_metadata`, `terminal_execute`), output size caps (`MAX_OUTPUT_BYTES = 100 KB`), argument sanitization, and structured audit logging.
- **`PermissionManager`**: Thread-safe manager governing global execution modes (`SAFE`, `ASK`, `FULL CONTROL`), approval request creation, pending queue management, and single-use vs. session-wide permissions.
- **`WorkspacePolicy`**: Strict containment engine resolving target paths against workspace root boundaries (`.projects/`), blocking path traversal (`..`, symlinks, absolute paths outside root).
- **`HermesBridge`**: Asynchronous process bridge running Hermes CLI with process isolation, execution timeout enforcement, usage JSON parsing, and Windows process tree termination.
- **Hermes Agent**: Sandboxed agent runner executing approved tool commands in safe mode (`--safe-mode -t terminal,file`).
- **Ollama Server**: Local inference provider serving specialist models and Hermes execution models via `http://localhost:11434`.
- **`AuditLogger`**: Append-only structured logger preserving execution events (`AuditRecord`) with automatic credential/token scrubbing (`redact_secrets`).
- **Frontend / Web UI**: Interactive user interface featuring live Permission Mode selector badge and Execution Approval Modal overlay.

---

### 3.3 Execution Modes (SAFE / ASK / FULL CONTROL)

1. **SAFE Mode (Default)**:
   - Terminal execution commands (`terminal_execute`) are strictly **DENIED** (`DENY_PERMISSION_POLICY`).
   - Safe read-only file tools (`file_list`, `file_read`, `file_metadata`) remain **ALLOWED**.
2. **ASK Mode (Interactive Approval)**:
   - Terminal execution requests pause and generate a unique `ApprovalRequest`.
   - The UI presents an interactive approval modal displaying command, working directory, request source, and expected timeout.
   - Execution resumes only after explicit user approval.
3. **FULL CONTROL Mode (User Granted)**:
   - Terminal execution requests proceed automatically under workspace policy validation without interactive pauses.

---

### 3.4 User Approval Flow

```
AgentOrchestrator ──► ToolRouter ──► PermissionManager (ASK Mode)
                                            │
                                            ▼
                                  Create ApprovalRequest (PENDING)
                                            │
                                            ▼
                                  Frontend Approval Modal
                                   [Allow Once] [Allow Session] [Deny]
                                            │
                                            ▼
                              POST /api/security/approvals/{id}/decision
                                            │
                                            ▼
                                  PermissionManager (APPROVED)
                                            │
                                            ▼
                                  ToolRouter Executed via Hermes
```

---

### 3.5 Security & Authorization Boundaries

#### 1. Workspace Containment Boundary
- `WorkspacePolicy` validates that all working directories and target paths resolve within the configured project root (`.projects/`).
- Traversal attempts (e.g. `cwd="../secret_folder"`) are rejected immediately with `DENY_PATH_TRAVERSAL` prior to permission pauses or execution.

#### 2. Model Authorization Boundary
- Models have **ZERO** direct system execution authority and **ZERO** permission management rights.
- Any attempt by model sources (`caller_source="model"`) to alter the permission mode or approve requests is blocked with `ValueError: Unauthorized caller`.

#### 3. Audit & Secret Redaction Flow
- All tool requests and execution outcomes are recorded as an `AuditRecord` by `AuditLogger`.
- `redact_secrets()` sanitizes API key formats (`sk-...`, `ghp_...`), passwords, and token values in commands, parameters, and stdout/stderr outputs, replacing them with `[REDACTED_SECRET]`.

---

### 3.6 Specialist Model Assignments

| Specialist Role | Model Name | Description |
| :--- | :--- | :--- |
| **Vulnerability Analyst** | `lazarevtill/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest` | Vulnerability assessment & exploit analysis |
| **Coding / Decompilation** | `qwen2.5-coder:7b` | Assembly decompilation & code synthesis |
| **Vision Analysis** | `huihui_ai/qwen2.5-vl-abliterated:7b` | Visual binary diagrams & UI analysis |
| **Reasoning Engine** | `huihui_ai/deepseek-r1-abliterated:8b` | Deep chain-of-thought binary analysis |
| **General RE Specialist** | `mannix/llama3.1-8b-abliterated:latest` | Reverse engineering domain knowledge |
| **Synthesizer** | `mannix-re:latest` | Final report synthesis & multi-agent aggregation |
| **Obfuscation Analyst** | `dolphin-mistral:7b-v2.6-q4_K_M` | Packed / obfuscated code analysis |
| **Embeddings & Memory** | `nomic-embed-text:latest` | Vector embeddings for session memory |

---

### 3.7 Hermes & Ollama Relationship

EKKI-RE-AI orchestrates multi-agent specialist reasoning via `AgentOrchestrator`. When a specialist agent requests tool execution, `ToolRouter` passes the request to `HermesBridge`. `HermesBridge` invokes Hermes CLI, which queries Ollama (`huihui_ai/qwen2.5-vl-abliterated:7b`) for precise tool formatting and executes the approved operation in a sandboxed process.

---

### 3.8 Verified Test Results & Known Environment Factors

#### Verified Test Metrics
- **Pytest Suite**: **163 passed, 1 skipped** (164 total items across 13 test files).
- **Live E2E Verification**: **17 / 17 checks PASSED**.

#### Known Limitations & Workarounds
1. **Local Model Cold-Start Latency**:
   - Initial cold-start invocation of Ollama 7B local models can require >120 seconds while Ollama loads model weights into GPU VRAM. Subsequent warm calls complete in seconds.
2. **Windows AppLocker / WDAC Workaround**:
   - On Windows systems with AppLocker or WDAC binary blocking enabled, invoking `hermes.exe` directly in `AppData` raises `WinError 4551`. `HermesBridge` resolves this by executing `python.exe -m hermes_cli.main`, providing seamless cross-platform compatibility.


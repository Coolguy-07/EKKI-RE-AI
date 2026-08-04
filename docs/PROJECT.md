# EKKI-RE-AI Project Documentation

---

# Project Name

**EKKI-RE-AI**

---

# Project Purpose

EKKI-RE-AI is a local-first AI assistant designed specifically for reverse engineering, binary analysis, malware analysis, vulnerability research, exploit development, debugging, and security learning.

Unlike general-purpose AI assistants, EKKI-RE-AI is intended to become a specialized technical assistant that understands reverse engineering workflows, assembly language, operating system internals, executable formats, debugging tools, and software security concepts.

The assistant runs entirely on local hardware using Ollama and open-source language models, giving the user full control over privacy, customization, and future development.

---

# Vision

The long-term vision is to build an AI system that assists throughout the complete reverse engineering workflow.

The assistant should eventually be capable of:

- Explaining assembly code
- Understanding compiler optimizations
- Assisting with malware analysis
- Assisting with Windows Internals
- Assisting with Linux Internals
- Explaining PE and ELF binaries
- Helping during CTF challenges
- Assisting bug bounty research
- Organizing technical notes
- Managing reverse engineering case files
- Acting as a personal knowledge base
- Automating repetitive reverse engineering tasks

The objective is not to replace the reverse engineer but to accelerate learning, analysis, and documentation.

---

# Project Philosophy

The project follows several guiding principles.

## 1. Local First

All inference should run locally whenever practical.

Advantages include:

- Privacy
- Offline availability
- Lower long-term cost
- Full customization
- No dependency on external AI providers

---

## 2. Human-in-the-Loop

The AI provides assistance rather than autonomous decision making.

The user remains responsible for:

- Analysis
- Validation
- Security decisions
- Reverse engineering conclusions

---

## 3. Modular Architecture

Every major component should remain independent.

Examples include:

- AI Engine
- Memory
- Knowledge Base
- Reverse Engineering Tools
- API Layer
- Frontend
- Database

Each module should be replaceable without rewriting the rest of the application.

---

## 4. Incremental Development

The project is intentionally developed in small milestones.

Each milestone must:

- Compile successfully
- Run successfully
- Be documented
- Be committed to Git

This ensures the project always remains in a working state.

---

# Current Architecture

Current implementation:

```
Browser
      │
      ▼
Swagger UI
      │
      ▼
FastAPI Backend
      │
      ▼
AI Client
      │
      ▼
Ollama
      │
      ▼
Mannix-RE:latest
```

The backend currently exposes a REST API that forwards prompts to the local Ollama server and returns generated responses.

---

# Current Components

## Backend

Responsibilities:

- API endpoints
- Request validation
- Error handling
- AI integration
- Configuration loading

Technology:

- FastAPI
- Pydantic
- Uvicorn

---

## AI Layer

Responsibilities:

- Connect to Ollama
- Send prompts
- Receive responses
- Handle connection errors

Technology:

- Ollama Python SDK

---

## Configuration System

Responsibilities:

- Model selection
- Ollama endpoint
- API configuration
- Environment variable loading

Technology:

- pydantic-settings

---

# Long-Term Architecture

Future architecture:

```
User
   │
   ▼
Frontend
   │
   ▼
FastAPI Backend
   │
   ├── Authentication
   ├── Conversation Manager
   ├── Memory
   ├── Knowledge Base
   ├── Prompt Builder
   ├── Tool Manager
   ├── Plugin Manager
   └── Reverse Engineering Engine
             │
             ▼
        Ollama / Local LLM
             │
             ▼
        Language Model
```

---

# Future Capabilities

The project is expected to support:

## AI

- Streaming responses
- Conversation memory
- Long-term memory
- System prompts
- Multiple models

---

## Reverse Engineering

- Assembly explanation
- Function analysis
- Stack analysis
- Calling convention detection
- Compiler optimization recognition
- Binary metadata extraction

---

## Binary Analysis

- PE parsing
- ELF parsing
- String extraction
- Import analysis
- Export analysis
- Section analysis

---

## Tool Integration

Planned integrations include:

- Ghidra
- x64dbg
- IDA Pro
- Capstone
- Keystone
- Unicorn
- Radare2

---

## Knowledge System

The assistant will eventually support:

- Personal notes
- Reverse engineering documentation
- Research papers
- Books
- Local PDFs
- Markdown documentation
- Retrieval-Augmented Generation (RAG)

---

# Development Principles

During development the following principles should always be followed.

## Code Quality

- Clean architecture
- Readable code
- Type hints
- Docstrings
- Modular design

---

## Documentation

Every significant feature must include:

- Documentation
- Git commit
- Update to roadmap
- Development log entry

---

## Testing

Every new feature should be tested before additional features are added.

The project should never intentionally remain in a broken state.

---

# Current Development Status

Current Version

Version 0.1

Completed:

- Project setup
- Git repository
- Virtual environment
- FastAPI backend
- Ollama integration
- Mannix-RE integration
- REST API
- Swagger documentation
- Configuration management

Next Objective:

Develop the frontend chat interface followed by conversation memory.

---

# Long-Term Goal

The ultimate objective of EKKI-RE-AI is to become a powerful local AI assistant that helps the user learn, understand, and perform reverse engineering more effectively while maintaining privacy, transparency, and user control.

The assistant should evolve alongside the user's knowledge and become a reliable technical companion for reverse engineering and security research.
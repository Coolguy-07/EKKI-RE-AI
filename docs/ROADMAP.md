# EKKI-RE-AI Development Roadmap

---

# Purpose

This roadmap outlines the long-term development plan for EKKI-RE-AI.

The project is developed incrementally. Each phase builds on the previous one, ensuring that the application remains functional, documented, and version-controlled throughout development.

---

# Current Status

**Current Version:** 0.1

**Current Phase:** Phase 1 – Foundation

Status:

✅ Completed

---

# Phase 1 — Foundation

## Goal

Build the minimum working backend capable of communicating with a local language model.

### Objectives

- [x] Initialize Git repository
- [x] Create Python virtual environment
- [x] Create project structure
- [x] Configure VS Code workspace
- [x] Create FastAPI backend
- [x] Create configuration system
- [x] Integrate Ollama
- [x] Integrate Qwen3:8B
- [x] Create AI client
- [x] Create REST API
- [x] Create Swagger documentation
- [x] Test local inference
- [x] Create initial documentation

Status:

✅ Completed

---

# Phase 2 — User Interface

## Goal

Replace Swagger with a modern chat interface.

### Planned Features

- [ ] Chat page
- [ ] Message bubbles
- [ ] Markdown rendering
- [ ] Code block highlighting
- [ ] Dark mode
- [ ] Settings page
- [ ] Responsive layout
- [ ] Loading indicators
- [ ] Error messages

Status:

🟡 Planned

---

# Phase 3 — Conversation Memory

## Goal

Allow the assistant to remember ongoing conversations.

### Planned Features

- [ ] Conversation history
- [ ] Session management
- [ ] Context management
- [ ] Conversation summaries
- [ ] Memory optimization

Status:

🟡 Planned

---

# Phase 4 — Knowledge Base

## Goal

Allow the assistant to search personal technical knowledge before answering.

### Planned Features

- [ ] Markdown support
- [ ] PDF indexing
- [ ] Research paper indexing
- [ ] Reverse engineering notes
- [ ] Local documentation search
- [ ] Retrieval-Augmented Generation (RAG)

Status:

🟡 Planned

---

# Phase 5 — Reverse Engineering Engine

## Goal

Transform the assistant into a specialized reverse engineering companion.

### Planned Features

- [ ] Assembly explanation
- [ ] Calling convention analysis
- [ ] Stack analysis
- [ ] Register tracking
- [ ] Function walkthroughs
- [ ] Compiler optimization recognition
- [ ] Decompiled code explanation

Status:

🟡 Planned

---

# Phase 6 — Binary Analysis

## Goal

Support analysis of executable files.

### Planned Features

- [ ] PE parsing
- [ ] ELF parsing
- [ ] Import analysis
- [ ] Export analysis
- [ ] Section analysis
- [ ] String extraction
- [ ] Binary metadata

Status:

🟡 Planned

---

# Phase 7 — Reverse Engineering Tool Integration

## Goal

Integrate with professional reverse engineering tools.

### Planned Features

- [ ] Ghidra integration
- [ ] x64dbg integration
- [ ] IDA Pro integration
- [ ] Capstone integration
- [ ] Keystone integration
- [ ] Unicorn integration
- [ ] Radare2 integration

Status:

🟡 Planned

---

# Phase 8 — Bug Bounty Assistant

## Goal

Provide AI assistance for web security research and bug bounty workflows.

### Planned Features

- [ ] Request analysis
- [ ] API explanation
- [ ] HTTP workflow visualization
- [ ] Vulnerability note management
- [ ] Report drafting
- [ ] Target organization

Status:

🟡 Planned

---

# Phase 9 — AI Workspace

## Goal

Create a complete desktop workspace for reverse engineering.

### Planned Features

- [ ] File explorer
- [ ] Binary viewer
- [ ] Project management
- [ ] Notes
- [ ] Case management
- [ ] Search
- [ ] Workspace customization

Status:

🟡 Planned

---

# Phase 10 — Version 1.0

## Goal

Deliver the first stable release of EKKI-RE-AI.

### Release Objectives

- [ ] Stable backend
- [ ] Stable frontend
- [ ] Persistent memory
- [ ] Knowledge base
- [ ] Reverse engineering engine
- [ ] Binary analysis
- [ ] Tool integration
- [ ] Documentation
- [ ] Testing
- [ ] Release package

Status:

🔵 Future

---

# Guiding Principles

Every completed phase should satisfy the following requirements before moving to the next phase:

- Code is functional.
- Tests pass.
- Documentation is updated.
- Git commit is created.
- Architecture remains modular.
- No unfinished broken features remain.

---

# Roadmap Update Policy

This document should only be updated when:

- A phase is completed.
- A new phase is introduced.
- Major project priorities change.
- Version milestones are reached.

Minor implementation details should be recorded in `DEVLOG.md` instead of this roadmap.
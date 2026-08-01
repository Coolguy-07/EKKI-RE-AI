# EKKI-RE-AI Architecture

---

# Purpose

This document describes the architecture of EKKI-RE-AI.

It explains how the current system is organized, how components communicate, and how the architecture will evolve as new capabilities are added.

This document should be updated whenever major architectural changes are introduced.

---

# Design Principles

The architecture follows several principles:

- Modular
- Local First
- Human-in-the-Loop
- Extensible
- Maintainable
- Testable
- Replaceable Components

Each module should have a single responsibility and communicate through well-defined interfaces.

---

# Current Architecture (Version 0.1)

Current implementation:

```
                User
                  │
                  ▼
         Web Browser / Swagger
                  │
                  ▼
          FastAPI REST API
                  │
                  ▼
            Request Validation
             (Pydantic Models)
                  │
                  ▼
             AI Client Layer
                  │
                  ▼
          Ollama Local Server
                  │
                  ▼
             Qwen3:8B Model
                  │
                  ▼
            Generated Response
                  │
                  ▼
             JSON Response
                  │
                  ▼
                 User
```

---

# Current Folder Architecture

```
EKKI-RE-AI/

backend/
    app.py
    ai.py
    config.py

frontend/

docs/

notes/

data/

models/

cases/

scripts/

tests/
```

---

# Current Components

## FastAPI Backend

Responsibilities

- Receive HTTP requests
- Validate input
- Call AI layer
- Return JSON responses
- Handle exceptions

---

## AI Layer

Responsibilities

- Connect to Ollama
- Select model
- Send prompt
- Receive generated response
- Handle connection failures

---

## Configuration Layer

Responsibilities

- Load environment variables
- Store model configuration
- Store API configuration
- Store runtime settings

---

# Request Flow

Current request lifecycle

```
User

↓

POST /chat

↓

FastAPI

↓

Pydantic Validation

↓

AI Client

↓

Ollama

↓

Qwen3

↓

Generated Response

↓

FastAPI

↓

JSON

↓

User
```

---

# Future Architecture

As the project grows additional modules will be introduced.

```
                         User
                           │
                           ▼
                     Web Frontend
                           │
                           ▼
                      FastAPI API
                           │
      ┌────────────────────┼────────────────────┐
      │                    │                    │
      ▼                    ▼                    ▼
 Conversation       Prompt Builder       Authentication
    Manager
      │
      ▼
 Memory Manager
      │
      ▼
 Knowledge Base
      │
      ▼
 Reverse Engineering Engine
      │
      ▼
 Tool Manager
      │
      ▼
 Local AI Model (Ollama)
      │
      ▼
 Qwen / Future Models
```

---

# Planned Modules

## Frontend

Purpose

- Chat interface
- Settings
- File upload
- Conversation history
- Reverse engineering workspace

---

## Conversation Manager

Purpose

- Maintain active conversations
- Context window management
- Session state

---

## Memory Manager

Purpose

- Short-term memory
- Long-term memory
- Conversation summaries

---

## Knowledge Base

Purpose

- Markdown notes
- PDFs
- Books
- Research papers
- Reverse engineering documentation
- RAG

---

## Reverse Engineering Engine

Purpose

- Assembly explanation
- Binary analysis
- Function analysis
- Calling convention recognition
- Stack analysis
- Compiler optimization recognition

---

## Tool Manager

Purpose

Coordinate external tools including:

- Ghidra
- x64dbg
- IDA Pro
- Capstone
- Keystone
- Unicorn
- Radare2

---

## Plugin System

Future versions should allow additional plugins without modifying the core architecture.

Examples:

- Malware plugins
- PE analysis plugins
- ELF plugins
- CTF plugins
- Bug bounty plugins

---

# Data Flow

Future request flow

```
User

↓

Frontend

↓

FastAPI

↓

Conversation Manager

↓

Memory

↓

Knowledge Base

↓

Prompt Builder

↓

Tool Manager

↓

Ollama

↓

Language Model

↓

Response

↓

Conversation Storage

↓

Frontend
```

---

# Scalability

The architecture should allow:

- Multiple local models
- Additional AI providers
- New reverse engineering tools
- Additional databases
- Plugin extensions
- Multiple frontend clients

without requiring major redesign.

---

# Technology Stack

Current

Backend

- Python
- FastAPI
- Pydantic
- Uvicorn

AI

- Ollama
- Qwen3:8B

Development

- Git
- VS Code

Future

Database

- SQLite
- PostgreSQL

Frontend

- React

Vector Database

- ChromaDB
- FAISS

Reverse Engineering

- Ghidra
- Capstone
- Keystone
- Unicorn
- Radare2

---

# Future Evolution

Version 0.1

- Local chat API

↓

Version 0.2

- Web chat interface

↓

Version 0.3

- Memory

↓

Version 0.4

- Knowledge Base

↓

Version 0.5

- Reverse Engineering Engine

↓

Version 0.6

- Binary Analysis

↓

Version 1.0

- Complete Reverse Engineering Assistant

---

# Architectural Goals

The architecture should remain:

- Modular
- Understandable
- Well documented
- Easy to extend
- Easy to test
- Easy to maintain

Every new feature should fit into the existing architecture rather than introducing unnecessary complexity.

---

# Architecture Revision History

Version 0.1

Initial architecture documenting the FastAPI backend, Ollama integration, Qwen3 model integration, and planned long-term system evolution.
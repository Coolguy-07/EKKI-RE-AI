# EKKI-RE-AI

> A local AI-powered Reverse Engineering Assistant built with FastAPI, Ollama, and Mannix-RE.

---

# Overview

EKKI-RE-AI is an AI assistant designed to help with reverse engineering, binary analysis, malware analysis, exploit development, assembly understanding, debugging, and vulnerability research.

Unlike cloud AI assistants, EKKI-RE-AI is designed to run completely on local hardware using Ollama, allowing offline usage, privacy, and full customization.

This project is being built incrementally, starting from a simple AI backend and evolving into an intelligent reverse engineering assistant capable of assisting throughout the reverse engineering workflow.

---

# Vision

The long-term vision of EKKI-RE-AI is to become an advanced AI assistant capable of helping with:

- Reverse Engineering
- Assembly Language Analysis
- Binary Analysis
- Malware Analysis
- Vulnerability Research
- Debugging
- Static Analysis
- Dynamic Analysis
- Windows Internals
- Linux Internals
- Ghidra Assistance
- IDA Pro Assistance
- x64dbg Assistance
- Bug Bounty Research
- Exploit Development Guidance
- CTF Challenges
- Security Learning

The assistant is intended to accelerate learning and productivity while keeping the human in control of all analysis and decisions.

---

# Current Status

Current Development Phase:

✅ Foundation Completed

Completed components:

- Local Ollama integration
- Mannix-RE:latest model integration
- FastAPI backend
- REST API
- Swagger UI
- Configuration system
- Git repository
- Python virtual environment
- Project structure

---

# Project Structure

```
EKKI-RE-AI/

│
├── backend/
│   ├── __init__.py
│   ├── app.py
│   ├── ai.py
│   └── config.py
│
├── frontend/
│
├── docs/
│
├── models/
│
├── notes/
│
├── scripts/
│
├── tests/
│
├── cases/
│
├── data/
│
├── .gitignore
│
└── README.md
```

---

# Technologies

Backend

- Python
- FastAPI
- Uvicorn
- Pydantic

AI

- Ollama
- Mannix-RE:latest

Development

- Git
- VS Code

Future

- SQLite
- PostgreSQL
- React
- Docker

---

# Features

Current Features

- Local AI inference
- REST API
- JSON responses
- Swagger documentation
- Configurable AI model
- Configurable Ollama endpoint
- Error handling
- Modular architecture

Planned Features

- Web chat interface
- Persistent memory
- Conversation history
- Reverse engineering knowledge base
- Binary file analysis
- Assembly explanation
- PE/ELF parsing
- Ghidra integration
- IDA integration
- x64dbg integration
- Malware report generation
- Plugin system
- Case management
- Local vector database
- RAG support

---

# Installation

Clone the repository

```bash
git clone <repository-url>
cd EKKI-RE-AI
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate

Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Backend

Start Ollama

```bash
ollama serve
```

Run the model

```bash
ollama run mannix-re:latest
```

Start the API

```bash
uvicorn backend.app:app --reload
```

Swagger UI

```
http://127.0.0.1:8000/docs
```

---

# Current API

POST

```
/chat
```

Example Request

```json
{
  "message": "Hello"
}
```

Example Response

```json
{
  "response": "Hello! I'm Mannix-RE..."
}
```

---

# Development Roadmap

## Phase 1

- Project setup
- FastAPI backend
- Ollama integration
- REST API

Status

✅ Completed

---

## Phase 2

- Web frontend
- Chat interface
- Better UI

Status

🚧 In Progress

---

## Phase 3

- Memory system
- Conversation history
- Notes
- Knowledge storage

---

## Phase 4

- Reverse engineering assistant

- Assembly explanation
- Function analysis
- Calling conventions
- Stack visualization

---

## Phase 5

- Binary analysis

- PE parser
- ELF parser
- String extraction
- Symbol analysis

---

## Phase 6

- Reverse engineering tool integration

- Ghidra
- IDA Pro
- x64dbg

---

## Phase 7

- Bug bounty assistant

- HTTP analysis
- API analysis
- Request explanation
- Security checklist

---

## Phase 8

- Autonomous reverse engineering workflow

- Multi-step reasoning
- Tool orchestration
- Report generation

---

# Philosophy

EKKI-RE-AI is designed around three principles:

- Privacy First
- Local First
- Human-in-the-Loop

The assistant provides explanations, guidance, and automation while leaving important security decisions to the user.

---

# License

This project is currently under active development.

License information will be added in a future release.

---

# Author

EKKI

Building a local AI assistant focused on reverse engineering, binary analysis, and security research.
# EKKI-RE-AI

**EKKI (Experimental Knowledge & Kernel Intelligence)** is a private, local-first AI assistant designed to push the capabilities of autonomous AI systems on consumer hardware.

EKKI is not designed as a conventional chatbot. It is being developed as a modular personal AI system with specialized models, multi-agent reasoning, evidence provenance, controlled tool execution, local knowledge retrieval, and strict resource/security boundaries.

> **Status:** Active long-term research and engineering project.

---

## Vision

The long-term goal of EKKI is to approach the capabilities of fictional personal AI assistants such as E.D.I.T.H. and F.R.I.D.A.Y. using technologies that can actually run locally.

The project focuses on:

- Multi-agent intelligence
- Local model orchestration
- Evidence-grounded reasoning
- Debate and consensus
- Reverse-engineering assistance
- Technical knowledge retrieval
- Controlled computer interaction
- Strict security boundaries
- Efficient operation on limited hardware

---

## Current Architecture

EKKI currently uses a bounded multi-agent workflow built around Microsoft Agent Framework and local Ollama inference.

```text
                         USER
                           │
                           ▼
                    EKKI CONTROLLER
                           │
                           ▼
                    MAF WORKFLOW
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
       DECOMPILATION   VULNERABILITY   OBFUSCATION
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                   CONTRADICTION CHECK
                           │
                           ▼
                       CHALLENGE
                           │
                           ▼
                       REBUTTAL
                           │
                           ▼
                       CONSENSUS
                           │
                    ┌──────┴──────┐
                    ▼             ▼
               REASONING      SYNTHESIS
                             
                           │
                           ▼
                    FINAL ANSWER

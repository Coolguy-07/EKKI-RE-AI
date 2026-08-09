# Changelog

## Version 0.2.6

Released: 2026-08-06

Added:
- Phase 2.6 Ghidra Headless Integration Engine (`GhidraAnalysisEngine`)
- Subprocess analyzeHeadless execution launcher with timeout guards
- Persisted `analysis/{file_id}/ghidra.json` artifact
- REST API endpoint `GET /api/projects/{project_id}/files/{file_id}/ghidra`
- Frontend `Ghidra` tab with function listing & decompiled C code viewer
- Unit & integration test suite `tests/test_ghidra_engine.py`

## Version 0.1

Released:
2026-08-01

Added:
- FastAPI backend
- Ollama integration
- Mannix-RE:latest integration
- REST API
- Swagger documentation
- Configuration system
- Project documentation

Changed:
- Added .gitignore

Fixed:
- Ignored Python cache files
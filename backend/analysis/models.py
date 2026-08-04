"""
backend/analysis/models.py

Strongly typed Pydantic domain models for versioned analysis metadata.
Stored under analysis/{file_id}/metadata.json.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# Schema Version constant
CURRENT_SCHEMA_VERSION = 1


class BinaryMetadata(BaseModel):
    """Pydantic model representing versioned file metadata stored under analysis/{file_id}/metadata.json."""

    schema_version: int = Field(
        default=CURRENT_SCHEMA_VERSION,
        description="Version number of the metadata JSON schema.",
    )
    file_id: str = Field(
        ...,
        description="Immutable internal file identifier.",
    )
    filename: str = Field(
        ...,
        description="Display name of the stored file.",
    )
    file_size: int = Field(
        ...,
        description="Exact file size in bytes.",
    )
    mime_type: str = Field(
        default="application/octet-stream",
        description="MIME content type.",
    )
    extension: str = Field(
        default="",
        description="Lowercased file extension (e.g. '.exe', '.c', or empty string).",
    )
    md5: str = Field(
        ...,
        description="32-character hexadecimal MD5 hash.",
    )
    sha1: str = Field(
        ...,
        description="40-character hexadecimal SHA-1 hash.",
    )
    sha256: str = Field(
        ...,
        description="64-character hexadecimal SHA-256 hash.",
    )
    sha512: str = Field(
        ...,
        description="128-character hexadecimal SHA-512 hash.",
    )
    entropy: float = Field(
        ...,
        description="Shannon entropy value ranging from 0.0000 to 8.0000.",
    )
    detected_type: str = Field(
        ...,
        description="Universal file type identified by magic bytes/heuristics.",
    )
    detected_architecture: Optional[str] = Field(
        default="N/A",
        description="CPU Architecture if available (e.g., x86, x86_64, ARM, ARM64, MIPS, RISC-V, PowerPC, N/A).",
    )
    upload_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC upload timestamp.",
    )
    status: str = Field(
        default="analyzed",
        description="Status of analysis execution (e.g., 'analyzed', 'failed').",
    )
    errors: List[str] = Field(
        default_factory=list,
        description="List of structured error messages encountered during analysis.",
    )
    engine_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible namespace for engine-specific metadata outputs.",
    )


class SchemaVersion(BaseModel):
    """Model to check schema version compatibility."""

    schema_version: int = CURRENT_SCHEMA_VERSION

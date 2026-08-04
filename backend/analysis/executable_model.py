"""
backend/analysis/executable_model.py

Shared Executable Format Model for EKKI-RE-AI.
Provides a unified, standardized cross-platform domain model representing common binary
metadata across PE, ELF, and Mach-O executables for future AI consumption and reasoning.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

CURRENT_SHARED_MODEL_VERSION = 1


class UnifiedSection(BaseModel):
    """Standardized representation of an executable section across formats."""

    name: str = Field(..., description="Section name (e.g., .text, __text, .rdata).")
    virtual_address: str = Field(..., description="Virtual address or RVA hex string.")
    virtual_address_raw: int = Field(..., description="Raw virtual address integer.")
    virtual_size: int = Field(..., description="Virtual size in memory (bytes).")
    raw_offset: int = Field(..., description="Physical file offset (bytes).")
    raw_size: int = Field(..., description="Physical raw size in file (bytes).")
    entropy: float = Field(0.0, description="Shannon entropy score (0.0 - 8.0).")
    flags: List[str] = Field(default_factory=list, description="Parsed human-readable flag tokens.")


class UnifiedExecutableModel(BaseModel):
    """Standardized cross-platform executable metadata model."""

    schema_version: int = Field(
        default=CURRENT_SHARED_MODEL_VERSION,
        description="Schema version of the shared executable model.",
    )
    file_id: str = Field(..., description="Immutable file identifier.")
    format: str = Field(..., description="Binary format: 'PE', 'ELF', 'Mach-O', or 'Unknown'.")
    architecture: str = Field(..., description="Target architecture (e.g. x86_64, ARM64, x86).")
    bitness: int = Field(..., description="Architecture bitness: 32 or 64.")
    endianness: str = Field(..., description="Endianness: 'little' or 'big'.")
    entry_point: str = Field(..., description="Entry point hex string.")
    entry_point_raw: int = Field(0, description="Entry point raw integer.")
    image_base: Optional[str] = Field(None, description="Image base address hex string if applicable.")
    subsystem_or_abi: Optional[str] = Field(None, description="OS Subsystem or ABI identifier.")
    is_executable: bool = Field(False, description="True if executable binary.")
    is_shared_library: bool = Field(False, description="True if DLL, .so, or .dylib.")
    sections: List[UnifiedSection] = Field(default_factory=list, description="Standardized sections list.")
    libraries: List[str] = Field(default_factory=list, description="Imported/Shared library names.")
    symbols_count: int = Field(0, description="Count of exported/local symbols.")
    parser_name: str = Field(..., description="Parser engine name.")
    parser_version: str = Field(..., description="Parser version string.")
    parser_errors: List[str] = Field(default_factory=list, description="Accumulated parser errors.")
    format_specific: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible dictionary holding full format-specific parser details.",
    )

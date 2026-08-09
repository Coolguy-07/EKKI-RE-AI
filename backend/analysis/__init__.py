"""
backend/analysis/__init__.py

Modular, extensible Analysis Engine Architecture for EKKI-RE-AI.
Exposes base analysis engine interfaces, metadata models, binary intelligence,
PE parser, ELF parser, Mach-O parser, Capstone disassembly engine,
and Unified Executable models.
"""

from .base import BaseAnalysisEngine
from .binary_intelligence import BinaryIntelligenceEngine
from .binary_reader import BinaryReader
from .capstone_engine import CapstoneDisassemblyEngine
from .disassembly_model import (
    CURRENT_DISASSEMBLY_SCHEMA_VERSION,
    DisassemblyArtifact,
    LoopDetectionResult,
    SectionDisassembly,
)
from .elf_parser import ELFParserEngine
from .executable_model import CURRENT_SHARED_MODEL_VERSION, UnifiedExecutableModel, UnifiedSection
from .ghidra_engine import GhidraAnalysisEngine
from .macho_parser import MachOParserEngine
from .models import BinaryMetadata, SchemaVersion
from .pe_parser import PEParserEngine
from .registry import AnalysisPipeline, analysis_pipeline

__all__ = [
    "BaseAnalysisEngine",
    "BinaryIntelligenceEngine",
    "BinaryReader",
    "BinaryMetadata",
    "SchemaVersion",
    "CapstoneDisassemblyEngine",
    "DisassemblyArtifact",
    "LoopDetectionResult",
    "SectionDisassembly",
    "CURRENT_DISASSEMBLY_SCHEMA_VERSION",
    "GhidraAnalysisEngine",
    "PEParserEngine",
    "ELFParserEngine",
    "MachOParserEngine",
    "UnifiedExecutableModel",
    "UnifiedSection",
    "CURRENT_SHARED_MODEL_VERSION",
    "AnalysisPipeline",
    "analysis_pipeline",
]

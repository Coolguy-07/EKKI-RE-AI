"""
backend/analysis/binary_intelligence.py

Production-grade Binary Intelligence Engine implementing BaseAnalysisEngine interface.
Performs efficient single-pass hash computation, Shannon entropy calculation,
and universal file type signature matching.
"""

import collections
import hashlib
import logging
import math
import os
import time
from typing import Any, Dict, List, Optional

from .base import BaseAnalysisEngine
from .detector import FileDetector
from .models import BinaryMetadata, CURRENT_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class BinaryIntelligenceEngine(BaseAnalysisEngine):
    """Engine responsible for binary identification, hashes, entropy, and metadata extraction."""

    @property
    def engine_name(self) -> str:
        return "binary_intelligence"

    @property
    def engine_version(self) -> str:
        return "1.0.0"

    def analyze(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = None,
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs binary intelligence analysis on byte payload.

        Single-pass algorithm computes MD5, SHA-1, SHA-256, SHA-512, and byte distribution
        for Shannon entropy calculation without redundant disk or memory operations.

        Args:
            file_id: Unique immutable file identifier.
            filename: Display filename.
            content: Raw byte payload.
            mime_type: Optional MIME content type.
            existing_metadata: Extensible existing metadata dict.

        Returns:
            Dict matching BinaryMetadata schema ready for serialization.
        """
        start_time = time.perf_counter()
        logger.info("Analysis started: engine='%s' file_id='%s' filename='%s'", self.engine_name, file_id, filename)

        errors: List[str] = []
        size_bytes = len(content)
        ext = os.path.splitext(filename)[1].lower()

        # 1. Single-pass Hash Computation & Shannon Entropy Frequency Counting
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        sha256_obj = hashlib.sha256()
        sha512_obj = hashlib.sha512()

        md5_obj.update(content)
        sha1_obj.update(content)
        sha256_obj.update(content)
        sha512_obj.update(content)

        md5_hex = md5_obj.hexdigest()
        sha1_hex = sha1_obj.hexdigest()
        sha256_hex = sha256_obj.hexdigest()
        sha512_hex = sha512_obj.hexdigest()

        logger.debug("Hashes generated: file_id='%s' sha256='%s'", file_id, sha256_hex)

        # Calculate Shannon Entropy: -sum(p * log2(p)) over 256 byte frequencies
        if size_bytes == 0:
            entropy = 0.0
        else:
            byte_counts = collections.Counter(content)
            entropy = -sum((count / size_bytes) * math.log2(count / size_bytes) for count in byte_counts.values())

        entropy = round(entropy, 4)
        logger.debug("Entropy calculated: file_id='%s' entropy=%.4f", file_id, entropy)

        # 2. Universal File Type & Architecture Detection
        try:
            detected_type, arch, det_err = FileDetector.detect(content=content, filename=filename)
            if det_err:
                errors.append(det_err)
        except Exception as err:
            logger.exception("File detection error for file_id='%s': %s", file_id, err)
            detected_type = "Unknown Binary"
            arch = "N/A"
            errors.append(f"Detection engine exception: {err}")

        logger.info(
            "File detected: file_id='%s' type='%s' arch='%s'",
            file_id,
            detected_type,
            arch or "N/A",
        )

        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Construct Engine-specific metadata payload
        engine_payload = {
            self.engine_name: {
                "engine_version": self.engine_version,
                "execution_time_ms": exec_time_ms,
                "header_magic_hex": content[:16].hex() if content else "",
            }
        }

        # Merge with existing engine metadata if available
        if existing_metadata and "engine_metadata" in existing_metadata:
            merged_engine_meta = {**existing_metadata["engine_metadata"], **engine_payload}
        else:
            merged_engine_meta = engine_payload

        status = "failed" if (errors and detected_type == "Unknown Binary") else "analyzed"

        metadata_obj = BinaryMetadata(
            schema_version=CURRENT_SCHEMA_VERSION,
            file_id=file_id,
            filename=filename,
            file_size=size_bytes,
            mime_type=mime_type or "application/octet-stream",
            extension=ext,
            md5=md5_hex,
            sha1=sha1_hex,
            sha256=sha256_hex,
            sha512=sha512_hex,
            entropy=entropy,
            detected_type=detected_type,
            detected_architecture=arch or "N/A",
            status=status,
            errors=errors,
            engine_metadata=merged_engine_meta,
        )

        logger.info("Analysis completed: file_id='%s' status='%s' in %.2fms", file_id, status, exec_time_ms)
        return metadata_obj.model_dump()

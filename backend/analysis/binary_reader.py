"""
backend/analysis/binary_reader.py

Reusable, bounds-checked BinaryReader utility for EKKI-RE-AI analysis engines.
Provides safe offset reading, endianness handling, string extraction, byte slicing,
Shannon entropy calculation, and structured error tracking.
Shared across PE, ELF, Mach-O, and future binary parsers.
"""

import collections
import logging
import math
import struct
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class BinaryReader:
    """Thread-safe, bounds-checked reader over a raw bytes payload."""

    def __init__(self, content: bytes) -> None:
        self._content: bytes = content
        self._length: int = len(content)
        self._errors: List[str] = []

    @property
    def size(self) -> int:
        """Returns total file size in bytes."""
        return self._length

    @property
    def errors(self) -> List[str]:
        """Returns list of accumulated bounds or parsing errors."""
        return list(self._errors)

    def add_error(self, message: str) -> None:
        """Appends a structured error message."""
        self._errors.append(message)
        logger.warning("BinaryReader error: %s", message)

    def is_valid_offset(self, offset: int, length: int = 1) -> bool:
        """Validates whether [offset, offset + length) is within buffer boundaries."""
        if offset < 0 or length < 0:
            return False
        return (offset + length) <= self._length

    def read_bytes(self, offset: int, length: int) -> Optional[bytes]:
        """Safely extracts a byte slice from offset."""
        if not self.is_valid_offset(offset, length):
            self.add_error(f"Read bounds violation: offset {offset} + len {length} exceeds size {self._length}")
            return None
        return self._content[offset : offset + length]

    def read_u8(self, offset: int) -> Optional[int]:
        """Reads 1-byte unsigned integer."""
        if not self.is_valid_offset(offset, 1):
            return None
        return self._content[offset]

    def read_u16_le(self, offset: int) -> Optional[int]:
        """Reads 2-byte unsigned integer (little-endian)."""
        data = self.read_bytes(offset, 2)
        if data is None:
            return None
        return struct.unpack("<H", data)[0]

    def read_u16_be(self, offset: int) -> Optional[int]:
        """Reads 2-byte unsigned integer (big-endian)."""
        data = self.read_bytes(offset, 2)
        if data is None:
            return None
        return struct.unpack(">H", data)[0]

    def read_u32_le(self, offset: int) -> Optional[int]:
        """Reads 4-byte unsigned integer (little-endian)."""
        data = self.read_bytes(offset, 4)
        if data is None:
            return None
        return struct.unpack("<I", data)[0]

    def read_u32_be(self, offset: int) -> Optional[int]:
        """Reads 4-byte unsigned integer (big-endian)."""
        data = self.read_bytes(offset, 4)
        if data is None:
            return None
        return struct.unpack(">I", data)[0]

    def read_u64_le(self, offset: int) -> Optional[int]:
        """Reads 8-byte unsigned integer (little-endian)."""
        data = self.read_bytes(offset, 8)
        if data is None:
            return None
        return struct.unpack("<Q", data)[0]

    def read_u64_be(self, offset: int) -> Optional[int]:
        """Reads 8-byte unsigned integer (big-endian)."""
        data = self.read_bytes(offset, 8)
        if data is None:
            return None
        return struct.unpack(">Q", data)[0]

    def read_cstring(self, offset: int, max_length: int = 256, encoding: str = "ascii") -> Optional[str]:
        """Reads null-terminated string starting at offset up to max_length bytes."""
        if not self.is_valid_offset(offset, 1):
            return None

        end = min(self._length, offset + max_length)
        chunk = self._content[offset:end]
        null_pos = chunk.find(b"\x00")

        if null_pos != -1:
            raw_str = chunk[:null_pos]
        else:
            raw_str = chunk

        try:
            return raw_str.decode(encoding, errors="replace")
        except Exception as err:
            self.add_error(f"String decode exception at offset {offset}: {err}")
            return None

    def read_utf16_string(self, offset: int, max_length_bytes: int = 256) -> Optional[str]:
        """Reads null-terminated UTF-16 (LE) string starting at offset."""
        if not self.is_valid_offset(offset, 2):
            return None

        end = min(self._length, offset + max_length_bytes)
        chunk = self._content[offset:end]
        
        # Find 2-byte null terminator (\x00\x00 at even byte boundary)
        null_pos = -1
        for i in range(0, len(chunk) - 1, 2):
            if chunk[i : i + 2] == b"\x00\x00":
                null_pos = i
                break

        if null_pos != -1:
            raw_bytes = chunk[:null_pos]
        else:
            raw_bytes = chunk

        try:
            return raw_bytes.decode("utf-16le", errors="replace")
        except Exception as err:
            self.add_error(f"UTF-16 decode exception at offset {offset}: {err}")
            return None

    def calculate_entropy(self, offset: int, length: int) -> float:
        """Calculates Shannon entropy for byte slice [offset, offset + length)."""
        if length <= 0 or not self.is_valid_offset(offset, length):
            return 0.0

        slice_bytes = self._content[offset : offset + length]
        if not slice_bytes:
            return 0.0

        byte_counts = collections.Counter(slice_bytes)
        total = len(slice_bytes)

        entropy = -sum((count / total) * math.log2(count / total) for count in byte_counts.values())
        return round(entropy, 4)

"""
backend/memory.py

Production-grade in-memory conversation storage for EKKI-RE-AI.
Provides role-based structured messages, sliding-window retention,
and thread-safe operations without external dependencies.
"""

from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from .config import settings

# Supported message roles matching standard LLM specs
RoleType = Literal["system", "user", "assistant", "tool"]


class ChatMessage(BaseModel):
    """Domain model representing a structured conversation message.

    Extensible schema supporting roles, timestamps, and metadata for future
    tool calls, RAG context citations, or agent steps.
    """

    role: RoleType = Field(..., description="Role of the message author.")
    content: str = Field(..., description="Text content of the message.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of message creation.",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Extensible metadata payload for tool calls or retrieval citations.",
    )

    def to_ollama_dict(self) -> Dict[str, str]:
        """Converts internal model into the dict format expected by Ollama Chat API."""
        return {"role": self.role, "content": self.content}


class BaseMemoryStore(ABC):
    """Abstract Base Class defining the contract for memory storage implementations."""

    @abstractmethod
    def add_message(self, message: ChatMessage) -> None:
        """Appends a message to memory."""
        pass

    @abstractmethod
    def get_messages(self) -> List[ChatMessage]:
        """Retrieves ordered conversation history."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clears all stored messages."""
        pass


class InMemoryMemoryStore(BaseMemoryStore):
    """Thread-safe, sliding-window in-memory store for conversation memory.

    Retains up to `max_messages` using a First-In-First-Out (FIFO) queue.
    """

    def __init__(self, max_messages: int = 20) -> None:
        """Initialize memory buffer with capacity constraint.

        Args:
            max_messages: Maximum historical messages retained in RAM.
        """
        self._max_messages: int = max_messages
        self._messages: deque[ChatMessage] = deque(maxlen=max_messages)
        # Re-entrant lock ensures safe concurrent access across FastAPI threads
        self._lock: threading.RLock = threading.RLock()

    def add_message(self, message: ChatMessage) -> None:
        """Appends a message to the memory buffer thread-safely."""
        with self._lock:
            self._messages.append(message)

    def get_messages(self) -> List[ChatMessage]:
        """Retrieves an immutable snapshot copy of stored messages."""
        with self._lock:
            return list(self._messages)

    def clear(self) -> None:
        """Clears stored messages from memory."""
        with self._lock:
            self._messages.clear()


# Default singleton memory instance
memory_store: BaseMemoryStore = InMemoryMemoryStore(
    max_messages=settings.MAX_MEMORY_MESSAGES
)
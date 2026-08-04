"""
backend/ai.py

AI client wrapper managing interactions with the local Ollama service using
structured role-based messages, system prompts, and memory integration.
"""

import json
import logging
from typing import Any, Generator, List, Optional
from ollama import Client, ResponseError

from .config import settings
from .memory import BaseMemoryStore, ChatMessage, memory_store, session_memory_manager
from .prompts import get_system_prompt

logger = logging.getLogger(__name__)


class AIClientError(Exception):
    """Custom exception raised when communication with the AI service fails."""

    pass


def extract_ollama_response_content(response: Any) -> str:
    """Shared helper to extract response text safely across dict or object SDK models."""
    if response is None:
        return ""
    if isinstance(response, dict):
        msg = response.get("message", {})
        return str(msg.get("content", "")) if isinstance(msg, dict) else str(getattr(msg, "content", ""))

    msg = getattr(response, "message", None)
    if isinstance(msg, dict):
        return str(msg.get("content", ""))
    return str(getattr(msg, "content", "")) if msg is not None else ""


class OllamaAIClient:
    """Reusable client for structured Ollama chat model operations."""

    def __init__(
        self,
        host: Optional[str] = None,
        model_name: Optional[str] = None,
        store: Optional[BaseMemoryStore] = None,
        num_ctx: Optional[int] = None,
    ) -> None:
        """Initialize the Ollama AI client.

        Args:
            host: Ollama server base URL. Defaults to configuration setting.
            model_name: Target model identifier. Defaults to configuration setting.
            store: Default memory store fallback instance.
            num_ctx: Context window size limit. Defaults to configuration setting.
        """
        self.host: str = host or settings.OLLAMA_HOST
        self.model_name: str = model_name or settings.MODEL_NAME
        self.num_ctx: int = num_ctx or settings.OLLAMA_NUM_CTX
        self.memory_store: BaseMemoryStore = store or memory_store
        self._client: Client = Client(host=self.host)

    def generate(self, prompt: str, session_id: Optional[str] = None) -> str:
        """Generates a response using structured role-based messages.

        Args:
            prompt: Incoming user prompt text.
            session_id: Optional conversation session identifier for memory isolation.

        Returns:
            str: Generated assistant response text.

        Raises:
            ValueError: If prompt is empty or whitespace.
            AIClientError: On Ollama service communication failure.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")

        target_store = session_memory_manager.get_store(session_id) if session_id else self.memory_store

        # 1. Fetch system prompt from dedicated prompts module
        system_prompt = get_system_prompt()

        # 2. Retrieve history from session memory store
        history: List[ChatMessage] = target_store.get_messages()

        # 3. Assemble structured messages payload
        messages_payload = []

        if system_prompt:
            messages_payload.append({"role": "system", "content": system_prompt})

        for msg in history:
            messages_payload.append(msg.to_ollama_dict())

        # Append incoming active user prompt
        messages_payload.append({"role": "user", "content": prompt})

        try:
            logger.debug(
                "Dispatching structured chat payload (%d messages) to Ollama [Model: %s, Session: %s]",
                len(messages_payload),
                self.model_name,
                session_id or "default",
            )

            # 4. Invoke Ollama structured chat API
            response = self._client.chat(
                model=self.model_name,
                messages=messages_payload,
                options={"num_ctx": self.num_ctx},
            )

            # Extract message content safely across response variants
            response_content = extract_ollama_response_content(response)

            # 5. Commit user prompt and assistant response to memory upon success
            user_msg = ChatMessage(role="user", content=prompt)
            assistant_msg = ChatMessage(role="assistant", content=response_content)

            target_store.add_message(user_msg)
            target_store.add_message(assistant_msg)

            return response_content

        except ResponseError as e:
            logger.error("Ollama API error response [code=%s]: %s", e.status_code, e.error)
            raise AIClientError(
                f"Ollama service error (HTTP {e.status_code}): {e.error}"
            ) from e
        except Exception as e:
            logger.error("Failed to connect to Ollama server at %s: %s", self.host, str(e))
            raise AIClientError(
                f"Could not connect to Ollama service at {self.host}. "
                "Ensure Ollama is running and accessible."
            ) from e

    def generate_stream(self, prompt: str, session_id: Optional[str] = None) -> Generator[str, None, None]:
        """Generates a streaming response formatted as SSE data frames.

        Args:
            prompt: Incoming user prompt text.
            session_id: Optional conversation session identifier for memory isolation.

        Yields:
            str: SSE formatted data string containing token content or status.

        Raises:
            ValueError: If prompt is empty or whitespace.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")

        target_store = session_memory_manager.get_store(session_id) if session_id else self.memory_store

        system_prompt = get_system_prompt()
        history: List[ChatMessage] = target_store.get_messages()

        messages_payload = []
        if system_prompt:
            messages_payload.append({"role": "system", "content": system_prompt})

        for msg in history:
            messages_payload.append(msg.to_ollama_dict())

        messages_payload.append({"role": "user", "content": prompt})

        accumulated_tokens: List[str] = []

        try:
            logger.debug(
                "Dispatching streaming chat payload (%d messages) to Ollama [Model: %s, Session: %s]",
                len(messages_payload),
                self.model_name,
                session_id or "default",
            )

            stream_response = self._client.chat(
                model=self.model_name,
                messages=messages_payload,
                stream=True,
                options={"num_ctx": self.num_ctx},
            )

            for chunk in stream_response:
                content = extract_ollama_response_content(chunk)
                if content:
                    accumulated_tokens.append(content)
                    data_frame = json.dumps({"content": content})
                    yield f"data: {data_frame}\n\n"

            # Stream successfully completed: Commit conversation to session memory
            full_response = "".join(accumulated_tokens)
            user_msg = ChatMessage(role="user", content=prompt)
            assistant_msg = ChatMessage(role="assistant", content=full_response)

            target_store.add_message(user_msg)
            target_store.add_message(assistant_msg)

            # Signal stream completion
            done_frame = json.dumps({"done": True})
            yield f"data: {done_frame}\n\n"

        except ResponseError as e:
            logger.error("Ollama API streaming error [code=%s]: %s", e.status_code, e.error)
            err_frame = json.dumps({"error": f"Ollama service error (HTTP {e.status_code}): {e.error}"})
            yield f"data: {err_frame}\n\n"
        except Exception as e:
            logger.error("Error during streaming generation: %s", str(e))
            err_frame = json.dumps({"error": f"Service connection error: {str(e)}"})
            yield f"data: {err_frame}\n\n"


# Global default client instance
ai_client = OllamaAIClient()
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
from .memory import BaseMemoryStore, ChatMessage, memory_store
from .prompts import get_system_prompt

logger = logging.getLogger(__name__)


class AIClientError(Exception):
    """Custom exception raised when communication with the AI service fails."""

    pass


class OllamaAIClient:
    """Reusable client for structured Ollama chat model operations."""

    def __init__(
        self,
        host: Optional[str] = None,
        model_name: Optional[str] = None,
        store: Optional[BaseMemoryStore] = None,
    ) -> None:
        """Initialize the Ollama AI client.

        Args:
            host: Ollama server base URL. Defaults to configuration setting.
            model_name: Target model identifier. Defaults to configuration setting.
            store: Conversation memory store instance. Defaults to global memory_store.
        """
        self.host: str = host or settings.OLLAMA_HOST
        self.model_name: str = model_name or settings.MODEL_NAME
        self.memory_store: BaseMemoryStore = store or memory_store
        self._client: Client = Client(host=self.host)

    def generate(self, prompt: str) -> str:
        """Generates a response using structured role-based messages.

        Args:
            prompt: Incoming user prompt text.

        Returns:
            str: Generated assistant response text.

        Raises:
            ValueError: If prompt is empty or whitespace.
            AIClientError: On Ollama service communication failure.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")

        # 1. Fetch system prompt from dedicated prompts module
        system_prompt = get_system_prompt()

        # 2. Retrieve history from memory store
        history: List[ChatMessage] = self.memory_store.get_messages()

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
                "Dispatching structured chat payload (%d messages) to Ollama [Model: %s]",
                len(messages_payload),
                self.model_name,
            )

            # 4. Invoke Ollama structured chat API
            response = self._client.chat(
                model=self.model_name,
                messages=messages_payload,
            )

            # Extract message content safely across response variants
            response_content = self._extract_response_content(response)

            # 5. Commit user prompt and assistant response to memory upon success
            user_msg = ChatMessage(role="user", content=prompt)
            assistant_msg = ChatMessage(role="assistant", content=response_content)

            self.memory_store.add_message(user_msg)
            self.memory_store.add_message(assistant_msg)

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

    def generate_stream(self, prompt: str) -> Generator[str, None, None]:
        """Generates a streaming response formatted as SSE data frames.

        Args:
            prompt: Incoming user prompt text.

        Yields:
            str: SSE formatted data string containing token content or status.

        Raises:
            ValueError: If prompt is empty or whitespace.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")

        system_prompt = get_system_prompt()
        history: List[ChatMessage] = self.memory_store.get_messages()

        messages_payload = []
        if system_prompt:
            messages_payload.append({"role": "system", "content": system_prompt})

        for msg in history:
            messages_payload.append(msg.to_ollama_dict())

        messages_payload.append({"role": "user", "content": prompt})

        accumulated_tokens: List[str] = []

        try:
            logger.debug(
                "Dispatching streaming chat payload (%d messages) to Ollama [Model: %s]",
                len(messages_payload),
                self.model_name,
            )

            stream_response = self._client.chat(
                model=self.model_name,
                messages=messages_payload,
                stream=True,
            )

            for chunk in stream_response:
                content = self._extract_response_content(chunk)
                if content:
                    accumulated_tokens.append(content)
                    data_frame = json.dumps({"content": content})
                    yield f"data: {data_frame}\n\n"

            # Stream successfully completed: Commit conversation to memory
            full_response = "".join(accumulated_tokens)
            user_msg = ChatMessage(role="user", content=prompt)
            assistant_msg = ChatMessage(role="assistant", content=full_response)

            self.memory_store.add_message(user_msg)
            self.memory_store.add_message(assistant_msg)

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

    @staticmethod
    def _extract_response_content(response: Any) -> str:
        """Helper to extract response text safely across dict or object SDK models."""
        if isinstance(response, dict):
            msg = response.get("message", {})
            return str(msg.get("content", "")) if isinstance(msg, dict) else str(getattr(msg, "content", ""))

        msg = getattr(response, "message", None)
        if isinstance(msg, dict):
            return str(msg.get("content", ""))
        return str(getattr(msg, "content", ""))


# Global default client instance
ai_client = OllamaAIClient()
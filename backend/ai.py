import logging
from typing import Optional
from ollama import Client, ResponseError

from .config import settings

logger = logging.getLogger(__name__)


class AIClientError(Exception):
    """Custom exception raised when communication with the AI service fails."""

    pass


class OllamaAIClient:
    """Reusable client for managing interactions with the local Ollama LLM engine."""

    def __init__(
        self,
        host: Optional[str] = None,
        model_name: Optional[str] = None,
    ) -> None:
        """Initialize the Ollama AI client.

        Args:
            host: Base URL for the local Ollama server. Defaults to `settings.OLLAMA_HOST`.
            model_name: Target model identifier. Defaults to `settings.MODEL_NAME`.
        """
        self.host: str = host or settings.OLLAMA_HOST
        self.model_name: str = model_name or settings.MODEL_NAME
        self._client: Client = Client(host=self.host)

    def generate(self, prompt: str) -> str:
        """Generates a text completion response for a given prompt using Ollama.

        Args:
            prompt: The text prompt input for the model.

        Returns:
            str: The generated response text from the LLM.

        Raises:
            ValueError: If the prompt is empty or blank.
            AIClientError: If connection fails or Ollama returns an error.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")

        try:
            logger.debug(
                "Dispatching prompt to Ollama [Model: %s, Host: %s]",
                self.model_name,
                self.host,
            )

            response = self._client.generate(
                model=self.model_name,
                prompt=prompt,
            )

            # Handle both dictionary response structures and response objects
            if isinstance(response, dict):
                return str(response.get("response", ""))
            return str(getattr(response, "response", ""))

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


# Pre-configured default client instance for global usage
ai_client = OllamaAIClient()
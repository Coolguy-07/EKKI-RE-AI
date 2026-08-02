from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings for EKKI-RE-AI backend.

    Configuration parameters are loaded from environment variables or an optional
    `.env` file. Explicit default values are provided for local development.
    """

    # --- API Server Settings ---
    API_HOST: str = Field(
        default="127.0.0.1",
        description="Host interface for the FastAPI application server.",
    )
    API_PORT: int = Field(
        default=8000,
        description="Port number for the FastAPI application server.",
    )
    DEBUG: bool = Field(
        default=False,
        description="Enable or disable debug mode and verbose logging.",
    )

    # --- AI / Ollama Settings ---
    OLLAMA_HOST: str = Field(
        default="http://localhost:11434",
        description="Base URL for the local Ollama service endpoint.",
    )
    MODEL_NAME: str = Field(
        default="qwen3:8b",
        description="Default LLM model identifier used for local generation.",
    )

    # --- Memory Limits ---
    MAX_MEMORY_MESSAGES: int = Field(
        default=20,
        description="Maximum number of historical messages retained in memory.",
    )

    # --- Database Settings ---
    DATABASE_URL: str = Field(
        default="sqlite:///./ekki_re_ai.db",
        description="SQLAlchemy connection URI for persistent storage.",
    )

    # Pydantic Settings Configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Creates and caches the application settings instance."""
    return Settings()


# Default global settings instance
settings = get_settings()
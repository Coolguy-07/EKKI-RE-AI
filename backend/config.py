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
    CORS_ORIGINS: list[str] = Field(
        default=["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:8000", "http://localhost:8000", "*"],
        description="Allowed CORS origin URLs for application server.",
    )

    # --- AI / Ollama Settings ---
    OLLAMA_HOST: str = Field(
        default="http://localhost:11434",
        description="Base URL for the local Ollama service endpoint.",
    )
    MODEL_NAME: str = Field(
        default="mannix-re:latest",
        description="Default LLM model identifier used for local generation.",
    )
    OLLAMA_NUM_CTX: int = Field(
        default=4096,
        description="Context window size limit (num_ctx) passed to Ollama API for VRAM optimization.",
    )

    # Multi-Agent Pipeline Model Settings
    INTENT_ROUTER_MODEL: str = Field(
        default="mannix-re:latest",
        description="Model identifier for quick intent classification.",
    )
    DECOMPILER_MODEL: str = Field(
        default="qwen2.5-coder:7b",
        description="Decompilation Specialist model identifier.",
    )
    VULN_ANALYST_MODEL: str = Field(
        default="xploiter/pentester:latest",
        description="Vulnerability Analyst model identifier.",
    )
    OBFUSCATION_MODEL: str = Field(
        default="dolphin-mistral:7b-v2.6-q4_K_M",
        description="Obfuscation Specialist model identifier.",
    )
    SYNTHESIZER_MODEL: str = Field(
        default="mannix-re:latest",
        description="Lead Synthesizer model identifier.",
    )

    # --- Memory Limits ---
    MAX_MEMORY_MESSAGES: int = Field(
        default=20,
        description="Maximum number of historical messages retained in memory.",
    )

    # --- Workspace Storage Settings ---
    PROJECTS_DIR: str = Field(
        default="projects",
        description="Root directory path for project workspaces stored on disk.",
    )
    MAX_UPLOAD_SIZE_MB: int = Field(
        default=500,
        description="Maximum allowed file upload size in megabytes.",
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
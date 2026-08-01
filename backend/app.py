import logging
from typing import Annotated

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, StringConstraints

from .ai import AIClientError, ai_client
from .config import settings

logger = logging.getLogger(__name__)

# Initialize FastAPI Application
app = FastAPI(
    title="EKKI-RE-AI API",
    description="Production-grade local AI assistant backend powered by FastAPI and Ollama.",
    version="1.0.0",
    debug=settings.DEBUG,
)

# CORS Middleware Configuration for Frontend Development
origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request & Response Schemas
class ChatRequest(BaseModel):
    message: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1),
    ] = Field(
        ...,
        description="Non-empty user input prompt for the AI assistant.",
        json_schema_extra={"example": "What is the capital of France?"},
    )


class ChatResponse(BaseModel):
    response: str = Field(
        ...,
        description="The generated text response from the AI assistant.",
        json_schema_extra={"example": "The capital of France is Paris."},
    )


class HealthCheckResponse(BaseModel):
    status: str = Field(..., description="API operational status.")
    model: str = Field(..., description="Currently configured LLM model.")


# Endpoints
@app.get(
    "/health",
    response_model=HealthCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description="Endpoint for readiness and liveness probes.",
)
def health_check() -> HealthCheckResponse:
    """Returns application operational status and model configuration."""
    return HealthCheckResponse(
        status="healthy",
        model=settings.MODEL_NAME,
    )


@app.post(
    "/chat",
    response_model=ChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a message to the AI assistant",
    description="Processes a text prompt using the local Ollama engine and returns the completed text.",
)
def chat(request: ChatRequest) -> ChatResponse:
    """Handles chat generation requests.

    Synchronous def ensures execution runs safely in FastAPI's background threadpool,
    preventing blocking of the asyncio event loop during Ollama I/O operations.
    """
    try:
        generated_text = ai_client.generate(prompt=request.message)
        return ChatResponse(response=generated_text)

    except ValueError as err:
        logger.warning("Validation failure on chat request: %s", err)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    except AIClientError as err:
        logger.error("AI service error during processing: %s", err)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(err),
        ) from err

    except Exception as err:
        logger.exception("Unexpected error encountered during /chat request.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing your request.",
        ) from err
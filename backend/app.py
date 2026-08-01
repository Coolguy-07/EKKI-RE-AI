import logging
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from .ai import AIClientError, ai_client
from .config import settings

logger = logging.getLogger(__name__)

# Initialize FastAPI Application
app = FastAPI(
    title="EKKI-RE-AI API",
    description="Backend API for local AI assistant powered by FastAPI and Ollama.",
    version="1.0.0",
    debug=settings.DEBUG,
)


# Request and Response Pydantic Schemas
class ChatRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        description="The user input message or prompt to send to the AI model.",
        json_schema_extra={"example": "What is the capital of France?"},
    )


class ChatResponse(BaseModel):
    response: str = Field(
        ...,
        description="The generated text response from the AI assistant.",
        json_schema_extra={"example": "The capital of France is Paris."},
    )


# API Endpoints
@app.post(
    "/chat",
    response_model=ChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Chat with the local AI assistant",
    description="Processes a prompt through the local Ollama LLM and returns the generated text response.",
)
def chat(request: ChatRequest) -> ChatResponse:
    """Endpoint for generating AI assistant responses.

    Using standard synchronous def ensures FastAPI automatically runs blocking
    I/O calls (Ollama HTTP client) inside an external thread pool.
    """
    try:
        generated_text = ai_client.generate(prompt=request.message)
        return ChatResponse(response=generated_text)

    except ValueError as err:
        logger.warning("Invalid request payload: %s", err)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    except AIClientError as err:
        logger.error("AI client operational error: %s", err)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(err),
        ) from err

    except Exception as err:
        logger.exception("Unhandled exception during /chat request execution.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal server error occurred while processing your request.",
        ) from err
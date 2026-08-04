"""
backend/app.py

Production-grade local AI assistant backend powered by FastAPI and Ollama.
Includes Project Workspace REST APIs and session management.
"""

import logging
from typing import Annotated, List, Optional

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Path as APIPath,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field, StringConstraints

from .agent_orchestrator import agent_orchestrator
from .ai import AIClientError, ai_client
from .analysis import BinaryMetadata
from .config import settings
from .workspace import (
    FileNotFoundInWorkspaceError,
    InvalidWorkspacePathError,
    ProjectAlreadyExistsError,
    ProjectFileMetadata,
    ProjectMetadata,
    ProjectNotFoundError,
    ProjectSummary,
    WorkspaceCreate,
    WorkspaceError,
    WorkspaceManager,
    WorkspaceUpdate,
    workspace_manager,
)

logger = logging.getLogger(__name__)


# Initialize FastAPI Application
app = FastAPI(
    title="EKKI-RE-AI API",
    description="Production-grade local AI assistant and Reverse Engineering platform backend powered by FastAPI and Ollama.",
    version="1.0.0",
    debug=settings.DEBUG,
)

# Configurable CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
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
    session_id: Optional[str] = Field(
        default="default",
        description="Unique conversation session identifier for isolated memory store.",
        json_schema_extra={"example": "conv-1700000000000-xyz"},
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


class OpenCloseProjectRequest(BaseModel):
    session_id: str = Field(
        default="default",
        description="Unique conversation session identifier binding the active project workspace.",
    )


class OpenCloseProjectResponse(BaseModel):
    message: str
    session_id: str
    active_project: Optional[ProjectMetadata] = None


class RenameFileRequest(BaseModel):
    new_filename: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1),
    ] = Field(..., description="New user-visible display filename.")


class DeleteOperationResponse(BaseModel):
    success: bool
    message: str


# Helper Function to Map Workspace Domain Exceptions to HTTP Status Codes
def _handle_workspace_exception(err: Exception) -> HTTPException:
    if isinstance(err, ProjectNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    elif isinstance(err, FileNotFoundInWorkspaceError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    elif isinstance(err, InvalidWorkspacePathError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    elif isinstance(err, ProjectAlreadyExistsError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err))
    elif isinstance(err, WorkspaceError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    else:
        logger.exception("Unexpected workspace error.")
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while processing workspace operation.",
        )


# System & Health Endpoints
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


# Project Workspace Management REST API Endpoints
@app.get(
    "/api/projects",
    response_model=List[ProjectSummary],
    status_code=status.HTTP_200_OK,
    summary="List all project workspaces",
    description="Retrieves a list of lightweight project summaries sorted by last modification timestamp.",
)
def list_projects() -> List[ProjectSummary]:
    try:
        return workspace_manager.list_projects()
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.post(
    "/api/projects",
    response_model=ProjectMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new project workspace",
    description="Initializes an isolated project directory structure on disk with metadata.",
)
def create_project(body: WorkspaceCreate) -> ProjectMetadata:
    try:
        return workspace_manager.create_project(
            name=body.name,
            description=body.description,
            tags=body.tags,
            model=body.model,
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.get(
    "/api/projects/{project_id}",
    response_model=ProjectMetadata,
    status_code=status.HTTP_200_OK,
    summary="Get project metadata",
    description="Retrieves full metadata and file catalog for a given project_id.",
)
def get_project(
    project_id: str = APIPath(..., description="Unique project identifier"),
) -> ProjectMetadata:
    try:
        return workspace_manager.get_project(project_id=project_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.put(
    "/api/projects/{project_id}",
    response_model=ProjectMetadata,
    status_code=status.HTTP_200_OK,
    summary="Update project metadata",
    description="Updates name, description, tags, status, or model for a project.",
)
def update_project(
    project_id: str = APIPath(..., description="Unique project identifier"),
    body: WorkspaceUpdate = ...,
) -> ProjectMetadata:
    try:
        return workspace_manager.update_project(
            project_id=project_id,
            name=body.name,
            description=body.description,
            tags=body.tags,
            status=body.status,
            model=body.model,
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.delete(
    "/api/projects/{project_id}",
    response_model=DeleteOperationResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete a project workspace",
    description="Permanently deletes the project directory and all associated stored files.",
)
def delete_project(
    project_id: str = APIPath(..., description="Unique project identifier"),
) -> DeleteOperationResponse:
    try:
        workspace_manager.delete_project(project_id=project_id)
        return DeleteOperationResponse(
            success=True,
            message=f"Project '{project_id}' deleted successfully.",
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.post(
    "/api/projects/{project_id}/open",
    response_model=OpenCloseProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Open a project workspace for a session",
    description="Binds a project workspace as the active project for a given session_id.",
)
def open_project(
    project_id: str = APIPath(..., description="Unique project identifier"),
    body: OpenCloseProjectRequest = ...,
) -> OpenCloseProjectResponse:
    try:
        metadata = workspace_manager.open_project(session_id=body.session_id, project_id=project_id)
        return OpenCloseProjectResponse(
            message=f"Project '{project_id}' is now active for session '{body.session_id}'.",
            session_id=body.session_id,
            active_project=metadata,
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.post(
    "/api/projects/{project_id}/close",
    response_model=OpenCloseProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Close active project workspace for a session",
    description="Unbinds active project workspace for a given session_id.",
)
def close_project(
    project_id: str = APIPath(..., description="Unique project identifier"),
    body: OpenCloseProjectRequest = ...,
) -> OpenCloseProjectResponse:
    try:
        workspace_manager.close_project(session_id=body.session_id)
        return OpenCloseProjectResponse(
            message=f"Project closed for session '{body.session_id}'.",
            session_id=body.session_id,
            active_project=None,
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.get(
    "/api/projects/active/{session_id}",
    response_model=Optional[ProjectMetadata],
    status_code=status.HTTP_200_OK,
    summary="Get active project metadata for a session",
    description="Returns metadata of the project workspace currently bound to session_id, or null if none.",
)
def get_active_project(
    session_id: str = APIPath(..., description="Session identifier"),
) -> Optional[ProjectMetadata]:
    try:
        return workspace_manager.get_active_project(session_id=session_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


# File Upload & Management REST API Endpoints
@app.post(
    "/api/projects/{project_id}/files",
    response_model=ProjectFileMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a file to project workspace",
    description="Stores uploaded binary file under an immutable unique File ID (files/{file_id}/{filename}).",
)
def upload_file(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file: UploadFile = File(..., description="Binary or code file payload"),
    tags: Optional[str] = Form(None, description="Comma-separated file tags"),
) -> ProjectFileMetadata:
    try:
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        content_buf = bytearray()
        chunk_size = 1024 * 1024  # 1MB chunks

        while True:
            chunk = file.file.read(chunk_size)
            if not chunk:
                break
            content_buf.extend(chunk)
            if len(content_buf) > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File size exceeds maximum allowed upload threshold of {settings.MAX_UPLOAD_SIZE_MB} MB.",
                )

        content = bytes(content_buf)

        # Parse tags cleanly: remove empty strings and whitespace-only entries
        parsed_tags = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

        return workspace_manager.add_file(
            project_id=project_id,
            filename=file.filename or "uploaded_file.bin",
            content=content,
            mime_type=file.content_type or "application/octet-stream",
            tags=parsed_tags,
        )
    except HTTPException:
        raise
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.get(
    "/api/projects/{project_id}/files/{file_id}",
    status_code=status.HTTP_200_OK,
    summary="Download or view a stored file",
    description="Returns raw file payload as a downloadable file response using file_id.",
)
def get_file(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
) -> FileResponse:
    try:
        file_path = workspace_manager.get_file_path(project_id=project_id, file_id=file_id)
        project_meta = workspace_manager.get_project(project_id=project_id)
        file_meta = project_meta.files[file_id]

        return FileResponse(
            path=str(file_path),
            filename=file_meta.filename,
            media_type=file_meta.mime_type,
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.put(
    "/api/projects/{project_id}/files/{file_id}",
    response_model=ProjectFileMetadata,
    status_code=status.HTTP_200_OK,
    summary="Rename stored file display name",
    description="Updates user-visible display filename without breaking immutable file_id paths.",
)
def rename_file(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
    body: RenameFileRequest = ...,
) -> ProjectFileMetadata:
    try:
        return workspace_manager.rename_file(
            project_id=project_id,
            file_id=file_id,
            new_filename=body.new_filename,
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.delete(
    "/api/projects/{project_id}/files/{file_id}",
    response_model=DeleteOperationResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete stored file from project workspace",
    description="Removes stored file and associated analysis engine folders for file_id.",
)
def delete_file(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
) -> DeleteOperationResponse:
    try:
        workspace_manager.delete_file(project_id=project_id, file_id=file_id)
        return DeleteOperationResponse(
            success=True,
            message=f"File '{file_id}' deleted successfully from project '{project_id}'.",
        )
    except Exception as err:
        raise _handle_workspace_exception(err) from err


# Binary Intelligence Layer REST API Endpoints
@app.get(
    "/api/projects/{project_id}/files/{file_id}/metadata",
    response_model=BinaryMetadata,
    status_code=status.HTTP_200_OK,
    summary="Get extracted Binary Intelligence metadata",
    description="Retrieves structured analysis metadata stored under analysis/{file_id}/metadata.json.",
)
def get_file_metadata(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
) -> BinaryMetadata:
    try:
        return workspace_manager.get_file_analysis_metadata(project_id=project_id, file_id=file_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.post(
    "/api/projects/{project_id}/files/{file_id}/analyze",
    response_model=BinaryMetadata,
    status_code=status.HTTP_200_OK,
    summary="Trigger Binary Intelligence analysis pipeline",
    description="Executes analysis engines on stored file payload and updates analysis/{file_id}/metadata.json.",
)
def analyze_file(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
) -> BinaryMetadata:
    try:
        return workspace_manager.analyze_file(project_id=project_id, file_id=file_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.get(
    "/api/projects/{project_id}/files/{file_id}/pe",
    status_code=status.HTTP_200_OK,
    summary="Get parsed PE Information artifact",
    description="Retrieves structured PE analysis payload stored under analysis/{file_id}/pe.json.",
)
def get_pe_metadata(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
):
    try:
        return workspace_manager.get_file_pe_metadata(project_id=project_id, file_id=file_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.get(
    "/api/projects/{project_id}/files/{file_id}/elf",
    status_code=status.HTTP_200_OK,
    summary="Get parsed ELF Information artifact",
    description="Retrieves structured ELF analysis payload stored under analysis/{file_id}/elf.json.",
)
def get_elf_metadata(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
):
    try:
        return workspace_manager.get_file_elf_metadata(project_id=project_id, file_id=file_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


@app.get(
    "/api/projects/{project_id}/files/{file_id}/macho",
    status_code=status.HTTP_200_OK,
    summary="Get parsed Mach-O Information artifact",
    description="Retrieves structured Mach-O analysis payload stored under analysis/{file_id}/macho.json.",
)
def get_macho_metadata(
    project_id: str = APIPath(..., description="Unique project identifier"),
    file_id: str = APIPath(..., description="Immutable unique file identifier"),
):
    try:
        return workspace_manager.get_file_macho_metadata(project_id=project_id, file_id=file_id)
    except Exception as err:
        raise _handle_workspace_exception(err) from err


# Existing AI Chat Endpoints (Preserved with complete backward compatibility)
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
        generated_text = ai_client.generate(prompt=request.message, session_id=request.session_id)
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


@app.post(
    "/chat/stream",
    status_code=status.HTTP_200_OK,
    summary="Send a message to the AI assistant with real-time streaming",
    description="Streams text generation tokens real-time using Server-Sent Events (SSE).",
)
def chat_stream(request: ChatRequest) -> StreamingResponse:
    """Handles streaming chat generation requests using SSE.

    Invokes ai_client.generate_stream() and streams chunk frames using StreamingResponse.
    """
    try:
        generator = ai_client.generate_stream(prompt=request.message, session_id=request.session_id)
        return StreamingResponse(
            content=generator,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    except ValueError as err:
        logger.warning("Validation failure on chat stream request: %s", err)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    except AIClientError as err:
        logger.error("AI service error during streaming request: %s", err)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(err),
        ) from err

    except Exception as err:
        logger.exception("Unexpected error encountered during /chat/stream request.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while initializing response stream.",
        ) from err


@app.post(
    "/chat/orchestrate",
    status_code=status.HTTP_200_OK,
    summary="Multi-agent intent-driven routing chat analysis stream",
    description="Routes prompts through intent router and specialized Ollama model pipeline with VRAM cleanup (keep_alive: 0).",
)
def chat_orchestrate(request: ChatRequest) -> StreamingResponse:
    """Handles multi-agent orchestrated streaming requests using SSE."""
    try:
        generator = agent_orchestrator.run_pipeline_stream(
            prompt=request.message,
            session_id=request.session_id,
        )
        return StreamingResponse(
            content=generator,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    except ValueError as err:
        logger.warning("Validation failure on orchestrate request: %s", err)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    except Exception as err:
        logger.exception("Unexpected error encountered during /chat/orchestrate request.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while initializing orchestrator stream.",
        ) from err
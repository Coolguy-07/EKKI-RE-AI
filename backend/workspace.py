"""
backend/workspace.py

Production-grade modular WorkspaceManager service for EKKI-RE-AI.
Manages project lifecycle, isolated disk structure, metadata persistence,
and file storage with unique internal File IDs and path security guarantees.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from .analysis import BinaryMetadata, analysis_pipeline
from .config import settings

logger = logging.getLogger(__name__)


# Custom Domain Exceptions
class WorkspaceError(Exception):
    """Base exception for workspace management operations."""
    pass


class ProjectNotFoundError(WorkspaceError):
    """Raised when a requested project ID does not exist."""
    pass


class FileNotFoundInWorkspaceError(WorkspaceError):
    """Raised when a requested file ID does not exist within a project."""
    pass


class InvalidWorkspacePathError(WorkspaceError):
    """Raised when path traversal or unsafe path manipulation is detected."""
    pass


class ProjectAlreadyExistsError(WorkspaceError):
    """Raised when attempting to create a project with a duplicate ID."""
    pass


# Domain Models
class ProjectFileMetadata(BaseModel):
    """Domain model representing a file stored inside a project workspace."""

    file_id: str = Field(
        ...,
        description="Immutable unique internal file identifier (e.g. file-8d9f2a1b).",
    )
    filename: str = Field(
        ...,
        description="Display name of the file.",
    )
    stored_path: str = Field(
        ...,
        description="Relative path within the project workspace directory.",
    )
    size_bytes: int = Field(
        ...,
        description="Exact file size in bytes.",
    )
    mime_type: str = Field(
        default="application/octet-stream",
        description="MIME content type of the file.",
    )
    uploaded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of file upload.",
    )
    sha256: str = Field(
        ...,
        description="Hexadecimal SHA-256 hash of the binary file content.",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Analyst tags for the file (e.g., pe32, executable, unpacked).",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible metadata payload for future parsers and analysis engines.",
    )


class ProjectMetadata(BaseModel):
    """Domain model representing a project workspace and its stored metadata."""

    project_id: str = Field(
        ...,
        description="Immutable unique project identifier (e.g. proj-1722762000-a1b2c3).",
    )
    name: str = Field(
        ...,
        description="User-defined display name of the project.",
    )
    description: Optional[str] = Field(
        default="",
        description="Analyst description or summary for the project workspace.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of project creation.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of last modification.",
    )
    status: str = Field(
        default="idle",
        description="Lifecycle status of the analysis workspace (e.g. idle, active, analyzing, completed).",
    )
    model: str = Field(
        default_factory=lambda: settings.MODEL_NAME,
        description="LLM or analysis model configured for this project.",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Categorization tags for the project.",
    )
    files: Dict[str, ProjectFileMetadata] = Field(
        default_factory=dict,
        description="Dictionary mapping unique file_id to file metadata for O(1) lookups.",
    )
    custom_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible metadata storage for future engines, symbol indexing, or RAG context.",
    )


class ProjectSummary(BaseModel):
    """Lightweight summary model for listing project workspaces efficiently."""

    project_id: str
    name: str
    description: Optional[str] = ""
    created_at: datetime
    updated_at: datetime
    status: str
    file_count: int
    tags: List[str]


class WorkspaceCreate(BaseModel):
    """DTO for creating a new project workspace."""

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default="")
    tags: Optional[List[str]] = Field(default_factory=list)
    model: Optional[str] = None


class WorkspaceUpdate(BaseModel):
    """DTO for updating an existing project workspace."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    status: Optional[str] = None
    model: Optional[str] = None


# Core Workspace Manager Service
class WorkspaceManager:
    """Thread-safe backend manager for project workspaces on disk.

    Handles creation, persistence, directory isolation, file storage,
    unique File ID assignment, path security validation, and metadata management.
    """

    def __init__(self, projects_dir: Optional[Path] = None) -> None:
        """Initialize WorkspaceManager with target root storage directory."""
        if projects_dir is None:
            projects_dir = Path(settings.PROJECTS_DIR)

        self.projects_dir: Path = projects_dir.resolve()
        self._lock: threading.RLock = threading.RLock()
        self._active_sessions: Dict[str, str] = {}  # session_id -> project_id

        # Ensure base storage directory exists
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    # --- Security & Path Helper Methods ---
    def _sanitize_identifier(self, id_str: str) -> str:
        """Sanitizes project or file identifiers, preventing directory traversal."""
        sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "", id_str)
        if not sanitized or sanitized != id_str:
            raise InvalidWorkspacePathError(f"Invalid identifier format: '{id_str}'")
        return sanitized

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitizes user-provided filenames while keeping valid extensions."""
        basename = os.path.basename(filename)
        sanitized = re.sub(r"[^\w\-. ]", "_", basename).strip()
        if not sanitized or sanitized in (".", ".."):
            sanitized = "unnamed_file.bin"
        return sanitized

    def _validate_safe_path(self, base_dir: Path, target_path: Path) -> Path:
        """Ensures target_path resolves strictly within base_dir to prevent path traversal."""
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        try:
            resolved_target.relative_to(resolved_base)
        except ValueError as err:
            logger.error("Path traversal attempt detected: target '%s' outside base '%s'", target_path, base_dir)
            raise InvalidWorkspacePathError("Path traversal violation detected.") from err
        return resolved_target

    def _get_project_dir(self, project_id: str) -> Path:
        """Returns the verified project workspace directory on disk."""
        safe_id = self._sanitize_identifier(project_id)
        project_dir = self.projects_dir / safe_id
        return self._validate_safe_path(self.projects_dir, project_dir)

    def _get_metadata_file(self, project_id: str) -> Path:
        """Returns path to metadata.json inside project directory."""
        project_dir = self._get_project_dir(project_id)
        metadata_file = project_dir / "metadata.json"
        return self._validate_safe_path(project_dir, metadata_file)

    def _load_metadata_unlocked(self, project_id: str) -> ProjectMetadata:
        """Internal helper to load metadata without acquiring locks."""
        project_dir = self._get_project_dir(project_id)
        if not project_dir.exists() or not project_dir.is_dir():
            raise ProjectNotFoundError(f"Project '{project_id}' not found.")

        metadata_file = self._get_metadata_file(project_id)
        if not metadata_file.exists():
            raise ProjectNotFoundError(f"Metadata file missing for project '{project_id}'.")

        try:
            with open(metadata_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return ProjectMetadata.model_validate(data)
        except Exception as err:
            logger.error("Failed to parse metadata for project '%s': %s", project_id, err)
            raise WorkspaceError(f"Corrupted metadata in project '{project_id}': {err}") from err

    def _save_metadata_unlocked(self, metadata: ProjectMetadata) -> None:
        """Internal helper to persist metadata atomically without acquiring locks."""
        project_dir = self._get_project_dir(metadata.project_id)
        if not project_dir.exists():
            raise ProjectNotFoundError(f"Project directory missing for '{metadata.project_id}'.")

        metadata.updated_at = datetime.now(timezone.utc)
        metadata_file = self._get_metadata_file(metadata.project_id)
        temp_file = metadata_file.with_suffix(".json.tmp")

        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json_str = metadata.model_dump_json(indent=2)
                f.write(json_str)
            temp_file.replace(metadata_file)
        except Exception as err:
            if temp_file.exists():
                temp_file.unlink()
            logger.error("Failed to save metadata for project '%s': %s", metadata.project_id, err)
            raise WorkspaceError(f"Could not persist metadata for project '{metadata.project_id}': {err}") from err

    # --- Project Lifecycle CRUD Operations ---
    def create_project(
        self,
        name: str,
        description: Optional[str] = "",
        tags: Optional[List[str]] = None,
        model: Optional[str] = None,
    ) -> ProjectMetadata:
        """Creates a new isolated project workspace directory structure on disk.

        Args:
            name: Display name of the project.
            description: Analyst summary description.
            tags: Project tags.
            model: Target LLM model name.

        Returns:
            ProjectMetadata model instance.
        """
        with self._lock:
            timestamp = int(datetime.now(timezone.utc).timestamp())
            unique_hex = uuid.uuid4().hex[:6]
            project_id = f"proj-{timestamp}-{unique_hex}"

            project_dir = self._get_project_dir(project_id)
            if project_dir.exists():
                raise ProjectAlreadyExistsError(f"Project directory '{project_id}' already exists.")

            # Create isolated subdirectories per project specification
            subdirs = ["files", "reports", "analysis", "cache", "thumbnails"]
            for subdir in subdirs:
                subdir_path = project_dir / subdir
                subdir_path.mkdir(parents=True, exist_ok=True)

            metadata = ProjectMetadata(
                project_id=project_id,
                name=name,
                description=description or "",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                status="idle",
                model=model or settings.MODEL_NAME,
                tags=tags or [],
                files={},
            )

            self._save_metadata_unlocked(metadata)
            logger.info("Created project workspace '%s' (%s)", name, project_id)
            return metadata

    def get_project(self, project_id: str) -> ProjectMetadata:
        """Retrieves ProjectMetadata for a given project_id."""
        with self._lock:
            return self._load_metadata_unlocked(project_id)

    def list_projects(self) -> List[ProjectSummary]:
        """Lists all project workspaces as lightweight ProjectSummary objects."""
        with self._lock:
            summaries: List[ProjectSummary] = []
            if not self.projects_dir.exists():
                return summaries

            for item in self.projects_dir.iterdir():
                if item.is_dir():
                    metadata_file = item / "metadata.json"
                    if metadata_file.exists():
                        try:
                            meta = self._load_metadata_unlocked(item.name)
                            summaries.append(
                                ProjectSummary(
                                    project_id=meta.project_id,
                                    name=meta.name,
                                    description=meta.description,
                                    created_at=meta.created_at,
                                    updated_at=meta.updated_at,
                                    status=meta.status,
                                    file_count=len(meta.files),
                                    tags=meta.tags,
                                )
                            )
                        except Exception as err:
                            logger.warning("Skipping unreadable project dir '%s': %s", item.name, err)

            summaries.sort(key=lambda x: x.updated_at, reverse=True)
            return summaries

    def update_project(
        self,
        project_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        status: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ProjectMetadata:
        """Updates project metadata fields thread-safely."""
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)

            if name is not None:
                metadata.name = name
            if description is not None:
                metadata.description = description
            if tags is not None:
                metadata.tags = tags
            if status is not None:
                metadata.status = status
            if model is not None:
                metadata.model = model

            self._save_metadata_unlocked(metadata)
            logger.info("Updated project metadata for '%s'", project_id)
            return metadata

    def delete_project(self, project_id: str) -> bool:
        """Deletes project directory and all associated files/subdirectories permanently."""
        with self._lock:
            project_dir = self._get_project_dir(project_id)
            if not project_dir.exists():
                raise ProjectNotFoundError(f"Cannot delete: Project '{project_id}' not found.")

            try:
                shutil.rmtree(project_dir)
                # Clear active session bindings referencing this project
                self._active_sessions = {
                    sid: pid for sid, pid in self._active_sessions.items() if pid != project_id
                }
                logger.info("Deleted project workspace '%s'", project_id)
                return True
            except Exception as err:
                logger.error("Failed to delete project directory '%s': %s", project_id, err)
                raise WorkspaceError(f"Failed to delete project '{project_id}': {err}") from err

    # --- Session Management ---
    def open_project(self, session_id: str, project_id: str) -> ProjectMetadata:
        """Binds a project workspace as active for a given conversation session_id."""
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            sid = session_id or "default"
            self._active_sessions[sid] = project_id
            logger.info("Session '%s' opened active project '%s'", sid, project_id)
            return metadata

    def close_project(self, session_id: str) -> None:
        """Unbinds active project workspace for session_id."""
        with self._lock:
            sid = session_id or "default"
            if sid in self._active_sessions:
                del self._active_sessions[sid]
                logger.info("Session '%s' closed active project", sid)

    def get_active_project(self, session_id: str) -> Optional[ProjectMetadata]:
        """Returns currently active ProjectMetadata for session_id, if open."""
        with self._lock:
            sid = session_id or "default"
            project_id = self._active_sessions.get(sid)
            if not project_id:
                return None
            try:
                return self._load_metadata_unlocked(project_id)
            except ProjectNotFoundError:
                del self._active_sessions[sid]
                return None

    # --- File Management & Storage Operations ---
    def add_file(
        self,
        project_id: str,
        filename: str,
        content: bytes,
        mime_type: Optional[str] = "application/octet-stream",
        tags: Optional[List[str]] = None,
    ) -> ProjectFileMetadata:
        """Uploads and stores a file in project workspace with an immutable File ID.

        File storage path: `projects/{project_id}/files/{file_id}/{filename}`
        Prepares analysis directories: `projects/{project_id}/analysis/{file_id}/`, etc.

        Args:
            project_id: Target project identifier.
            filename: Display name of uploaded file.
            content: Raw byte payload.
            mime_type: MIME content type string.
            tags: File categorization tags.

        Returns:
            ProjectFileMetadata domain model.
        """
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            project_dir = self._get_project_dir(project_id)

            # Generate immutable internal File ID and compute SHA-256
            file_id = f"file-{uuid.uuid4().hex[:8]}"
            safe_filename = self._sanitize_filename(filename)
            sha256_hash = hashlib.sha256(content).hexdigest()
            size_bytes = len(content)

            # Construct directory paths
            file_dir = project_dir / "files" / file_id
            file_dir = self._validate_safe_path(project_dir / "files", file_dir)
            file_dir.mkdir(parents=True, exist_ok=True)

            target_file_path = file_dir / safe_filename
            self._validate_safe_path(file_dir, target_file_path)

            # Save content to disk
            with open(target_file_path, "wb") as f:
                f.write(content)

            # Pre-create future analysis artifact subdirectories under file_id
            for engine_subdir in ["analysis", "reports", "cache", "thumbnails"]:
                engine_dir = project_dir / engine_subdir / file_id
                engine_dir = self._validate_safe_path(project_dir / engine_subdir, engine_dir)
                engine_dir.mkdir(parents=True, exist_ok=True)

            rel_stored_path = f"files/{file_id}/{safe_filename}"

            # Run Analysis Pipeline (Binary Intelligence Layer)
            try:
                analysis_meta = analysis_pipeline.run_pipeline(
                    project_dir=project_dir,
                    file_id=file_id,
                    filename=safe_filename,
                    content=content,
                    mime_type=mime_type or "application/octet-stream",
                )
                analysis_dict = analysis_meta.model_dump()
            except Exception as err:
                logger.error("Error executing analysis pipeline for file '%s': %s", file_id, err)
                analysis_dict = {}

            file_meta = ProjectFileMetadata(
                file_id=file_id,
                filename=safe_filename,
                stored_path=rel_stored_path,
                size_bytes=size_bytes,
                mime_type=mime_type or "application/octet-stream",
                uploaded_at=datetime.now(timezone.utc),
                sha256=sha256_hash,
                tags=tags or [],
                metadata=analysis_dict,
            )

            metadata.files[file_id] = file_meta
            self._save_metadata_unlocked(metadata)

            logger.info(
                "Stored file '%s' (File ID: %s, %d bytes) in project '%s'",
                safe_filename,
                file_id,
                size_bytes,
                project_id,
            )
            return file_meta

    def rename_file(self, project_id: str, file_id: str, new_filename: str) -> ProjectFileMetadata:
        """Renames display name of a stored file without breaking internal File ID paths."""
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            safe_new_name = self._sanitize_filename(new_filename)
            file_meta = metadata.files[safe_file_id]

            # Update display filename while keeping stored_path & file_id intact
            file_meta.filename = safe_new_name
            metadata.files[safe_file_id] = file_meta
            self._save_metadata_unlocked(metadata)

            logger.info("Renamed display name of File ID '%s' to '%s' in project '%s'", file_id, safe_new_name, project_id)
            return file_meta

    def delete_file(self, project_id: str, file_id: str) -> bool:
        """Removes stored file and associated analysis directories for file_id."""
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            project_dir = self._get_project_dir(project_id)

            # Remove file directory and analysis subdirectories
            for subdir in ["files", "analysis", "reports", "cache", "thumbnails"]:
                target_dir = project_dir / subdir / safe_file_id
                if target_dir.exists():
                    try:
                        shutil.rmtree(target_dir)
                    except Exception as err:
                        logger.warning("Error removing subdir '%s' for file '%s': %s", target_dir, file_id, err)

            del metadata.files[safe_file_id]
            self._save_metadata_unlocked(metadata)
            logger.info("Deleted file ID '%s' from project '%s'", file_id, project_id)
            return True

    def get_file_path(self, project_id: str, file_id: str) -> Path:
        """Returns absolute disk path for a stored file by file_id."""
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            file_meta = metadata.files[safe_file_id]
            project_dir = self._get_project_dir(project_id)
            file_path = project_dir / file_meta.stored_path
            return self._validate_safe_path(project_dir, file_path)

    # --- Subdirectory Access Helper Methods for Analysis Engines ---
    def get_analysis_dir(self, project_id: str, file_id: str, create_if_missing: bool = True) -> Path:
        """Returns path to projects/{project_id}/analysis/{file_id}/."""
        return self._get_engine_dir(project_id, "analysis", file_id, create_if_missing)

    def get_reports_dir(self, project_id: str, file_id: str, create_if_missing: bool = True) -> Path:
        """Returns path to projects/{project_id}/reports/{file_id}/."""
        return self._get_engine_dir(project_id, "reports", file_id, create_if_missing)

    def get_cache_dir(self, project_id: str, file_id: str, create_if_missing: bool = True) -> Path:
        """Returns path to projects/{project_id}/cache/{file_id}/."""
        return self._get_engine_dir(project_id, "cache", file_id, create_if_missing)

    def get_thumbnails_dir(self, project_id: str, file_id: str, create_if_missing: bool = True) -> Path:
        """Returns path to projects/{project_id}/thumbnails/{file_id}/."""
        return self._get_engine_dir(project_id, "thumbnails", file_id, create_if_missing)

    def _get_engine_dir(self, project_id: str, category: str, file_id: str, create_if_missing: bool) -> Path:
        """Helper to return validated analysis engine directory paths."""
        project_dir = self._get_project_dir(project_id)
        safe_file_id = self._sanitize_identifier(file_id)
        engine_dir = project_dir / category / safe_file_id
        engine_dir = self._validate_safe_path(project_dir / category, engine_dir)
        if create_if_missing:
            engine_dir.mkdir(parents=True, exist_ok=True)
        return engine_dir


    def get_file_analysis_metadata(self, project_id: str, file_id: str) -> BinaryMetadata:
        """Retrieves structured BinaryMetadata for file_id from analysis/{file_id}/metadata.json.

        If missing or corrupted, triggers a re-analysis from stored disk file.
        """
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            project_dir = self._get_project_dir(project_id)
            metadata_json_path = project_dir / "analysis" / safe_file_id / "metadata.json"

            if metadata_json_path.exists():
                try:
                    with open(metadata_json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    return BinaryMetadata.model_validate(data)
                except Exception as err:
                    logger.warning("Corrupted analysis metadata JSON for file_id='%s': %s. Re-analyzing...", file_id, err)

            # Re-run analysis if missing or unreadable
            return self.analyze_file(project_id=project_id, file_id=file_id)

    def analyze_file(self, project_id: str, file_id: str) -> BinaryMetadata:
        """Re-runs analysis pipeline for stored file_id."""
        with self._lock:
            file_path = self.get_file_path(project_id=project_id, file_id=file_id)
            project_dir = self._get_project_dir(project_id)
            file_meta = self._load_metadata_unlocked(project_id).files[self._sanitize_identifier(file_id)]

            with open(file_path, "rb") as f:
                content = f.read()

            analysis_meta = analysis_pipeline.run_pipeline(
                project_dir=project_dir,
                file_id=file_id,
                filename=file_meta.filename,
                content=content,
                mime_type=file_meta.mime_type,
            )

            # Update cached metadata inside project metadata.json
            proj_metadata = self._load_metadata_unlocked(project_id)
            if file_id in proj_metadata.files:
                proj_metadata.files[file_id].metadata = analysis_meta.model_dump()
                self._save_metadata_unlocked(proj_metadata)

            return analysis_meta

    def get_file_pe_metadata(self, project_id: str, file_id: str) -> Dict[str, Any]:
        """Retrieves structured PE analysis payload from analysis/{file_id}/pe.json.

        If missing, triggers analysis pipeline on demand.
        """
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            project_dir = self._get_project_dir(project_id)
            pe_json_path = project_dir / "analysis" / safe_file_id / "pe.json"

            if pe_json_path.exists():
                try:
                    with open(pe_json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as err:
                    logger.warning("Corrupted PE JSON for file_id='%s': %s. Re-analyzing...", file_id, err)

            # Re-run analysis if missing or unreadable
            self.analyze_file(project_id=project_id, file_id=file_id)
            if pe_json_path.exists():
                try:
                    with open(pe_json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass

            return {"schema_version": 1, "file_id": file_id, "is_pe": False, "errors": ["PE metadata unavailable."]}

    def get_file_elf_metadata(self, project_id: str, file_id: str) -> Dict[str, Any]:
        """Retrieves structured ELF analysis payload from analysis/{file_id}/elf.json.

        If missing, triggers analysis pipeline on demand.
        """
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            project_dir = self._get_project_dir(project_id)
            elf_json_path = project_dir / "analysis" / safe_file_id / "elf.json"

            if elf_json_path.exists():
                try:
                    with open(elf_json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as err:
                    logger.warning("Corrupted ELF JSON for file_id='%s': %s. Re-analyzing...", file_id, err)

            # Re-run analysis if missing or unreadable
            self.analyze_file(project_id=project_id, file_id=file_id)
            if elf_json_path.exists():
                try:
                    with open(elf_json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass

            return {"schema_version": 1, "file_id": file_id, "is_elf": False, "errors": ["ELF metadata unavailable."]}

    def get_file_macho_metadata(self, project_id: str, file_id: str) -> Dict[str, Any]:
        """Retrieves structured Mach-O analysis payload from analysis/{file_id}/macho.json.

        If missing, triggers analysis pipeline on demand.
        """
        with self._lock:
            metadata = self._load_metadata_unlocked(project_id)
            safe_file_id = self._sanitize_identifier(file_id)

            if safe_file_id not in metadata.files:
                raise FileNotFoundInWorkspaceError(f"File ID '{file_id}' not found in project '{project_id}'.")

            project_dir = self._get_project_dir(project_id)
            macho_json_path = project_dir / "analysis" / safe_file_id / "macho.json"

            if macho_json_path.exists():
                try:
                    with open(macho_json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as err:
                    logger.warning("Corrupted Mach-O JSON for file_id='%s': %s. Re-analyzing...", file_id, err)

            # Re-run analysis if missing or unreadable
            self.analyze_file(project_id=project_id, file_id=file_id)
            if macho_json_path.exists():
                try:
                    with open(macho_json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass

            return {"schema_version": 1, "file_id": file_id, "is_macho": False, "errors": ["Mach-O metadata unavailable."]}


# Global singleton instance of WorkspaceManager
workspace_manager = WorkspaceManager()



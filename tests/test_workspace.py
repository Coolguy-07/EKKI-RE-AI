"""
tests/test_workspace.py

Comprehensive test suite verifying WorkspaceManager functionality,
File ID generation, SHA-256 hashing, path security, thread safety, and error handling.
"""

import concurrent.futures
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

# Import WorkspaceManager and exceptions
from backend.workspace import (
    WorkspaceManager,
    ProjectNotFoundError,
    FileNotFoundInWorkspaceError,
    InvalidWorkspacePathError,
)


class TestWorkspaceManager(unittest.TestCase):
    def setUp(self) -> None:
        # Create a isolated temporary root directory for test project workspaces
        self.temp_dir = tempfile.mkdtemp(prefix="ekki_re_test_projects_")
        self.manager = WorkspaceManager(projects_dir=Path(self.temp_dir))

    def tearDown(self) -> None:
        # Clean up temporary test directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_and_get_project(self) -> None:
        """Verify project creation, directory structure creation, and metadata retrieval."""
        project = self.manager.create_project(
            name="Malware Analysis Project 1",
            description="Testing workspace creation",
            tags=["malware", "pe32"],
        )

        self.assertTrue(project.project_id.startswith("proj-"))
        self.assertEqual(project.name, "Malware Analysis Project 1")
        self.assertEqual(project.description, "Testing workspace creation")
        self.assertEqual(project.tags, ["malware", "pe32"])

        # Check directory structure on disk
        proj_dir = Path(self.temp_dir) / project.project_id
        self.assertTrue(proj_dir.exists())
        self.assertTrue((proj_dir / "metadata.json").exists())
        for subdir in ["files", "reports", "analysis", "cache", "thumbnails"]:
            self.assertTrue((proj_dir / subdir).exists())

        # Retrieve project using get_project
        fetched = self.manager.get_project(project.project_id)
        self.assertEqual(fetched.project_id, project.project_id)
        self.assertEqual(fetched.name, "Malware Analysis Project 1")

    def test_list_projects(self) -> None:
        """Verify listing multiple projects with correct summary counts."""
        p1 = self.manager.create_project(name="Project 1")
        p2 = self.manager.create_project(name="Project 2")

        summaries = self.manager.list_projects()
        self.assertEqual(len(summaries), 2)
        project_ids = [s.project_id for s in summaries]
        self.assertIn(p1.project_id, project_ids)
        self.assertIn(p2.project_id, project_ids)

    def test_update_and_delete_project(self) -> None:
        """Verify project metadata update and complete folder deletion."""
        project = self.manager.create_project(name="Initial Name")

        # Update project name and status
        updated = self.manager.update_project(
            project.project_id,
            name="Renamed Project",
            status="analyzing",
        )
        self.assertEqual(updated.name, "Renamed Project")
        self.assertEqual(updated.status, "analyzing")

        # Delete project
        result = self.manager.delete_project(project.project_id)
        self.assertTrue(result)

        # Confirm project is removed from disk and raises ProjectNotFoundError
        with self.assertRaises(ProjectNotFoundError):
            self.manager.get_project(project.project_id)

    def test_add_file_with_unique_file_id_and_sha256(self) -> None:
        """Verify file upload generates immutable unique File ID, accurate SHA-256, and engine dirs."""
        project = self.manager.create_project(name="File Test Project")
        content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        expected_sha256 = hashlib.sha256(content).hexdigest()

        file_meta = self.manager.add_file(
            project_id=project.project_id,
            filename="sample.exe",
            content=content,
            mime_type="application/x-msdownload",
            tags=["binary"],
        )

        self.assertTrue(file_meta.file_id.startswith("file-"))
        self.assertEqual(file_meta.filename, "sample.exe")
        self.assertEqual(file_meta.sha256, expected_sha256)
        self.assertEqual(file_meta.size_bytes, len(content))

        # Check that file path on disk matches /files/{file_id}/sample.exe
        file_path = self.manager.get_file_path(project.project_id, file_meta.file_id)
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.read_bytes(), content)

        # Check that analysis subdirectories for this File ID exist
        proj_dir = Path(self.temp_dir) / project.project_id
        for subdir in ["analysis", "reports", "cache", "thumbnails"]:
            engine_dir = proj_dir / subdir / file_meta.file_id
            self.assertTrue(engine_dir.exists())

    def test_file_rename_and_delete(self) -> None:
        """Verify display filename renaming preserves File ID, and file deletion cleans up disk."""
        project = self.manager.create_project(name="Rename Test Project")
        file_meta = self.manager.add_file(
            project_id=project.project_id,
            filename="old_name.bin",
            content=b"test bytes",
        )

        # Rename file display name
        renamed_meta = self.manager.rename_file(
            project_id=project.project_id,
            file_id=file_meta.file_id,
            new_filename="new_display_name.exe",
        )
        self.assertEqual(renamed_meta.filename, "new_display_name.exe")
        self.assertEqual(renamed_meta.file_id, file_meta.file_id)

        # Delete file by File ID
        deleted = self.manager.delete_file(project.project_id, file_meta.file_id)
        self.assertTrue(deleted)

        with self.assertRaises(FileNotFoundInWorkspaceError):
            self.manager.get_file_path(project.project_id, file_meta.file_id)

    def test_path_traversal_security_prevention(self) -> None:
        """Verify that directory traversal attempts are detected and blocked."""
        project = self.manager.create_project(name="Security Test")

        # Invalid project ID attempt
        with self.assertRaises(InvalidWorkspacePathError):
            self.manager.get_project("../../etc/passwd")

        with self.assertRaises(InvalidWorkspacePathError):
            self.manager.get_file_path(project.project_id, "../../../secret")

    def test_thread_safety_concurrent_uploads(self) -> None:
        """Verify thread safety during concurrent file uploads to the same project."""
        project = self.manager.create_project(name="Concurrency Test Project")

        def upload_worker(idx: int) -> str:
            content = f"Concurrent content payload {idx}".encode("utf-8")
            meta = self.manager.add_file(
                project_id=project.project_id,
                filename=f"file_{idx}.txt",
                content=content,
            )
            return meta.file_id

        # Launch 10 concurrent threads uploading files
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(upload_worker, i) for i in range(10)]
            file_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(file_ids), 10)
        self.assertEqual(len(set(file_ids)), 10)  # All File IDs must be unique

        # Reload metadata and verify all 10 files are present
        reloaded = self.manager.get_project(project.project_id)
        self.assertEqual(len(reloaded.files), 10)


if __name__ == "__main__":
    unittest.main()

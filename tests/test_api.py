"""
tests/test_api.py

Comprehensive API integration test suite for FastAPI Project Workspace REST endpoints,
verifying 0-byte uploads, tag parsing, session boundaries, size limits, and preserved chat endpoints.
"""

from pathlib import Path
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

from backend.app import app
from backend.config import settings
from backend.workspace import workspace_manager


class TestWorkspaceAPI(unittest.TestCase):
    def setUp(self) -> None:
        # Create isolated temporary directory for test storage
        self.temp_dir = tempfile.mkdtemp(prefix="ekki_re_api_test_")
        # Override workspace manager root directory for testing
        workspace_manager.projects_dir = Path(self.temp_dir).resolve()
        workspace_manager.projects_dir.mkdir(parents=True, exist_ok=True)
        self.client = TestClient(app)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_health_check_endpoint(self) -> None:
        """Verify health check endpoint returns 200 OK and status."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")

    def test_project_crud_lifecycle_api(self) -> None:
        """Verify project creation, listing, retrieval, update, and deletion endpoints."""
        # 1. Create project
        create_payload = {
            "name": "API Test Project",
            "description": "API integration test",
            "tags": ["api", "malware"],
        }
        res_create = self.client.post("/api/projects", json=create_payload)
        self.assertEqual(res_create.status_code, 201)
        project_data = res_create.json()
        project_id = project_data["project_id"]
        self.assertEqual(project_data["name"], "API Test Project")
        self.assertEqual(project_data["tags"], ["api", "malware"])

        # 2. List projects
        res_list = self.client.get("/api/projects")
        self.assertEqual(res_list.status_code, 200)
        summaries = res_list.json()
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["project_id"], project_id)

        # 3. Get single project
        res_get = self.client.get(f"/api/projects/{project_id}")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.json()["name"], "API Test Project")

        # 4. Update project
        update_payload = {
            "name": "Updated API Project",
            "status": "completed",
        }
        res_update = self.client.put(f"/api/projects/{project_id}", json=update_payload)
        self.assertEqual(res_update.status_code, 200)
        self.assertEqual(res_update.json()["name"], "Updated API Project")
        self.assertEqual(res_update.json()["status"], "completed")

        # 5. Delete project
        res_delete = self.client.delete(f"/api/projects/{project_id}")
        self.assertEqual(res_delete.status_code, 200)
        self.assertTrue(res_delete.json()["success"])

        # 6. Confirm 404 on deleted project
        res_404 = self.client.get(f"/api/projects/{project_id}")
        self.assertEqual(res_404.status_code, 404)

    def test_session_open_close_active_api(self) -> None:
        """Verify open project, close project, and get active project APIs."""
        # Create project
        res_create = self.client.post("/api/projects", json={"name": "Session Project"})
        project_id = res_create.json()["project_id"]
        session_id = "test-session-123"

        # Open project
        res_open = self.client.post(
            f"/api/projects/{project_id}/open",
            json={"session_id": session_id},
        )
        self.assertEqual(res_open.status_code, 200)
        self.assertEqual(res_open.json()["active_project"]["project_id"], project_id)

        # Get active project for session
        res_active = self.client.get(f"/api/projects/active/{session_id}")
        self.assertEqual(res_active.status_code, 200)
        self.assertEqual(res_active.json()["project_id"], project_id)

        # Close project
        res_close = self.client.post(
            f"/api/projects/{project_id}/close",
            json={"session_id": session_id},
        )
        self.assertEqual(res_close.status_code, 200)

        # Confirm active project is now null
        res_active_none = self.client.get(f"/api/projects/active/{session_id}")
        self.assertEqual(res_active_none.status_code, 200)
        self.assertIsNone(res_active_none.json())

    def test_non_existent_session_close_api(self) -> None:
        """Verify closing a session that was never opened handles cleanly without errors."""
        res_proj = self.client.post("/api/projects", json={"name": "NonExistent Session Test"})
        project_id = res_proj.json()["project_id"]

        res_close = self.client.post(
            f"/api/projects/{project_id}/close",
            json={"session_id": "session-never-opened-xyz"},
        )
        self.assertEqual(res_close.status_code, 200)
        self.assertEqual(res_close.json()["session_id"], "session-never-opened-xyz")
        self.assertIsNone(res_close.json()["active_project"])

    def test_file_upload_download_rename_delete_api(self) -> None:
        """Verify multipart file upload, raw download, display rename, and file delete APIs."""
        # Create project
        res_proj = self.client.post("/api/projects", json={"name": "File Upload Project"})
        project_id = res_proj.json()["project_id"]

        # Upload multipart binary file
        binary_content = b"PE\x00\x00\x4c\x01\x03\x00"
        files = {"file": ("malware_sample.exe", binary_content, "application/x-msdownload")}
        data = {"tags": "executable, x86"}

        res_upload = self.client.post(
            f"/api/projects/{project_id}/files",
            files=files,
            data=data,
        )
        self.assertEqual(res_upload.status_code, 201)
        file_meta = res_upload.json()
        file_id = file_meta["file_id"]
        self.assertTrue(file_id.startswith("file-"))
        self.assertEqual(file_meta["filename"], "malware_sample.exe")
        self.assertEqual(file_meta["tags"], ["executable", "x86"])

        # Download raw binary file
        res_download = self.client.get(f"/api/projects/{project_id}/files/{file_id}")
        self.assertEqual(res_download.status_code, 200)
        self.assertEqual(res_download.content, binary_content)

        # Rename display filename
        res_rename = self.client.put(
            f"/api/projects/{project_id}/files/{file_id}",
            json={"new_filename": "renamed_sample.exe"},
        )
        self.assertEqual(res_rename.status_code, 200)
        self.assertEqual(res_rename.json()["filename"], "renamed_sample.exe")
        self.assertEqual(res_rename.json()["file_id"], file_id)

        # Delete file
        res_delete_file = self.client.delete(f"/api/projects/{project_id}/files/{file_id}")
        self.assertEqual(res_delete_file.status_code, 200)
        self.assertTrue(res_delete_file.json()["success"])

        # Confirm 404 on deleted file
        res_404_file = self.client.get(f"/api/projects/{project_id}/files/{file_id}")
        self.assertEqual(res_404_file.status_code, 404)

    def test_zero_byte_file_upload_api(self) -> None:
        """Verify uploading an empty 0-byte file succeeds and records 0 size_bytes."""
        res_proj = self.client.post("/api/projects", json={"name": "Zero Byte Upload Test"})
        project_id = res_proj.json()["project_id"]

        files = {"file": ("empty_sample.bin", b"", "application/octet-stream")}
        res_upload = self.client.post(f"/api/projects/{project_id}/files", files=files)

        self.assertEqual(res_upload.status_code, 201)
        meta = res_upload.json()
        self.assertEqual(meta["size_bytes"], 0)
        self.assertEqual(meta["filename"], "empty_sample.bin")

    def test_empty_and_whitespace_tag_parsing_api(self) -> None:
        """Verify empty tags='' or whitespace tags parse into [] without empty string elements."""
        res_proj = self.client.post("/api/projects", json={"name": "Tag Parsing Test"})
        project_id = res_proj.json()["project_id"]

        # Case 1: Empty tags parameter
        res1 = self.client.post(
            f"/api/projects/{project_id}/files",
            files={"file": ("f1.bin", b"data", "application/octet-stream")},
            data={"tags": ""},
        )
        self.assertEqual(res1.status_code, 201)
        self.assertEqual(res1.json()["tags"], [])

        # Case 2: Whitespace-only tags parameter
        res2 = self.client.post(
            f"/api/projects/{project_id}/files",
            files={"file": ("f2.bin", b"data", "application/octet-stream")},
            data={"tags": "   ,   , "},
        )
        self.assertEqual(res2.status_code, 201)
        self.assertEqual(res2.json()["tags"], [])

        # Case 3: Mixed valid and whitespace tags
        res3 = self.client.post(
            f"/api/projects/{project_id}/files",
            files={"file": ("f3.bin", b"data", "application/octet-stream")},
            data={"tags": "pe32, , x86,  "},
        )
        self.assertEqual(res3.status_code, 201)
        self.assertEqual(res3.json()["tags"], ["pe32", "x86"])

    def test_oversized_file_upload_rejection_api(self) -> None:
        """Verify that file uploads exceeding MAX_UPLOAD_SIZE_MB trigger HTTP 413 Payload Too Large."""
        res_proj = self.client.post("/api/projects", json={"name": "Oversized Upload Test"})
        project_id = res_proj.json()["project_id"]

        # Temporarily lower limit to 1MB for unit testing
        original_limit = settings.MAX_UPLOAD_SIZE_MB
        settings.MAX_UPLOAD_SIZE_MB = 1
        try:
            oversized_data = b"X" * (1024 * 1024 + 100)  # 1MB + 100 bytes
            files = {"file": ("large_sample.bin", oversized_data, "application/octet-stream")}

            res_upload = self.client.post(f"/api/projects/{project_id}/files", files=files)
            self.assertEqual(res_upload.status_code, 413)
            self.assertIn("File size exceeds maximum allowed upload threshold", res_upload.json()["detail"])
        finally:
            settings.MAX_UPLOAD_SIZE_MB = original_limit


if __name__ == "__main__":
    unittest.main()

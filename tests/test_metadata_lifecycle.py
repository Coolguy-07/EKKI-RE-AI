"""
tests/test_metadata_lifecycle.py

Comprehensive test suite verifying metadata lifecycle persistence on upload,
GET /metadata artifact reading, and project metadata sync.
"""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from backend.workspace import WorkspaceManager


class TestMetadataLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="ekki_re_test_metadata_")
        self.manager = WorkspaceManager(projects_dir=Path(self.temp_dir))
        self.project = self.manager.create_project(
            name="Metadata Lifecycle Test Project",
            description="Testing metadata persistence lifecycle",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_upload_persists_analysis_artifact_and_summary(self) -> None:
        """Requirement 1: Verify file upload automatically executes AnalysisPipeline and persists artifact."""
        sample_md = b"# Test Walkthrough\n\nThis is a sample markdown payload.\n"
        file_meta = self.manager.add_file(
            project_id=self.project.project_id,
            filename="walkthrough.md",
            content=sample_md,
            mime_type="text/markdown",
        )

        proj_dir = Path(self.temp_dir) / self.project.project_id
        artifact_path = proj_dir / "analysis" / file_meta.file_id / "metadata.json"

        # 1. Confirm analysis/{file_id}/metadata.json exists immediately
        self.assertTrue(artifact_path.exists(), "analysis/{file_id}/metadata.json must exist immediately after upload")

        # 2. Confirm analysis/{file_id}/metadata.json contents are valid
        with open(artifact_path, "r", encoding="utf-8") as f:
            artifact_data = json.load(f)

        self.assertEqual(artifact_data["filename"], "walkthrough.md")
        self.assertEqual(artifact_data["detected_type"], "Markdown Document")
        self.assertIn("md5", artifact_data)
        self.assertIn("sha1", artifact_data)
        self.assertIn("sha256", artifact_data)
        self.assertIn("sha512", artifact_data)
        self.assertIsInstance(artifact_data["entropy"], float)

        # 3. Confirm project metadata index contains populated metadata summary
        updated_proj = self.manager.get_project(self.project.project_id)
        stored_file_meta = updated_proj.files[file_meta.file_id]
        self.assertTrue(stored_file_meta.metadata, "Project metadata files entry must contain populated analysis summary")
        self.assertEqual(stored_file_meta.metadata["detected_type"], "Markdown Document")
        self.assertEqual(stored_file_meta.metadata["md5"], artifact_data["md5"])

    def test_get_metadata_reads_persisted_artifact(self) -> None:
        """Requirement 2 & 3: Verify GET /metadata reads existing metadata.json artifact without re-analysis."""
        sample_bytes = b"MZ\x90\x00\x03\x00\x00\x00"
        file_meta = self.manager.add_file(
            project_id=self.project.project_id,
            filename="test.exe",
            content=sample_bytes,
        )

        # Modify the artifact slightly to prove get_file_analysis_metadata reads from disk
        proj_dir = Path(self.temp_dir) / self.project.project_id
        artifact_path = proj_dir / "analysis" / file_meta.file_id / "metadata.json"
        
        with open(artifact_path, "r", encoding="utf-8") as f:
            artifact_data = json.load(f)

        artifact_data["engine_metadata"]["test_marker"] = "disk_read_confirmed"
        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(artifact_data, f, indent=2)

        # Call get_file_analysis_metadata
        res_meta = self.manager.get_file_analysis_metadata(self.project.project_id, file_meta.file_id)
        self.assertEqual(res_meta.engine_metadata.get("test_marker"), "disk_read_confirmed")

    def test_get_metadata_syncs_empty_cached_metadata(self) -> None:
        """Verify that get_file_analysis_metadata syncs cached project metadata if it was empty."""
        sample_bytes = b"# Hello World\n"
        file_meta = self.manager.add_file(
            project_id=self.project.project_id,
            filename="doc.md",
            content=sample_bytes,
        )

        # Artificially clear file_meta.metadata in project.metadata.json
        proj_meta = self.manager._load_metadata_unlocked(self.project.project_id)
        proj_meta.files[file_meta.file_id].metadata = {}
        self.manager._save_metadata_unlocked(proj_meta)

        # Call get_file_analysis_metadata
        res_meta = self.manager.get_file_analysis_metadata(self.project.project_id, file_meta.file_id)
        self.assertEqual(res_meta.detected_type, "Markdown Document")

        # Verify project.metadata.json was synced
        reloaded_proj = self.manager.get_project(self.project.project_id)
        self.assertTrue(reloaded_proj.files[file_meta.file_id].metadata)
        self.assertEqual(reloaded_proj.files[file_meta.file_id].metadata["detected_type"], "Markdown Document")

    def test_pipeline_execution_for_pe_binary(self) -> None:
        """Verify pipeline execution with PE binary persists metadata.json and pe.json artifacts."""
        from tests.test_pe_parser import build_synthetic_pe
        pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=False)

        file_meta = self.manager.add_file(
            project_id=self.project.project_id,
            filename="sample.exe",
            content=pe_bytes,
        )

        proj_dir = Path(self.temp_dir) / self.project.project_id
        meta_path = proj_dir / "analysis" / file_meta.file_id / "metadata.json"
        pe_path = proj_dir / "analysis" / file_meta.file_id / "pe.json"

        self.assertTrue(meta_path.exists(), "metadata.json must exist on PE upload")
        self.assertTrue(pe_path.exists(), "pe.json must exist on PE upload")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta_data = json.load(f)

        self.assertEqual(meta_data["filename"], "sample.exe")
        self.assertIn("PE (Windows Executable)", meta_data["detected_type"])
        self.assertIn("pe_parser", meta_data["engine_metadata"])
        self.assertIn("binary_intelligence", meta_data["engine_metadata"])


if __name__ == "__main__":
    unittest.main()

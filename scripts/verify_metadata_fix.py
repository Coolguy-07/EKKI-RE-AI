"""
scripts/verify_metadata_fix.py

Automated verification script for metadata lifecycle fix and walkthrough.md verification.
"""

import json
from pathlib import Path
from backend.workspace import WorkspaceManager

def run_verification():
    root_dir = Path(__file__).parent.parent
    projects_dir = root_dir / "projects"
    manager = WorkspaceManager(projects_dir=projects_dir)

    print("=== Step A & B: Upload walkthrough.md and verify artifact creation ===")
    proj = manager.create_project(
        name="Verification Workspace",
        description="Testing walkthrough.md metadata persistence",
    )
    
    walkthrough_path = root_dir / "projects" / "proj-1785826310-7cc797" / "files" / "file-5c3616d2" / "walkthrough.md"
    if not walkthrough_path.exists():
        walkthrough_content = b"# Walkthrough\nSample payload\n"
    else:
        with open(walkthrough_path, "rb") as f:
            walkthrough_content = f.read()

    file_meta = manager.add_file(
        project_id=proj.project_id,
        filename="walkthrough.md",
        content=walkthrough_content,
        mime_type="text/markdown",
    )

    proj_dir = projects_dir / proj.project_id
    artifact_file = proj_dir / "analysis" / file_meta.file_id / "metadata.json"
    
    print(f"Project ID: {proj.project_id}")
    print(f"File ID: {file_meta.file_id}")
    print(f"Artifact Path: {artifact_file}")
    assert artifact_file.exists(), "ERROR: analysis/{file_id}/metadata.json was not created on upload!"
    print("[SUCCESS] analysis/{file_id}/metadata.json exists on disk immediately after upload!")

    with open(artifact_file, "r", encoding="utf-8") as f:
        artifact_json = json.load(f)

    print("\n--- Artifact JSON Contents ---")
    print(json.dumps(artifact_json, indent=2))

    proj_metadata_file = proj_dir / "metadata.json"
    with open(proj_metadata_file, "r", encoding="utf-8") as f:
        proj_json = json.load(f)

    stored_file_metadata = proj_json["files"][file_meta.file_id]["metadata"]
    assert stored_file_metadata, "ERROR: Project metadata contains empty metadata object ({})!"
    print("\n[SUCCESS] projects/{project_id}/metadata.json contains populated metadata object!")

    print("\n=== Step C: Call GET /api/projects/{project_id}/files/{file_id}/metadata ===")
    get_meta = manager.get_file_analysis_metadata(proj.project_id, file_meta.file_id)
    raw_response = get_meta.model_dump()
    print("GET /metadata Raw Model Dump:")
    print(json.dumps(raw_response, indent=2))

    required_fields = ["detected_type", "detected_architecture", "md5", "sha1", "sha256", "sha512", "entropy", "status"]
    for field in required_fields:
        val = raw_response.get(field)
        assert val is not None, f"ERROR: Missing field '{field}' in response!"
        print(f"  - {field}: {val}")

    assert raw_response["detected_type"] == "Markdown Document", f"Expected Markdown Document, got {raw_response['detected_type']}"
    assert raw_response["entropy"] > 0, "Entropy must be greater than 0.0000"
    assert raw_response["md5"] != "---" and len(raw_response["md5"]) == 32
    assert raw_response["sha1"] != "---" and len(raw_response["sha1"]) == 40
    assert raw_response["sha512"] != "---" and len(raw_response["sha512"]) == 128

    print("\n=== Step D & E: Verify existing project proj-1785826310-7cc797 / file-5c3616d2 ===")
    old_proj_id = "proj-1785826310-7cc797"
    old_file_id = "file-5c3616d2"
    old_meta = manager.get_file_analysis_metadata(old_proj_id, old_file_id)
    print(f"Original File {old_file_id} Metadata:")
    print(json.dumps(old_meta.model_dump(), indent=2))

    old_artifact_file = projects_dir / old_proj_id / "analysis" / old_file_id / "metadata.json"
    assert old_artifact_file.exists(), "Artifact for file-5c3616d2 should now exist!"
    print("[SUCCESS] Original project file-5c3616d2 metadata successfully synced and persisted!")

    print("\nALL VERIFICATION CHECKS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_verification()

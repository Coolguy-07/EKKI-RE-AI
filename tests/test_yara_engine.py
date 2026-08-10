"""
tests/test_yara_engine.py

Comprehensive tests for YaraAnalysisEngine.
Verifies graceful degradation, timeout safeguards, metadata merging, and accurate match schema.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.analysis.yara_engine import YaraAnalysisEngine


def test_yara_engine_identity():
    engine = YaraAnalysisEngine()
    assert engine.engine_name == "yara_analysis"
    assert engine.engine_version == "1.0.0"
    
    # Check can_handle
    assert engine.can_handle(b"test") is True
    assert engine.can_handle(b"") is False


@patch("backend.analysis.yara_engine.YARA_AVAILABLE", False)
def test_yara_unavailable_graceful_degradation():
    engine = YaraAnalysisEngine()
    result = engine.analyze("file123", "test.bin", b"hello world")
    
    # Engine should not crash, but return failed status
    assert "yara_analysis" in result
    yara_data = result["yara_analysis"]["parsed_data"]
    assert yara_data["scan_status"] == "failed"
    assert len(yara_data["errors"]) > 0
    assert "yara-python package is not installed." in yara_data["errors"][0]


@patch("backend.analysis.yara_engine.YARA_AVAILABLE", True)
@patch("backend.analysis.yara_engine.yara")
def test_yara_valid_rule_matching(mock_yara):
    # Setup mock compilation and matching
    mock_rules = MagicMock()
    mock_yara.compile.return_value = mock_rules
    
    mock_match = MagicMock()
    mock_match.rule = "Demo_Benign_Rule"
    mock_match.namespace = "demo"
    mock_match.tags = ["test", "benign"]
    mock_match.meta = {"severity": "info"}
    # strings format: (offset, string_identifier, string_data)
    mock_match.strings = [(10, "$s1", b"benign string")]
    
    mock_rules.match.return_value = [mock_match]

    engine = YaraAnalysisEngine()
    result = engine.analyze("file123", "test.bin", b"test benign string here")

    assert "yara_analysis" in result
    yara_data = result["yara_analysis"]["parsed_data"]
    assert yara_data["scan_status"] == "success"
    assert yara_data["match_count"] == 1
    assert yara_data["rules_loaded"] > 0
    
    match = yara_data["matches"][0]
    assert match["rule"] == "Demo_Benign_Rule"
    assert match["namespace"] == "demo"
    assert "benign" in match["tags"]
    assert match["meta"]["severity"] == "info"
    assert match["strings"][0]["identifier"] == "$s1"
    assert match["strings"][0]["instances"][0]["offset"] == 10
    assert match["strings"][0]["instances"][0]["matched_data"] == b"benign string".hex()


@patch("backend.analysis.yara_engine.YARA_AVAILABLE", True)
@patch("backend.analysis.yara_engine.yara")
def test_yara_no_matches(mock_yara):
    mock_rules = MagicMock()
    mock_yara.compile.return_value = mock_rules
    mock_rules.match.return_value = []

    engine = YaraAnalysisEngine()
    result = engine.analyze("file123", "test.bin", b"clean data")

    yara_data = result["yara_analysis"]["parsed_data"]
    assert yara_data["scan_status"] == "success"
    assert yara_data["match_count"] == 0
    assert len(yara_data["matches"]) == 0


@patch("backend.analysis.yara_engine.YARA_AVAILABLE", True)
@patch("backend.analysis.yara_engine.yara")
def test_yara_timeout_safeguard(mock_yara):
    mock_rules = MagicMock()
    mock_yara.compile.return_value = mock_rules
    # Simulate a timeout exception
    mock_rules.match.side_effect = Exception("Timeout exceeded")

    engine = YaraAnalysisEngine()
    result = engine.analyze("file123", "test.bin", b"complex data")

    yara_data = result["yara_analysis"]["parsed_data"]
    assert yara_data["scan_status"] == "failed"
    assert len(yara_data["errors"]) > 0
    assert "Timeout exceeded" in yara_data["errors"][0]


def test_yara_artifact_persistence(tmp_path):
    engine = YaraAnalysisEngine()
    yara_data = {"test": "data"}
    
    artifact_path = engine.save_yara_artifact(tmp_path, "file123", yara_data)
    
    assert artifact_path.exists()
    assert artifact_path.name == "yara.json"
    with open(artifact_path, "r") as f:
        loaded = json.load(f)
    assert loaded == yara_data

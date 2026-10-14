"""
Unit tests for dependency parser.
"""

import pytest
import json
from pathlib import Path
from scanner.dependency_parser import DependencyParser, Dependency


def test_parse_lockfile_v1():
    """Test parsing lockfileVersion 1."""
    parser = DependencyParser()
    lockfile_path = Path("tests/fixtures/project/backend/package-lock.json")
    
    deps = parser.parse_lockfile(lockfile_path)
    
    assert len(deps) > 0
    
    # Check that we have the expected dependencies
    dep_names = [dep.name for dep in deps]
    assert "express" in dep_names
    assert "lodash" in dep_names
    
    # Check version extraction
    express_dep = next(d for d in deps if d.name == "express")
    assert express_dep.version == "4.18.2"
    
    # Check source file is recorded
    for dep in deps:
        assert dep.source_file == str(lockfile_path)


def test_parse_lockfile_v2():
    """Test parsing lockfileVersion 2."""
    parser = DependencyParser()
    lockfile_path = Path("tests/fixtures/project/frontend/package-lock.json")
    
    deps = parser.parse_lockfile(lockfile_path)
    
    assert len(deps) > 0
    
    # Check that we have the expected dependencies
    dep_names = [dep.name for dep in deps]
    assert "react" in dep_names
    assert "lodash" in dep_names
    
    react_dep = next(d for d in deps if d.name == "react")
    assert react_dep.version == "18.2.0"


def test_parse_lockfile_v3():
    """Test parsing lockfileVersion 3."""
    parser = DependencyParser()
    lockfile_path = Path("tests/fixtures/project/client/package-lock.json")
    
    deps = parser.parse_lockfile(lockfile_path)
    
    assert len(deps) > 0
    
    # Check that we have the expected dependencies
    dep_names = [dep.name for dep in deps]
    assert "axios" in dep_names
    assert "lodash" in dep_names
    
    axios_dep = next(d for d in deps if d.name == "axios")
    assert axios_dep.version == "1.4.0"


def test_parse_malformed_json(tmp_path):
    """Test parsing malformed JSON file."""
    parser = DependencyParser()
    malformed_file = tmp_path / "package-lock.json"
    
    # Write invalid JSON
    malformed_file.write_text("{ invalid json }")
    
    deps = parser.parse_lockfile(malformed_file)
    
    # Should return empty list, not crash
    assert len(deps) == 0


def test_parse_nonexistent_file():
    """Test parsing nonexistent file."""
    parser = DependencyParser()
    nonexistent = Path("tests/fixtures/nonexistent/package-lock.json")
    
    deps = parser.parse_lockfile(nonexistent)
    
    # Should return empty list, not crash
    assert len(deps) == 0


def test_dependency_dataclass():
    """Test Dependency dataclass structure."""
    dep = Dependency(
        name="test-package",
        version="1.0.0",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    assert dep.name == "test-package"
    assert dep.version == "1.0.0"
    assert dep.is_direct is True
    assert dep.source_file == "/path/to/package-lock.json"
    
    # Test to_dict method
    dep_dict = dep.to_dict()
    assert dep_dict["name"] == "test-package"
    assert dep_dict["version"] == "1.0.0"
    assert dep_dict["is_direct"] is True

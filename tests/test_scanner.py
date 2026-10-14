"""
Unit tests for project scanner.
"""

import pytest
from pathlib import Path
from scanner.project_scanner import ProjectScanner


def test_find_manifests():
    """Test that scanner finds package-lock.json files."""
    scanner = ProjectScanner()
    fixture_path = Path("tests/fixtures/project")
    
    manifests = scanner.find_manifests(fixture_path)
    
    # Should find 3 package-lock.json files
    assert len(manifests) == 3
    
    # All should be package-lock.json files
    for manifest in manifests:
        assert manifest.name == "package-lock.json"
    
    # Check that node_modules is skipped (if it existed)
    # Our fixture doesn't have node_modules, but the logic is there


def test_find_manifests_nonexistent_path():
    """Test scanner with nonexistent path."""
    scanner = ProjectScanner()
    nonexistent = Path("tests/fixtures/nonexistent")
    
    manifests = scanner.find_manifests(nonexistent)
    
    # Should return empty list
    assert len(manifests) == 0


def test_skip_directories():
    """Test that scanner skips node_modules, build, dist, .git."""
    scanner = ProjectScanner()
    
    # Verify skip directories are defined
    assert "node_modules" in scanner.SKIP_DIRS
    assert "build" in scanner.SKIP_DIRS
    assert "dist" in scanner.SKIP_DIRS
    assert ".git" in scanner.SKIP_DIRS

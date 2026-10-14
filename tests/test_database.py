"""
Unit tests for database operations.
"""

import pytest
import os
import tempfile
from database.db import Database
from vulnerability.version_matcher import Finding, FindingStatus, Advisory


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_path = f.name
    
    # Override DB path
    original_path = os.environ.get("DB_PATH")
    os.environ["DB_PATH"] = db_path
    
    db = Database()
    
    yield db
    
    # Cleanup
    db.close()
    os.unlink(db_path)
    if original_path:
        os.environ["DB_PATH"] = original_path
    else:
        os.environ.pop("DB_PATH", None)


def test_create_scan(temp_db):
    """Test creating a scan record."""
    scan_id = temp_db.create_scan("/test/path")
    
    assert scan_id is not None
    assert len(scan_id) > 0
    
    # Verify scan was created
    summary = temp_db.get_scan_summary(scan_id)
    assert summary is not None
    assert summary["project_path"] == "/test/path"
    assert summary["status"] == "in_progress"


def test_complete_scan(temp_db):
    """Test marking a scan as completed."""
    scan_id = temp_db.create_scan("/test/path")
    
    temp_db.complete_scan(scan_id)
    
    summary = temp_db.get_scan_summary(scan_id)
    assert summary["status"] == "completed"
    assert summary["completed_at"] is not None


def test_record_finding(temp_db):
    """Test recording a vulnerability finding."""
    scan_id = temp_db.create_scan("/test/path")
    
    finding = Finding(
        dependency_name="lodash",
        dependency_version="4.17.15",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.CONFIRMED_AFFECTED,
        advisories=[
            Advisory(
                id="CVE-2021-23337",
                aliases=["GHSA-9jh3-xjcc-xh2h"],
                summary="Prototype Pollution",
                details="Details",
                severity="HIGH",
                affected_versions=["4.17.15"]
            )
        ]
    )
    
    temp_db.record_finding(scan_id, finding)
    
    # Verify finding was recorded
    findings = temp_db.get_findings(scan_id)
    assert len(findings) == 1
    assert findings[0]["dependency_name"] == "lodash"
    assert findings[0]["status"] == FindingStatus.CONFIRMED_AFFECTED.value
    
    # Verify scan counters were updated
    summary = temp_db.get_scan_summary(scan_id)
    assert summary["confirmed_findings"] == 1
    assert summary["total_dependencies"] == 1


def test_record_finding_ambiguous(temp_db):
    """Test recording an ambiguous finding."""
    scan_id = temp_db.create_scan("/test/path")
    
    finding = Finding(
        dependency_name="test",
        dependency_version="1.0.0",
        is_direct=False,
        source_file="/path/package-lock.json",
        status=FindingStatus.POTENTIAL_OR_AMBIGUOUS,
        advisories=[]
    )
    
    temp_db.record_finding(scan_id, finding)
    
    summary = temp_db.get_scan_summary(scan_id)
    assert summary["ambiguous_findings"] == 1


def test_record_finding_failed(temp_db):
    """Test recording a failed lookup."""
    scan_id = temp_db.create_scan("/test/path")
    
    finding = Finding(
        dependency_name="test",
        dependency_version="1.0.0",
        is_direct=False,
        source_file="/path/package-lock.json",
        status=FindingStatus.LOOKUP_FAILED,
        advisories=[],
        error_message="Network timeout"
    )
    
    temp_db.record_finding(scan_id, finding)
    
    summary = temp_db.get_scan_summary(scan_id)
    assert summary["failed_lookups"] == 1


def test_log_audit_event(temp_db):
    """Test logging audit events."""
    scan_id = temp_db.create_scan("/test/path")
    
    temp_db.log_audit_event(scan_id, "test_event", {"key": "value"})
    
    # Verify event was logged (we can't directly query audit_logs, but we can check no error)
    # In a real test, we'd add a get_audit_events method


def test_log_error(temp_db):
    """Test logging errors."""
    scan_id = temp_db.create_scan("/test/path")
    
    temp_db.log_error(scan_id, "Test error message", "test context")
    
    # Verify error was logged (we can't directly query error_logs, but we can check no error)
    # In a real test, we'd add a get_errors method


def test_sanitize_error_message(temp_db):
    """Test error message sanitization."""
    # Test with potential secret
    message = "Bearer abc123xyz token=secret123"
    sanitized = temp_db._sanitize_error_message(message)
    
    assert "abc123xyz" not in sanitized
    assert "secret123" not in sanitized
    assert "[REDACTED]" in sanitized


def test_get_findings_by_status(temp_db):
    """Test getting findings filtered by status."""
    scan_id = temp_db.create_scan("/test/path")
    
    # Add findings with different statuses
    finding1 = Finding(
        dependency_name="test1",
        dependency_version="1.0.0",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.CONFIRMED_AFFECTED,
        advisories=[]
    )
    
    finding2 = Finding(
        dependency_name="test2",
        dependency_version="2.0.0",
        is_direct=False,
        source_file="/path/package-lock.json",
        status=FindingStatus.NO_MATCH_RETURNED,
        advisories=[]
    )
    
    temp_db.record_finding(scan_id, finding1)
    temp_db.record_finding(scan_id, finding2)
    
    # Get only confirmed findings
    confirmed = temp_db.get_findings_by_status(scan_id, FindingStatus.CONFIRMED_AFFECTED)
    assert len(confirmed) == 1
    assert confirmed[0]["dependency_name"] == "test1"

"""
Unit tests for report generator.
"""

import pytest
import os
import tempfile
from database.db import Database
from reports.report_generator import ReportGenerator
from vulnerability.version_matcher import Finding, FindingStatus, Advisory


@pytest.fixture
def temp_report_dir():
    """Create a temporary report directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_dir = os.environ.get("REPORT_OUTPUT_DIR")
        os.environ["REPORT_OUTPUT_DIR"] = tmpdir
        
        yield tmpdir
        
        if original_dir:
            os.environ["REPORT_OUTPUT_DIR"] = original_dir
        else:
            os.environ.pop("REPORT_OUTPUT_DIR", None)


@pytest.fixture
def temp_db_with_scan():
    """Create a temporary database with a scan."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_path = f.name
    
    original_path = os.environ.get("DB_PATH")
    os.environ["DB_PATH"] = db_path
    
    db = Database()
    scan_id = db.create_scan("/test/path")
    
    # Add some findings
    finding1 = Finding(
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
    
    finding2 = Finding(
        dependency_name="express",
        dependency_version="4.18.2",
        is_direct=False,
        source_file="/path/package-lock.json",
        status=FindingStatus.NO_MATCH_RETURNED,
        advisories=[]
    )
    
    db.record_finding(scan_id, finding1)
    db.record_finding(scan_id, finding2)
    db.complete_scan(scan_id)
    
    yield db, scan_id
    
    db.close()
    os.unlink(db_path)
    if original_path:
        os.environ["DB_PATH"] = original_path
    else:
        os.environ.pop("DB_PATH", None)


def test_generate_report(temp_report_dir, temp_db_with_scan):
    """Test generating an HTML report."""
    db, scan_id = temp_db_with_scan
    
    generator = ReportGenerator()
    report_path = generator.generate(scan_id, db)
    
    assert os.path.exists(report_path)
    assert report_path.endswith(".html")
    
    # Read and verify HTML content
    with open(report_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    assert "Vulnerability Scan Report" in html
    assert scan_id in html
    assert "lodash" in html
    assert "CVE-2021-23337" in html


def test_report_status_vulnerabilities_found(temp_report_dir, temp_db_with_scan):
    """Test report status when vulnerabilities are found."""
    db, scan_id = temp_db_with_scan
    
    generator = ReportGenerator()
    report_path = generator.generate(scan_id, db)
    
    with open(report_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    assert "VULNERABILITIES_FOUND" in html


def test_report_status_partial_scan(temp_report_dir):
    """Test report status when scan has failures."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_path = f.name
    
    original_path = os.environ.get("DB_PATH")
    os.environ["DB_PATH"] = db_path
    
    db = Database()
    scan_id = db.create_scan("/test/path")
    
    # Add a failed lookup
    finding = Finding(
        dependency_name="test",
        dependency_version="1.0.0",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.LOOKUP_FAILED,
        advisories=[],
        error_message="Network timeout"
    )
    
    db.record_finding(scan_id, finding)
    db.complete_scan(scan_id)
    
    generator = ReportGenerator()
    report_path = generator.generate(scan_id, db)
    
    with open(report_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    assert "PARTIAL_SCAN" in html
    
    db.close()
    os.unlink(db_path)
    if original_path:
        os.environ["DB_PATH"] = original_path
    else:
        os.environ.pop("DB_PATH", None)

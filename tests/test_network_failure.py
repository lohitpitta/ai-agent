"""
Integration test for network failure handling.
"""

import pytest
import os
import tempfile
from unittest.mock import patch
from database.db import Database
from scanner.project_scanner import ProjectScanner
from scanner.dependency_parser import DependencyParser
from vulnerability.osv_client import OSVClient
from vulnerability.version_matcher import VersionMatcher
from reports.report_generator import ReportGenerator


def test_network_failure_produces_partial_scan():
    """Test that network failure produces LOOKUP_FAILED entries and partial scan status."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_path = f.name
    
    original_db_path = os.environ.get("DB_PATH")
    os.environ["DB_PATH"] = db_path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        original_report_dir = os.environ.get("REPORT_OUTPUT_DIR")
        os.environ["REPORT_OUTPUT_DIR"] = tmpdir
        
        try:
            db = Database()
            scanner = ProjectScanner()
            parser = DependencyParser()
            
            # Mock OSV client to simulate network failure
            with patch('vulnerability.osv_client.requests.post') as mock_post:
                import requests
                mock_post.side_effect = requests.exceptions.ConnectionError("Network unreachable")
                
                osv_client = OSVClient()
                version_matcher = VersionMatcher()
                report_generator = ReportGenerator()
                
                # Scan the fixture project
                fixture_path = "tests/fixtures/project"
                scan_id = db.create_scan(fixture_path)
                
                manifests = scanner.find_manifests(fixture_path)
                all_dependencies = []
                
                for manifest_path in manifests:
                    deps = parser.parse_lockfile(manifest_path)
                    all_dependencies.extend(deps)
                
                # Query OSV (will fail due to mock)
                vulnerabilities = osv_client.query_batch(all_dependencies)
                
                # Match versions and classify
                for dep, vuln_data in zip(all_dependencies, vulnerabilities):
                    result = version_matcher.classify_vulnerability(dep, vuln_data)
                    db.record_finding(scan_id, result)
                
                # Complete scan
                db.complete_scan(scan_id)
                
                # Generate report
                report_path = report_generator.generate(scan_id, db)
                
                # Verify results
                summary = db.get_scan_summary(scan_id)
                
                # All dependencies should have failed lookups
                assert summary['failed_lookups'] > 0
                assert summary['failed_lookups'] == summary['total_dependencies']
                
                # No confirmed or ambiguous findings (since lookups failed)
                assert summary['confirmed_findings'] == 0
                assert summary['ambiguous_findings'] == 0
                
                # Verify report exists
                assert os.path.exists(report_path)
                
                # Verify report shows partial scan status
                with open(report_path, 'r', encoding='utf-8') as f:
                    html = f.read()
                
                assert "PARTIAL_SCAN" in html
                # Error message should be visible in the failed dependencies section
                assert "Error:" in html
                
                # Verify it does NOT show as "clean" or "no vulnerabilities"
                assert "NO_VULNERABILITIES_FOUND" not in html
                
        finally:
            db.close()
            os.unlink(db_path)
            if original_db_path:
                os.environ["DB_PATH"] = original_db_path
            else:
                os.environ.pop("DB_PATH", None)
            
            if original_report_dir:
                os.environ["REPORT_OUTPUT_DIR"] = original_report_dir
            else:
                os.environ.pop("REPORT_OUTPUT_DIR", None)

"""
Unit tests for version matcher.
"""

import pytest
from vulnerability.version_matcher import VersionMatcher, FindingStatus, Advisory, Finding
from vulnerability.osv_client import VulnerabilityResult
from scanner.dependency_parser import Dependency


def test_classify_confirmed_affected():
    """Test classification when version is definitely affected."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="lodash",
        version="4.17.15",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with matching version
    vuln_result = VulnerabilityResult(
        dependency=dep,
        data={
            "vulns": [
                {
                    "id": "CVE-2021-23337",
                    "aliases": ["GHSA-9jh3-xjcc-xh2h"],
                    "summary": "Prototype Pollution in lodash",
                    "details": "Lodash is vulnerable to prototype pollution.",
                    "severity": [{"score": "HIGH"}],
                    "affected": [
                        {
                            "versions": ["4.17.15", "4.17.16", "4.17.17"]
                        }
                    ]
                }
            ]
        }
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    assert finding.status == FindingStatus.CONFIRMED_AFFECTED
    assert finding.dependency_name == "lodash"
    assert len(finding.advisories) == 1
    assert finding.advisories[0].id == "CVE-2021-23337"


def test_classify_no_match():
    """Test classification when version is not affected."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="lodash",
        version="4.17.21",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with non-matching version
    vuln_result = VulnerabilityResult(
        dependency=dep,
        data={
            "vulns": [
                {
                    "id": "CVE-2021-23337",
                    "aliases": ["GHSA-9jh3-xjcc-xh2h"],
                    "summary": "Prototype Pollution in lodash",
                    "details": "Lodash is vulnerable to prototype pollution.",
                    "severity": [{"score": "HIGH"}],
                    "affected": [
                        {
                            "versions": ["4.17.15", "4.17.16"]
                        }
                    ]
                }
            ]
        }
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    assert finding.status == FindingStatus.NO_MATCH_RETURNED
    assert len(finding.advisories) == 0


def test_classify_lookup_failed():
    """Test classification when OSV lookup fails."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="test-package",
        version="1.0.0",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with error
    vuln_result = VulnerabilityResult(
        dependency=dep,
        error="Network timeout",
        timed_out=True
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    assert finding.status == FindingStatus.LOOKUP_FAILED
    assert finding.error_message == "Network timeout"
    assert len(finding.advisories) == 0


def test_classify_no_data():
    """Test classification when OSV returns no data."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="test-package",
        version="1.0.0",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with no data
    vuln_result = VulnerabilityResult(
        dependency=dep,
        data=None
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    assert finding.status == FindingStatus.NO_MATCH_RETURNED
    assert len(finding.advisories) == 0


def test_deduplication():
    """Test that advisories are deduplicated by ID."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="lodash",
        version="4.17.15",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with duplicate advisories (same ID, different aliases)
    vuln_result = VulnerabilityResult(
        dependency=dep,
        data={
            "vulns": [
                {
                    "id": "CVE-2021-23337",
                    "aliases": ["GHSA-9jh3-xjcc-xh2h"],
                    "summary": "Prototype Pollution in lodash",
                    "details": "Lodash is vulnerable to prototype pollution.",
                    "severity": [{"score": "HIGH"}],
                    "affected": [{"versions": ["4.17.15"]}]
                },
                {
                    "id": "GHSA-9jh3-xjcc-xh2h",
                    "aliases": ["CVE-2021-23337"],
                    "summary": "Prototype Pollution in lodash",
                    "details": "Lodash is vulnerable to prototype pollution.",
                    "severity": [{"score": "HIGH"}],
                    "affected": [{"versions": ["4.17.15"]}]
                }
            ]
        }
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    # Should only have one advisory (deduplicated)
    assert len(finding.advisories) == 1


def test_prerelease_version():
    """Test handling of prerelease versions."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="test-package",
        version="1.0.0-alpha.1",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with exact version match
    vuln_result = VulnerabilityResult(
        dependency=dep,
        data={
            "vulns": [
                {
                    "id": "CVE-2023-1234",
                    "aliases": [],
                    "summary": "Test vulnerability",
                    "details": "Test",
                    "severity": [{"score": "MEDIUM"}],
                    "affected": [{"versions": ["1.0.0-alpha.1"]}]
                }
            ]
        }
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    # Should match exactly
    assert finding.status == FindingStatus.CONFIRMED_AFFECTED


def test_invalid_semver():
    """Test handling of invalid semver versions."""
    matcher = VersionMatcher()
    
    dep = Dependency(
        name="test-package",
        version="invalid-version-string",
        is_direct=True,
        source_file="/path/to/package-lock.json"
    )
    
    # Mock OSV result with some versions
    vuln_result = VulnerabilityResult(
        dependency=dep,
        data={
            "vulns": [
                {
                    "id": "CVE-2023-1234",
                    "aliases": [],
                    "summary": "Test vulnerability",
                    "details": "Test",
                    "severity": [{"score": "MEDIUM"}],
                    "affected": [{"versions": ["1.0.0"]}]
                }
            ]
        }
    )
    
    finding = matcher.classify_vulnerability(dep, vuln_result)
    
    # Should be marked as ambiguous since we can't parse the version
    assert finding.status == FindingStatus.POTENTIAL_OR_AMBIGUOUS

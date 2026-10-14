#!/usr/bin/env python3
"""
Demo script showing three different AI decision paths.
This demonstrates the Tool Selection policy with CONTINUE_TO_REPORT, VERIFY_WITH_ANOTHER_SOURCE, and FLAG_FOR_REVIEW outcomes.
"""

from unittest.mock import Mock, patch
from vulnerability.version_matcher import Finding, FindingStatus, Advisory
from ai.decision_orchestrator import DecisionOrchestrator, DecisionResult
from ai.decider_client import DecisionOutcome


def demo_continue_to_report():
    """Demo: Finding is clear and should be included in the report as-is."""
    print("\n" + "="*60)
    print("DEMO 1: CONTINUE_TO_REPORT")
    print("="*60)
    
    # Mock Decider to return CONTINUE_TO_REPORT
    with patch('ai.decider_client.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "answers": {
                "decision": {
                    "type": "choice",
                    "choice": "CONTINUE_TO_REPORT",
                    "confidence": 0.95
                }
            }
        }
        mock_post.return_value = mock_response
        
        orchestrator = DecisionOrchestrator()
        
        # Create a clear vulnerability finding
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
                    summary="Prototype Pollution in lodash",
                    details="Lodash versions before 4.17.21 are vulnerable to prototype pollution via functions that modify the prototype.",
                    severity="HIGH",
                    affected_versions=["4.17.15", "4.17.16", "4.17.17"]
                )
            ]
        )
        
        print(f"\nDependency: {finding.dependency_name}@{finding.dependency_version}")
        print(f"Status: {finding.status.value}")
        print(f"Advisories: {len(finding.advisories)}")
        print(f"  - {finding.advisories[0].id}: {finding.advisories[0].summary}")
        print(f"  - Severity: {finding.advisories[0].severity}")
        
        result = orchestrator.process_finding(finding)
        
        print(f"\nAI Decision: {result.outcome.value}")
        print(f"Decider Used: {result.decider_used}")
        print(f"Verification Evidence: {result.verification_evidence}")
        print(f"Explanation: {result.explanation}")
        
        print("\nAction: Finding included in report without additional verification")
        print("Reason: Vulnerability is clear and well-documented")


def demo_verify_with_another_source():
    """Demo: Finding needs verification from another source before reporting."""
    print("\n" + "="*60)
    print("DEMO 2: VERIFY_WITH_ANOTHER_SOURCE")
    print("="*60)
    
    # Mock Decider to return VERIFY_WITH_ANOTHER_SOURCE
    with patch('ai.decider_client.requests.post') as mock_post, \
         patch('ai.github_advisory_client.requests.get') as mock_get:
        
        # Mock Decider response
        mock_decider_response = Mock()
        mock_decider_response.status_code = 200
        mock_decider_response.json.return_value = {
            "answers": {
                "decision": {
                    "type": "choice",
                    "choice": "VERIFY_WITH_ANOTHER_SOURCE",
                    "confidence": 0.85
                }
            }
        }
        mock_post.return_value = mock_decider_response
        
        # Mock GitHub response
        mock_github_response = Mock()
        mock_github_response.status_code = 200
        mock_github_response.json.return_value = {
            "ghsa_id": "GHSA-xxxx",
            "cve_id": "CVE-2021-1234",
            "summary": "Prototype Pollution in lodash",
            "description": "Lodash is vulnerable to prototype pollution.",
            "severity": "HIGH",
            "published_at": "2021-01-01",
            "updated_at": "2021-01-02",
            "cvss": {"score": 7.5},
            "cwes": [{"cwe_id": "CWE-79"}],
            "vulnerabilities": [],
            "references": []
        }
        mock_get.return_value = mock_github_response
        
        orchestrator = DecisionOrchestrator()
        
        # Create a finding that needs verification
        finding = Finding(
            dependency_name="express",
            dependency_version="4.17.0",
            is_direct=True,
            source_file="/path/package-lock.json",
            status=FindingStatus.POTENTIAL_OR_AMBIGUOUS,
            advisories=[
                Advisory(
                    id="GHSA-xxxx",
                    aliases=["CVE-2021-1234"],
                    summary="Potential prototype pollution",
                    details="May be vulnerable to prototype pollution in certain conditions.",
                    severity="MEDIUM",
                    affected_versions=["4.17.0"]
                )
            ]
        )
        
        print(f"\nDependency: {finding.dependency_name}@{finding.dependency_version}")
        print(f"Status: {finding.status.value}")
        print(f"Advisories: {len(finding.advisories)}")
        print(f"  - {finding.advisories[0].id}: {finding.advisories[0].summary}")
        print(f"  - Severity: {finding.advisories[0].severity}")
        
        result = orchestrator.process_finding(finding)
        
        print(f"\nAI Decision: {result.outcome.value}")
        print(f"Decider Used: {result.decider_used}")
        
        if result.verification_evidence:
            print(f"\nVerification Evidence:")
            print(f"  Source: {result.verification_evidence.get('source')}")
            print(f"  Status: {result.verification_evidence.get('verification_status')}")
            print(f"  Advisories Found: {len(result.verification_evidence.get('advisories_found', []))}")
        
        print(f"\nExplanation: {result.explanation}")
        
        print("\nAction: Queried GitHub Advisory API for verification")
        print("Reason: Finding was ambiguous, needed cross-source confirmation")


def demo_flag_for_review():
    """Demo: Finding is ambiguous or requires manual review."""
    print("\n" + "="*60)
    print("DEMO 3: FLAG_FOR_REVIEW")
    print("="*60)
    
    # Mock Decider to return FLAG_FOR_REVIEW
    with patch('ai.decider_client.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "answers": {
                "decision": {
                    "type": "choice",
                    "choice": "FLAG_FOR_REVIEW",
                    "confidence": 0.75
                }
            }
        }
        mock_post.return_value = mock_response
        
        orchestrator = DecisionOrchestrator()
        
        # Create an ambiguous finding
        finding = Finding(
            dependency_name="unknown-package",
            dependency_version="1.0.0-beta",
            is_direct=False,
            source_file="/path/package-lock.json",
            status=FindingStatus.POTENTIAL_OR_AMBIGUOUS,
            advisories=[
                Advisory(
                    id="CVE-2023-9999",
                    aliases=[],
                    summary="Unverified vulnerability report",
                    details="This vulnerability has not been confirmed by the maintainer.",
                    severity="UNKNOWN",
                    affected_versions=["1.0.0-beta"]
                )
            ]
        )
        
        print(f"\nDependency: {finding.dependency_name}@{finding.dependency_version}")
        print(f"Status: {finding.status.value}")
        print(f"Direct: {finding.is_direct}")
        print(f"Advisories: {len(finding.advisories)}")
        print(f"  - {finding.advisories[0].id}: {finding.advisories[0].summary}")
        print(f"  - Severity: {finding.advisories[0].severity}")
        
        result = orchestrator.process_finding(finding)
        
        print(f"\nAI Decision: {result.outcome.value}")
        print(f"Decider Used: {result.decider_used}")
        print(f"Verification Evidence: {result.verification_evidence}")
        print(f"Explanation: {result.explanation}")
        
        print("\nAction: Flagged for manual security review")
        print("Reason: Finding is ambiguous, unverified, or requires expert analysis")


def demo_bedrock_fallback():
    """Demo: Bedrock fallback when Decider is unavailable."""
    print("\n" + "="*60)
    print("DEMO 4: BEDROCK FALLBACK")
    print("="*60)
    
    # Mock Decider unavailable, Bedrock available
    with patch('ai.decider_client.requests.post') as mock_post, \
         patch('ai.bedrock_client.boto3') as mock_boto3:
        
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError("Decider server not available")
        
        # Mock Bedrock
        mock_client = Mock()
        mock_boto3.client.return_value = mock_client
        mock_response = {
            "output": {
                "message": {
                    "content": [{"text": '{"decision": "CONTINUE_TO_REPORT"}'}]
                }
            }
        }
        mock_client.converse.return_value = mock_response
        
        orchestrator = DecisionOrchestrator()
        
        finding = Finding(
            dependency_name="react",
            dependency_version="16.13.0",
            is_direct=True,
            source_file="/path/package-lock.json",
            status=FindingStatus.CONFIRMED_AFFECTED,
            advisories=[
                Advisory(
                    id="CVE-2021-23337",
                    aliases=["GHSA-xxxx"],
                    summary="Test vulnerability",
                    details="Test details",
                    severity="HIGH",
                    affected_versions=["16.13.0"]
                )
            ]
        )
        
        print(f"\nDependency: {finding.dependency_name}@{finding.dependency_version}")
        print(f"Decider Server: UNAVAILABLE")
        print(f"Bedrock: AVAILABLE")
        
        result = orchestrator.process_finding(finding)
        
        print(f"\nAI Decision: {result.outcome.value}")
        print(f"Decider Used: {result.decider_used}")
        
        print("\nAction: Used Bedrock as fallback for decision-making")
        print("Reason: Decider 2B server was unavailable")


def main():
    """Run all demos."""
    print("\n" + "="*60)
    print("AI TOOL SELECTION DEMO")
    print("Demonstrating three-way decision policy")
    print("="*60)
    
    demo_continue_to_report()
    demo_verify_with_another_source()
    demo_flag_for_review()
    demo_bedrock_fallback()
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nSummary:")
    print("- CONTINUE_TO_REPORT: Clear findings go directly to report")
    print("- VERIFY_WITH_ANOTHER_SOURCE: Ambiguous findings get GitHub API verification")
    print("- FLAG_FOR_REVIEW: Unclear findings require manual review")
    print("- Bedrock fallback: Used when Decider 2B is unavailable")
    print("\nAll decisions are logged to audit_logs for traceability.")


if __name__ == "__main__":
    main()

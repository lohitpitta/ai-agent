"""
Unit tests for AI decision orchestrator and decision outcomes.
"""

import pytest
from unittest.mock import Mock, patch
from ai.decider_client import DeciderClient, DecisionOutcome
from ai.bedrock_client import BedrockClient
from ai.github_advisory_client import GitHubAdvisoryClient
from ai.decision_orchestrator import DecisionOrchestrator, DecisionResult
from vulnerability.version_matcher import Finding, FindingStatus, Advisory


def test_decider_client_initialization():
    """Test Decider client initialization."""
    client = DeciderClient()
    
    assert client.server_url == "http://localhost:8000"
    assert client.endpoint == "http://localhost:8000/v1/systemone"
    assert client.timeout == 30


def test_decider_client_custom_config():
    """Test Decider client with custom configuration."""
    import os
    os.environ["DECIDER_SERVER_URL"] = "http://localhost:9000"
    os.environ["DECIDER_TIMEOUT"] = "60"
    
    client = DeciderClient()
    
    assert client.server_url == "http://localhost:9000"
    assert client.timeout == 60
    
    # Cleanup
    os.environ.pop("DECIDER_SERVER_URL")
    os.environ.pop("DECIDER_TIMEOUT")


@patch('ai.decider_client.requests.post')
def test_decider_make_decision_continue_to_report(mock_post):
    """Test Decider decision for CONTINUE_TO_REPORT."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "CONTINUE_TO_REPORT",
                "confidence": 0.9
            }
        }
    }
    mock_post.return_value = mock_response
    
    client = DeciderClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome == DecisionOutcome.CONTINUE_TO_REPORT


@patch('ai.decider_client.requests.post')
def test_decider_make_decision_verify_with_another_source(mock_post):
    """Test Decider decision for VERIFY_WITH_ANOTHER_SOURCE."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "VERIFY_WITH_ANOTHER_SOURCE",
                "confidence": 0.8
            }
        }
    }
    mock_post.return_value = mock_response
    
    client = DeciderClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome == DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE


@patch('ai.decider_client.requests.post')
def test_decider_make_decision_flag_for_review(mock_post):
    """Test Decider decision for FLAG_FOR_REVIEW."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "FLAG_FOR_REVIEW",
                "confidence": 0.7
            }
        }
    }
    mock_post.return_value = mock_response
    
    client = DeciderClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome == DecisionOutcome.FLAG_FOR_REVIEW


@patch('ai.decider_client.requests.post')
def test_decider_make_decision_failure(mock_post):
    """Test Decider decision when request fails."""
    import requests
    mock_post.side_effect = requests.exceptions.ConnectionError()
    
    client = DeciderClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome is None


def test_decider_requires_three_options():
    """Test that Decider requires exactly 3 options."""
    client = DeciderClient()
    
    with pytest.raises(ValueError):
        client.make_decision("Test state", ["OPTION1", "OPTION2"])


@patch('ai.bedrock_client.boto3')
def test_bedrock_client_initialization(mock_boto3):
    """Test Bedrock client initialization."""
    mock_client = Mock()
    mock_boto3.client.return_value = mock_client
    
    client = BedrockClient()
    
    assert client.region == "us-west-2"
    assert client.model_id == "anthropic.claude-3-5-sonnet-20241022-v2:0"
    assert client.client == mock_client


@patch('ai.bedrock_client.boto3')
def test_bedrock_client_custom_config(mock_boto3):
    """Test Bedrock client with custom configuration."""
    import os
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["BEDROCK_MODEL_ID"] = "anthropic.claude-3-haiku-20240307-v1:0"
    
    mock_client = Mock()
    mock_boto3.client.return_value = mock_client
    
    client = BedrockClient()
    
    assert client.region == "us-east-1"
    assert client.model_id == "anthropic.claude-3-haiku-20240307-v1:0"
    
    # Cleanup
    os.environ.pop("AWS_REGION")
    os.environ.pop("BEDROCK_MODEL_ID")


@patch('ai.bedrock_client.boto3')
def test_bedrock_make_decision_continue_to_report(mock_boto3):
    """Test Bedrock decision for CONTINUE_TO_REPORT."""
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
    
    client = BedrockClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome == DecisionOutcome.CONTINUE_TO_REPORT


@patch('ai.bedrock_client.boto3')
def test_bedrock_make_decision_verify_with_another_source(mock_boto3):
    """Test Bedrock decision for VERIFY_WITH_ANOTHER_SOURCE."""
    mock_client = Mock()
    mock_boto3.client.return_value = mock_client
    
    mock_response = {
        "output": {
            "message": {
                "content": [{"text": '{"decision": "VERIFY_WITH_ANOTHER_SOURCE"}'}]
            }
        }
    }
    mock_client.converse.return_value = mock_response
    
    client = BedrockClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome == DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE


@patch('ai.bedrock_client.boto3')
def test_bedrock_make_decision_flag_for_review(mock_boto3):
    """Test Bedrock decision for FLAG_FOR_REVIEW."""
    mock_client = Mock()
    mock_boto3.client.return_value = mock_client
    
    mock_response = {
        "output": {
            "message": {
                "content": [{"text": '{"decision": "FLAG_FOR_REVIEW"}'}]
            }
        }
    }
    mock_client.converse.return_value = mock_response
    
    client = BedrockClient()
    options = [
        DecisionOutcome.CONTINUE_TO_REPORT.value,
        DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
        DecisionOutcome.FLAG_FOR_REVIEW.value
    ]
    
    outcome = client.make_decision("Test state", options)
    
    assert outcome == DecisionOutcome.FLAG_FOR_REVIEW


@patch('ai.bedrock_client.boto3')
def test_bedrock_generate_explanation(mock_boto3):
    """Test Bedrock explanation generation."""
    mock_client = Mock()
    mock_boto3.client.return_value = mock_client
    
    mock_response = {
        "output": {
            "message": {
                "content": [{"text": '{"explanation": "Test explanation", "remediation": "Test remediation"}'}]
            }
        }
    }
    mock_client.converse.return_value = mock_response
    
    client = BedrockClient()
    
    explanation = client.generate_explanation(
        "lodash",
        "4.17.15",
        [{"id": "CVE-2021-23337", "summary": "Prototype Pollution"}],
        {"source": "github", "status": "confirmed"}
    )
    
    assert explanation is not None
    assert "Test explanation" in explanation
    assert "Test remediation" in explanation


@patch('ai.github_advisory_client.requests.get')
def test_github_query_by_ghsa(mock_get):
    """Test GitHub Advisory query by GHSA ID."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "ghsa_id": "GHSA-xxxx",
        "cve_id": "CVE-2021-1234",
        "summary": "Test advisory",
        "description": "Test description",
        "severity": "HIGH",
        "published_at": "2021-01-01",
        "updated_at": "2021-01-02",
        "cvss": {"score": 7.5},
        "cwes": [{"cwe_id": "CWE-79"}],
        "vulnerabilities": [],
        "references": []
    }
    mock_get.return_value = mock_response
    
    client = GitHubAdvisoryClient()
    
    advisory = client.query_advisory_by_ghsa("GHSA-xxxx")
    
    assert advisory is not None
    assert advisory.ghsa_id == "GHSA-xxxx"
    assert advisory.cve_id == "CVE-2021-1234"
    assert advisory.severity == "HIGH"


@patch('ai.github_advisory_client.requests.get')
def test_github_query_by_package(mock_get):
    """Test GitHub Advisory query by package."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-xxxx",
            "cve_id": "CVE-2021-1234",
            "summary": "Test advisory",
            "description": "Test description",
            "severity": "HIGH",
            "published_at": "2021-01-01",
            "updated_at": "2021-01-02",
            "cvss": {"score": 7.5},
            "cwes": [{"cwe_id": "CWE-79"}],
            "vulnerabilities": [],
            "references": []
        }
    ]
    mock_get.return_value = mock_response
    
    client = GitHubAdvisoryClient()
    
    advisories = client.query_advisories_by_package("lodash", "npm", "4.17.15")
    
    assert len(advisories) == 1
    assert advisories[0].ghsa_id == "GHSA-xxxx"


@patch('ai.decider_client.requests.post')
def test_decision_orchestrator_continue_to_report_path(mock_post):
    """Test decision orchestrator with CONTINUE_TO_REPORT outcome."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "CONTINUE_TO_REPORT",
                "confidence": 0.9
            }
        }
    }
    mock_post.return_value = mock_response
    
    orchestrator = DecisionOrchestrator()
    
    finding = Finding(
        dependency_name="lodash",
        dependency_version="4.17.15",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.CONFIRMED_AFFECTED,
        advisories=[
            Advisory(
                id="CVE-2021-23337",
                aliases=["GHSA-xxxx"],
                summary="Prototype Pollution",
                details="Details",
                severity="HIGH",
                affected_versions=["4.17.15"]
            )
        ]
    )
    
    result = orchestrator.process_finding(finding)
    
    assert result.outcome == DecisionOutcome.CONTINUE_TO_REPORT
    assert result.decider_used == "decider"
    assert result.verification_evidence is None


@patch('ai.decider_client.requests.post')
@patch('ai.github_advisory_client.requests.get')
def test_decision_orchestrator_verify_with_another_source_path(mock_get, mock_post):
    """Test decision orchestrator with VERIFY_WITH_ANOTHER_SOURCE outcome."""
    # Mock Decider response
    mock_decider_response = Mock()
    mock_decider_response.status_code = 200
    mock_decider_response.json.return_value = {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "VERIFY_WITH_ANOTHER_SOURCE",
                "confidence": 0.8
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
        "summary": "Test advisory",
        "description": "Test description",
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
    
    finding = Finding(
        dependency_name="lodash",
        dependency_version="4.17.15",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.CONFIRMED_AFFECTED,
        advisories=[
            Advisory(
                id="GHSA-xxxx",
                aliases=["CVE-2021-1234"],
                summary="Test advisory",
                details="Details",
                severity="HIGH",
                affected_versions=["4.17.15"]
            )
        ]
    )
    
    result = orchestrator.process_finding(finding)
    
    assert result.outcome == DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE
    assert result.decider_used == "decider"
    assert result.verification_evidence is not None
    assert result.verification_evidence["source"] == "github_advisory_api"


@patch('ai.decider_client.requests.post')
def test_decision_orchestrator_flag_for_review_path(mock_post):
    """Test decision orchestrator with FLAG_FOR_REVIEW outcome."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "FLAG_FOR_REVIEW",
                "confidence": 0.7
            }
        }
    }
    mock_post.return_value = mock_response
    
    orchestrator = DecisionOrchestrator()
    
    finding = Finding(
        dependency_name="test-package",
        dependency_version="1.0.0",
        is_direct=False,
        source_file="/path/package-lock.json",
        status=FindingStatus.POTENTIAL_OR_AMBIGUOUS,
        advisories=[]
    )
    
    result = orchestrator.process_finding(finding)
    
    assert result.outcome == DecisionOutcome.FLAG_FOR_REVIEW
    assert result.decider_used == "decider"
    assert result.verification_evidence is None


@patch('ai.decider_client.requests.post')
@patch('ai.bedrock_client.boto3')
def test_decision_orchestrator_bedrock_fallback(mock_boto3, mock_post):
    """Test decision orchestrator falls back to Bedrock when Decider unavailable."""
    # Decider unavailable
    import requests
    mock_post.side_effect = requests.exceptions.ConnectionError()
    
    # Bedrock available
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
        dependency_name="lodash",
        dependency_version="4.17.15",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.CONFIRMED_AFFECTED,
        advisories=[
            Advisory(
                id="CVE-2021-23337",
                aliases=["GHSA-xxxx"],
                summary="Prototype Pollution",
                details="Details",
                severity="HIGH",
                affected_versions=["4.17.15"]
            )
        ]
    )
    
    result = orchestrator.process_finding(finding)
    
    assert result.outcome == DecisionOutcome.CONTINUE_TO_REPORT
    assert result.decider_used == "bedrock"


@patch('ai.decider_client.requests.post')
@patch('ai.bedrock_client.boto3')
def test_decision_orchestrator_both_unavailable(mock_boto3, mock_post):
    """Test decision orchestrator when both Decider and Bedrock unavailable."""
    import requests
    mock_post.side_effect = requests.exceptions.ConnectionError()
    mock_boto3.client.side_effect = Exception("AWS credentials not configured")
    
    orchestrator = DecisionOrchestrator()
    
    finding = Finding(
        dependency_name="lodash",
        dependency_version="4.17.15",
        is_direct=True,
        source_file="/path/package-lock.json",
        status=FindingStatus.CONFIRMED_AFFECTED,
        advisories=[
            Advisory(
                id="CVE-2021-23337",
                aliases=["GHSA-xxxx"],
                summary="Prototype Pollution",
                details="Details",
                severity="HIGH",
                affected_versions=["4.17.15"]
            )
        ]
    )
    
    result = orchestrator.process_finding(finding)
    
    assert result.outcome == DecisionOutcome.FLAG_FOR_REVIEW
    assert result.decider_used == "none"
    assert result.error is not None

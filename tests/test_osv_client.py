"""
Unit tests for OSV client with mocked responses.
"""

import pytest
from unittest.mock import Mock, patch
from vulnerability.osv_client import OSVClient, VulnerabilityResult
from scanner.dependency_parser import Dependency


def test_osv_client_initialization():
    """Test OSV client initialization with default values."""
    client = OSVClient()
    
    assert client.base_url == "https://api.osv.dev/v1"
    assert client.timeout == 30
    assert client.max_retries == 3
    assert client.retry_backoff == 1


def test_osv_client_custom_config():
    """Test OSV client initialization with custom config."""
    with patch.dict('os.environ', {
        'OSV_API_URL': 'https://custom.osv.dev/v1',
        'OSV_TIMEOUT': '60',
        'OSV_MAX_RETRIES': '5',
        'OSV_RETRY_BACKOFF': '2'
    }):
        client = OSVClient()
        
        assert client.base_url == "https://custom.osv.dev/v1"
        assert client.timeout == 60
        assert client.max_retries == 5
        assert client.retry_backoff == 2


@patch('vulnerability.osv_client.requests.post')
def test_query_batch_success(mock_post):
    """Test successful batch query."""
    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {"vulns": [{"id": "CVE-2021-23337"}]},
            {"vulns": []}
        ]
    }
    mock_post.return_value = mock_response
    
    client = OSVClient()
    
    deps = [
        Dependency("lodash", "4.17.15", True, "/path/1"),
        Dependency("express", "4.18.2", True, "/path/2")
    ]
    
    results = client.query_batch(deps)
    
    assert len(results) == 2
    assert results[0].data is not None
    assert results[1].data is not None
    assert results[0].error is None


@patch('vulnerability.osv_client.requests.post')
def test_query_batch_timeout(mock_post):
    """Test batch query with timeout."""
    import requests
    
    # Mock timeout exception
    mock_post.side_effect = requests.exceptions.Timeout()
    
    client = OSVClient()
    
    deps = [Dependency("test", "1.0.0", True, "/path")]
    
    results = client.query_batch(deps)
    
    assert len(results) == 1
    assert results[0].error == "Request timeout"
    assert results[0].timed_out is True


@patch('vulnerability.osv_client.requests.post')
def test_query_batch_rate_limit(mock_post):
    """Test batch query with rate limiting."""
    # Mock rate limit response first, then success
    mock_response_rate_limit = Mock()
    mock_response_rate_limit.status_code = 429
    
    mock_response_success = Mock()
    mock_response_success.status_code = 200
    mock_response_success.json.return_value = {"results": [{"vulns": []}]}
    
    mock_post.side_effect = [mock_response_rate_limit, mock_response_success]
    
    client = OSVClient()
    
    deps = [Dependency("test", "1.0.0", True, "/path")]
    
    results = client.query_batch(deps)
    
    assert len(results) == 1
    assert results[0].data is not None


@patch('vulnerability.osv_client.requests.post')
def test_query_batch_http_error(mock_post):
    """Test batch query with HTTP error."""
    # Mock error response
    mock_response = Mock()
    mock_response.status_code = 500
    mock_post.return_value = mock_response
    
    client = OSVClient()
    
    deps = [Dependency("test", "1.0.0", True, "/path")]
    
    results = client.query_batch(deps)
    
    assert len(results) == 1
    assert results[0].error == "HTTP 500"


@patch('vulnerability.osv_client.requests.post')
def test_query_batch_network_failure(mock_post):
    """Test batch query with network failure."""
    import requests
    
    # Mock connection error
    mock_post.side_effect = requests.exceptions.ConnectionError()
    
    client = OSVClient()
    
    deps = [Dependency("test", "1.0.0", True, "/path")]
    
    results = client.query_batch(deps)
    
    assert len(results) == 1
    assert results[0].error is not None
    # Error message should contain something about the failure
    assert len(results[0].error) > 0

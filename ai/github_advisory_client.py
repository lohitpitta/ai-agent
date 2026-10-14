"""
GitHub Advisory API client for verification of vulnerability findings.
"""

import os
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class GitHubAdvisory:
    """Represents a GitHub security advisory."""
    ghsa_id: str
    cve_id: Optional[str]
    summary: str
    description: str
    severity: str
    published_at: str
    updated_at: str
    cvss: Optional[Dict[str, Any]]
    cwes: List[str]
    vulnerabilities: List[Dict[str, Any]]
    references: List[Dict[str, Any]]


class GitHubAdvisoryClient:
    """Client for GitHub Advisory API."""
    
    def __init__(self):
        self.base_url = "https://api.github.com"
        self.token = os.getenv("GITHUB_TOKEN")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10"
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"
    
    def query_advisory_by_ghsa(self, ghsa_id: str) -> Optional[GitHubAdvisory]:
        """
        Query a specific advisory by GHSA ID.
        
        Args:
            ghsa_id: GitHub Security Advisory ID (e.g., GHSA-xxxx)
            
        Returns:
            GitHubAdvisory object or None if not found
        """
        url = f"{self.base_url}/advisories/{ghsa_id}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 404:
                return None
            
            if response.status_code != 200:
                print(f"GitHub API error: {response.status_code}")
                return None
            
            data = response.json()
            return self._parse_advisory(data)
            
        except requests.exceptions.RequestException as e:
            print(f"GitHub API request failed: {e}")
            return None
    
    def query_advisories_by_package(
        self,
        package_name: str,
        ecosystem: str = "npm",
        version: Optional[str] = None
    ) -> List[GitHubAdvisory]:
        """
        Query advisories for a specific package.
        
        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (default: npm)
            version: Optional version to filter by
            
        Returns:
            List of GitHubAdvisory objects
        """
        url = f"{self.base_url}/advisories"
        
        params = {
            "ecosystem": ecosystem,
            "affects": f"{package_name}@{version}" if version else package_name
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code != 200:
                print(f"GitHub API error: {response.status_code}")
                return []
            
            data = response.json()
            advisories = []
            
            for item in data:
                advisory = self._parse_advisory(item)
                if advisory:
                    advisories.append(advisory)
            
            return advisories
            
        except requests.exceptions.RequestException as e:
            print(f"GitHub API request failed: {e}")
            return []
    
    def _parse_advisory(self, data: Dict[str, Any]) -> Optional[GitHubAdvisory]:
        """Parse GitHub API response into GitHubAdvisory object."""
        try:
            return GitHubAdvisory(
                ghsa_id=data.get("ghsa_id", ""),
                cve_id=data.get("cve_id"),
                summary=data.get("summary", ""),
                description=data.get("description", ""),
                severity=data.get("severity", ""),
                published_at=data.get("published_at", ""),
                updated_at=data.get("updated_at", ""),
                cvss=data.get("cvss"),
                cwes=[cwe.get("cwe_id") for cwe in data.get("cwes", [])],
                vulnerabilities=data.get("vulnerabilities", []),
                references=data.get("references", [])
            )
        except Exception as e:
            print(f"Failed to parse advisory: {e}")
            return None

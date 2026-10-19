"""
AI decision orchestrator for vulnerability findings.
Implements Tool Selection policy with Decider 2B (primary) and Bedrock (fallback).
NVD enrichment is applied during the VERIFY_WITH_ANOTHER_SOURCE flow.
"""

import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from ai.decider_client import DeciderClient, DecisionOutcome
from ai.bedrock_client import BedrockClient
from ai.github_advisory_client import GitHubAdvisoryClient
from vulnerability.version_matcher import Finding, Advisory
from vulnerability.nvd_client import NVDClient, NVDEnrichmentResult


@dataclass
class DecisionResult:
    """Result of AI decision process."""
    outcome: DecisionOutcome
    decider_used: str  # "decider" or "bedrock" or "none"
    verification_evidence: Optional[Dict[str, Any]] = None
    explanation: Optional[str] = None
    error: Optional[str] = None


class DecisionOrchestrator:
    """Orchestrates AI decision-making for vulnerability findings."""
    
    def __init__(self):
        self.decider_client = DeciderClient()
        self.bedrock_client = BedrockClient()
        self.github_client = GitHubAdvisoryClient()
        self.nvd_client = NVDClient()
        
        # Decision options
        self.decision_options = [
            DecisionOutcome.CONTINUE_TO_REPORT.value,
            DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE.value,
            DecisionOutcome.FLAG_FOR_REVIEW.value
        ]
    
    def process_finding(
        self,
        finding: Finding,
        osv_data: Optional[Dict[str, Any]] = None
    ) -> DecisionResult:
        """
        Process a vulnerability finding through AI decision pipeline.
        
        Args:
            finding: The vulnerability finding to process
            osv_data: Raw OSV data (if available)
            
        Returns:
            DecisionResult with outcome and evidence
        """
        # Step 1: Make decision using Decider 2B (primary) or Bedrock (fallback)
        decision = self._make_decision(finding, osv_data)
        
        if decision.outcome is None:
            # Both deciders failed, default to FLAG_FOR_REVIEW
            return DecisionResult(
                outcome=DecisionOutcome.FLAG_FOR_REVIEW,
                decider_used="none",
                error="All decision sources unavailable"
            )
        
        # Step 2: Execute decision
        if decision.outcome == DecisionOutcome.VERIFY_WITH_ANOTHER_SOURCE:
            # Gather GitHub Advisory evidence
            verification_evidence = self._verify_with_github(finding)

            # Enrich with NVD data (CVSS scores, CWE, CVE details)
            nvd_evidence = self._enrich_with_nvd(finding)
            if nvd_evidence:
                verification_evidence["nvd_enrichment"] = nvd_evidence

            decision.verification_evidence = verification_evidence

            # After verification, generate explanation
            decision.explanation = self._generate_explanation(finding, verification_evidence)

        elif decision.outcome == DecisionOutcome.FLAG_FOR_REVIEW:
            # Just generate explanation for review
            decision.explanation = self._generate_explanation(finding, {})

        elif decision.outcome == DecisionOutcome.CONTINUE_TO_REPORT:
            # Generate explanation for report
            decision.explanation = self._generate_explanation(finding, {})
        
        return decision
    
    def _make_decision(
        self,
        finding: Finding,
        osv_data: Optional[Dict[str, Any]]
    ) -> DecisionResult:
        """Make decision using Decider 2B (primary) or Bedrock (fallback)."""
        # Construct state text for decision
        state = self._construct_decision_state(finding, osv_data)
        
        # Try Decider 2B first
        if self.decider_client.is_available():
            outcome = self.decider_client.make_decision(state, self.decision_options)
            if outcome:
                return DecisionResult(
                    outcome=outcome,
                    decider_used="decider"
                )
        
        # Fallback to Bedrock
        if self.bedrock_client.is_available():
            outcome = self.bedrock_client.make_decision(state, self.decision_options)
            if outcome:
                return DecisionResult(
                    outcome=outcome,
                    decider_used="bedrock"
                )
        
        # Both failed
        return DecisionResult(
            outcome=None,
            decider_used="none",
            error="No decision source available"
        )
    
    def _construct_decision_state(
        self,
        finding: Finding,
        osv_data: Optional[Dict[str, Any]]
    ) -> str:
        """Construct state text for decision-making."""
        state_parts = [
            f"Dependency: {finding.dependency_name}@{finding.dependency_version}",
            f"Status: {finding.status.value}",
            f"Direct dependency: {finding.is_direct}",
            f"Number of advisories: {len(finding.advisories)}"
        ]
        
        if finding.advisories:
            state_parts.append("\nAdvisories:")
            for adv in finding.advisories:
                state_parts.append(f"- {adv.id}: {adv.summary}")
                if adv.severity:
                    state_parts.append(f"  Severity: {adv.severity}")
        
        if osv_data:
            state_parts.append("\nOSV Data Available: Yes")
        
        return "\n".join(state_parts)
    
    def _verify_with_github(self, finding: Finding) -> Dict[str, Any]:
        """Verify finding with GitHub Advisory API."""
        evidence = {
            "source": "github_advisory_api",
            "advisories_found": [],
            "verification_status": "failed"
        }

        # Try to query by GHSA ID if available
        for adv in finding.advisories:
            if adv.id.startswith("GHSA-"):
                github_adv = self.github_client.query_advisory_by_ghsa(adv.id)
                if github_adv:
                    evidence["advisories_found"].append({
                        "ghsa_id": github_adv.ghsa_id,
                        "cve_id": github_adv.cve_id,
                        "severity": github_adv.severity,
                        "summary": github_adv.summary
                    })

        # Also query by package name
        package_advisories = self.github_client.query_advisories_by_package(
            finding.dependency_name,
            "npm",
            finding.dependency_version
        )

        for adv in package_advisories:
            evidence["advisories_found"].append({
                "ghsa_id": adv.ghsa_id,
                "cve_id": adv.cve_id,
                "severity": adv.severity,
                "summary": adv.summary
            })

        if evidence["advisories_found"]:
            evidence["verification_status"] = "confirmed"

        return evidence

    def _enrich_with_nvd(self, finding: Finding) -> Optional[Dict[str, Any]]:
        """
        Enrich a finding with CVSS scores and CVE details from NVD.

        Returns a dict of NVD evidence, or None if NVD is not available.
        """
        if not self.nvd_client.is_available():
            return None

        # Collect known CVE IDs from the finding's advisories
        cve_ids = []
        for adv in finding.advisories:
            if adv.id.upper().startswith("CVE-"):
                cve_ids.append(adv.id)
            for alias in adv.aliases:
                if alias.upper().startswith("CVE-"):
                    cve_ids.append(alias)

        enrichment = self.nvd_client.enrich_finding(
            dependency_name=finding.dependency_name,
            dependency_version=finding.dependency_version,
            cve_ids=cve_ids if cve_ids else None,
        )

        if not enrichment.cve_results:
            return None

        # Serialise NVD results into a plain dict for storage / reporting
        cve_entries = []
        for cve in enrichment.cve_results:
            cve_entries.append({
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_v3_score": cve.cvss_v3_score,
                "cvss_v3_severity": cve.cvss_v3_severity,
                "cvss_v3_vector": cve.cvss_v3_vector,
                "cvss_v2_score": cve.cvss_v2_score,
                "cvss_v2_severity": cve.cvss_v2_severity,
                "cwe_ids": cve.cwe_ids,
                "references": cve.references[:5],  # limit to 5 refs
                "published": cve.published,
                "last_modified": cve.last_modified,
                "vuln_status": cve.vuln_status,
            })

        return {
            "source": "nvd_api",
            "cve_count": len(cve_entries),
            "cves": cve_entries,
        }
    
    def _generate_explanation(
        self,
        finding: Finding,
        evidence: Dict[str, Any]
    ) -> Optional[str]:
        """Generate explanation using Bedrock."""
        if not self.bedrock_client.is_available():
            return None
        
        # Prepare advisory data
        advisories_data = []
        for adv in finding.advisories:
            advisories_data.append({
                "id": adv.id,
                "aliases": adv.aliases,
                "summary": adv.summary,
                "details": adv.details,
                "severity": adv.severity
            })
        
        return self.bedrock_client.generate_explanation(
            finding.dependency_name,
            finding.dependency_version,
            advisories_data,
            evidence
        )

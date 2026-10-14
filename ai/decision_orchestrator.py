"""
AI decision orchestrator for vulnerability findings.
Implements Tool Selection policy with Decider 2B (primary) and Bedrock (fallback).
"""

import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from ai.decider_client import DeciderClient, DecisionOutcome
from ai.bedrock_client import BedrockClient
from ai.github_advisory_client import GitHubAdvisoryClient
from vulnerability.version_matcher import Finding, Advisory


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
            verification_evidence = self._verify_with_github(finding)
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

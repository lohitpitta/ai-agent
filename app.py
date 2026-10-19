#!/usr/bin/env python3
"""
CLI entry point for the dependency vulnerability scanner.
"""

import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from the project root before anything else
load_dotenv()

from scanner.project_scanner import ProjectScanner
from vulnerability.osv_client import OSVClient
from vulnerability.version_matcher import VersionMatcher
from database.db import Database
from reports.report_generator import ReportGenerator
from ai.decision_orchestrator import DecisionOrchestrator


def main():
    parser = argparse.ArgumentParser(
        description="Scan npm projects for dependency vulnerabilities"
    )
    parser.add_argument(
        "command",
        choices=["scan"],
        help="Command to execute"
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to the project directory to scan"
    )
    
    args = parser.parse_args()
    
    if args.command == "scan":
        scan_project(args.path)


def scan_project(project_path: str):
    """Execute a full vulnerability scan on the given project path."""
    project_path = Path(project_path).absolute()
    
    if not project_path.exists():
        print(f"Error: Path does not exist: {project_path}")
        sys.exit(1)
    
    if not project_path.is_dir():
        print(f"Error: Path is not a directory: {project_path}")
        sys.exit(1)
    
    print(f"Scanning project: {project_path}")
    
    # Initialize components
    db = Database()
    scanner = ProjectScanner()
    osv_client = OSVClient()
    version_matcher = VersionMatcher()
    decision_orchestrator = DecisionOrchestrator()
    report_generator = ReportGenerator()
    
    # Create scan record
    scan_id = db.create_scan(str(project_path))
    print(f"Scan ID: {scan_id}")
    
    try:
        # Phase 1: Discover manifest files
        db.log_audit_event(scan_id, "scan_started", {"path": str(project_path)})
        manifests = scanner.find_manifests(project_path)
        db.log_audit_event(scan_id, "manifests_discovered", {"count": len(manifests)})
        print(f"Found {len(manifests)} manifest files")
        
        # Phase 2: Parse dependencies
        from scanner.dependency_parser import DependencyParser
        parser = DependencyParser()
        all_dependencies = []
        
        for manifest_path in manifests:
            deps = parser.parse_lockfile(manifest_path)
            all_dependencies.extend(deps)
        
        db.log_audit_event(scan_id, "dependencies_extracted", {"count": len(all_dependencies)})
        print(f"Extracted {len(all_dependencies)} dependencies")
        
        # Phase 3: Query OSV
        db.log_audit_event(scan_id, "source_queried", {"source": "OSV"})
        vulnerabilities = osv_client.query_batch(all_dependencies)
        
        # Phase 4: Match versions and classify
        findings = []
        for dep, vuln_data in zip(all_dependencies, vulnerabilities):
            result = version_matcher.classify_vulnerability(dep, vuln_data)
            findings.append(result)
            db.record_finding(scan_id, result)
        
        # Phase 5: AI decision processing (Tool Selection)
        db.log_audit_event(scan_id, "ai_decision_started", {"findings_count": len(findings)})
        findings_with_ai = db.get_findings(scan_id)
        
        for finding_dict in findings_with_ai:
            # Only process findings with advisories (confirmed or ambiguous)
            if finding_dict['status'] in ['CONFIRMED_AFFECTED', 'POTENTIAL_OR_AMBIGUOUS']:
                # Reconstruct Finding object
                from vulnerability.version_matcher import Finding, FindingStatus, Advisory
                finding = Finding(
                    dependency_name=finding_dict['dependency_name'],
                    dependency_version=finding_dict['dependency_version'],
                    is_direct=finding_dict['is_direct'],
                    source_file=finding_dict['source_file'],
                    status=FindingStatus(finding_dict['status']),
                    advisories=[],  # Simplified for decision
                    error_message=finding_dict.get('error_message')
                )
                
                # Get OSV data if available (simplified)
                osv_data = None
                
                # Process through AI decision orchestrator
                decision_result = decision_orchestrator.process_finding(finding, osv_data)
                
                # Update database with AI decision
                if decision_result.outcome:
                    db.update_ai_decision(
                        finding_id=finding_dict['id'],
                        decision_outcome=decision_result.outcome.value,
                        decider_used=decision_result.decider_used,
                        verification_evidence=decision_result.verification_evidence,
                        explanation=decision_result.explanation
                    )
                    db.increment_ai_decision_counter(scan_id, decision_result.outcome.value)
                    
                    # Log decision to audit
                    db.log_audit_event(scan_id, "ai_decision_made", {
                        "dependency": finding.dependency_name,
                        "outcome": decision_result.outcome.value,
                        "decider": decision_result.decider_used
                    })
        
        db.log_audit_event(scan_id, "ai_decision_completed", {})
        
        # Phase 6: Generate report
        report_path = report_generator.generate(scan_id, db)
        db.log_audit_event(scan_id, "report_generated", {"path": report_path})
        
        # Phase 7: Complete scan
        db.complete_scan(scan_id)
        db.log_audit_event(scan_id, "scan_completed", {"status": "completed"})
        
        print(f"Report generated: {report_path}")
        print(f"Scan completed successfully")
        
    except Exception as e:
        db.log_error(scan_id, str(e), "scan_execution")
        db.log_audit_event(scan_id, "scan_completed", {"status": "failed"})
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

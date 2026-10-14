"""
HTML report generator for vulnerability scan results.
"""

import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from database.db import Database
from vulnerability.version_matcher import FindingStatus


class ReportGenerator:
    """Generates HTML reports from scan results."""
    
    def __init__(self):
        self.output_dir = os.getenv("REPORT_OUTPUT_DIR", "reports")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(self, scan_id: str, db: Database) -> str:
        """
        Generate an HTML report for a scan.
        
        Args:
            scan_id: The scan ID
            db: Database instance
            
        Returns:
            Path to the generated report
        """
        # Get scan data
        scan_summary = db.get_scan_summary(scan_id)
        if not scan_summary:
            raise ValueError(f"Scan {scan_id} not found")
        
        findings = db.get_findings(scan_id)
        
        # Categorize findings
        confirmed = [f for f in findings if f['status'] == FindingStatus.CONFIRMED_AFFECTED.value]
        ambiguous = [f for f in findings if f['status'] == FindingStatus.POTENTIAL_OR_AMBIGUOUS.value]
        failed = [f for f in findings if f['status'] == FindingStatus.LOOKUP_FAILED.value]
        no_match = [f for f in findings if f['status'] == FindingStatus.NO_MATCH_RETURNED.value]
        
        # Determine overall status
        has_failures = scan_summary['failed_lookups'] > 0
        has_vulnerabilities = scan_summary['confirmed_findings'] > 0
        
        if has_failures:
            overall_status = "PARTIAL_SCAN"
        elif has_vulnerabilities:
            overall_status = "VULNERABILITIES_FOUND"
        else:
            overall_status = "NO_VULNERABILITIES_FOUND"
        
        # Generate HTML
        html = self._generate_html(
            scan_summary,
            confirmed,
            ambiguous,
            failed,
            no_match,
            overall_status
        )
        
        # Write to file
        report_filename = f"scan_{scan_id}.html"
        report_path = os.path.join(self.output_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return report_path
    
    def _generate_html(
        self,
        scan_summary: Dict[str, Any],
        confirmed: List[Dict[str, Any]],
        ambiguous: List[Dict[str, Any]],
        failed: List[Dict[str, Any]],
        no_match: List[Dict[str, Any]],
        overall_status: str
    ) -> str:
        """Generate the HTML content."""
        
        # Status color
        status_colors = {
            "PARTIAL_SCAN": "#f59e0b",
            "VULNERABILITIES_FOUND": "#ef4444",
            "NO_VULNERABILITIES_FOUND": "#10b981"
        }
        status_color = status_colors.get(overall_status, "#6b7280")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {scan_summary['scan_id']}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f9fafb;
        }}
        .header {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .status-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            background: {status_color};
            margin-bottom: 10px;
        }}
        h1 {{
            margin: 0 0 10px 0;
            color: #111827;
        }}
        .scan-id {{
            color: #6b7280;
            font-size: 14px;
        }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .section h2 {{
            margin-top: 0;
            color: #111827;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-card {{
            background: #f3f4f6;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #111827;
        }}
        .summary-card .label {{
            color: #6b7280;
            font-size: 14px;
            margin-top: 5px;
        }}
        .finding-item {{
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 10px;
        }}
        .finding-item.confirmed {{
            border-left: 4px solid #ef4444;
            background: #fef2f2;
        }}
        .finding-item.ambiguous {{
            border-left: 4px solid #f59e0b;
            background: #fffbeb;
        }}
        .finding-item.failed {{
            border-left: 4px solid #6b7280;
            background: #f3f4f6;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .dependency-name {{
            font-weight: bold;
            font-size: 16px;
        }}
        .dependency-version {{
            color: #6b7280;
            font-size: 14px;
        }}
        .advisory-list {{
            margin-top: 10px;
        }}
        .advisory-item {{
            background: white;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 5px;
        }}
        .advisory-id {{
            font-weight: bold;
            color: #dc2626;
        }}
        .advisory-summary {{
            margin-top: 5px;
            color: #374151;
        }}
        .direct-badge {{
            display: inline-block;
            padding: 2px 8px;
            background: #dbeafe;
            color: #1e40af;
            border-radius: 3px;
            font-size: 12px;
            margin-left: 10px;
        }}
        .transitive-badge {{
            display: inline-block;
            padding: 2px 8px;
            background: #e5e7eb;
            color: #374151;
            border-radius: 3px;
            font-size: 12px;
            margin-left: 10px;
        }}
        .metadata-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .metadata-table th, .metadata-table td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        .metadata-table th {{
            background: #f9fafb;
            font-weight: 600;
        }}
        .limitations {{
            background: #fffbeb;
            border: 1px solid #fcd34d;
            border-radius: 6px;
            padding: 15px;
            margin-top: 20px;
        }}
        .limitations h3 {{
            margin-top: 0;
            color: #92400e;
        }}
        .limitations ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .limitations li {{
            color: #92400e;
            margin-bottom: 5px;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #6b7280;
        }}
        .ai-section {{
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 1px solid #bae6fd;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }}
        .ai-section h4 {{
            margin-top: 0;
            color: #0369a1;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .ai-decision {{
            font-weight: 600;
            color: #0c4a6e;
            margin-bottom: 10px;
        }}
        .ai-decision-badge {{
            display: inline-block;
            padding: 4px 8px;
            background: #0ea5e9;
            color: white;
            border-radius: 3px;
            font-size: 11px;
            margin-left: 8px;
        }}
        .ai-explanation {{
            background: white;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 13px;
            color: #334155;
            border-left: 3px solid #0ea5e9;
        }}
        .verification-evidence {{
            background: white;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 12px;
            color: #475569;
        }}
        .verification-evidence strong {{
            color: #0c4a6e;
        }}
        .ai-unavailable {{
            background: #f1f5f9;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 12px;
            color: #64748b;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="status-badge">{overall_status}</div>
        <h1>Vulnerability Scan Report</h1>
        <div class="scan-id">Scan ID: {scan_summary['scan_id']}</div>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{scan_summary['total_dependencies']}</div>
                <div class="label">Total Dependencies</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #ef4444;">{scan_summary['confirmed_findings']}</div>
                <div class="label">Confirmed Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #f59e0b;">{scan_summary['ambiguous_findings']}</div>
                <div class="label">Ambiguous Findings</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #6b7280;">{scan_summary['failed_lookups']}</div>
                <div class="label">Failed Lookups</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Scan Metadata</h2>
        <table class="metadata-table">
            <tr>
                <th>Project Path</th>
                <td>{scan_summary['project_path']}</td>
            </tr>
            <tr>
                <th>Started At</th>
                <td>{scan_summary['started_at']}</td>
            </tr>
            <tr>
                <th>Completed At</th>
                <td>{scan_summary['completed_at'] or 'In progress'}</td>
            </tr>
            <tr>
                <th>Status</th>
                <td>{scan_summary['status']}</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Confirmed Vulnerabilities ({len(confirmed)})</h2>
        {self._render_findings(confirmed, 'confirmed')}
    </div>
    
    <div class="section">
        <h2>Ambiguous Findings ({len(ambiguous)})</h2>
        {self._render_findings(ambiguous, 'ambiguous')}
    </div>
    
    <div class="section">
        <h2>Failed/Unchecked Dependencies ({len(failed)})</h2>
        {self._render_findings(failed, 'failed')}
    </div>
    
    <div class="section">
        <h2>Dependencies with No Vulnerabilities ({len(no_match)})</h2>
        {self._render_findings(no_match, 'none')}
    </div>
    
    <div class="section">
        <h2>Scan Limitations</h2>
        <div class="limitations">
            <h3>Important Notes</h3>
            <ul>
                <li>This scan only checks npm dependencies</li>
                <li>Vulnerabilities are based on OSV database at the time of scanning</li>
                <li>A scan with failed lookups is marked as "partial scan" - some dependencies could not be checked</li>
                <li>No vulnerabilities found does not guarantee the project is secure</li>
                <li>Transitive dependencies are included in the scan</li>
                <li>Version matching uses deterministic semver rules</li>
            </ul>
        </div>
    </div>
    
    <div style="text-align: center; color: #6b7280; margin-top: 40px; font-size: 14px;">
        Generated by Dependency Vulnerability Scanner
    </div>
</body>
</html>"""
        
        return html
    
    def _render_findings(self, findings: List[Dict[str, Any]], style: str) -> str:
        """Render findings as HTML."""
        if not findings:
            return '<div class="empty-state">No findings in this category</div>'
        
        html = ""
        for finding in findings:
            badge_class = 'direct-badge' if finding['is_direct'] else 'transitive-badge'
            badge_text = 'Direct' if finding['is_direct'] else 'Transitive'
            
            html += f"""
            <div class="finding-item {style}">
                <div class="finding-header">
                    <div>
                        <span class="dependency-name">{finding['dependency_name']}</span>
                        <span class="dependency-version">@{finding['dependency_version']}</span>
                        <span class="{badge_class}">{badge_text}</span>
                    </div>
                </div>
                <div style="color: #6b7280; font-size: 13px; margin-bottom: 10px;">
                    Source: {finding['source_file']}
                </div>
            """
            
            if finding['advisory_ids']:
                advisories = finding['advisory_ids'].split(',')
                html += '<div class="advisory-list">'
                for adv_id in advisories:
                    html += f'''
                    <div class="advisory-item">
                        <div class="advisory-id">{adv_id}</div>
                    </div>
                    '''
                html += '</div>'
            
            if finding['error_message']:
                html += f'<div style="color: #ef4444; margin-top: 10px;">Error: {finding["error_message"]}</div>'
            
            # AI Decision Section (visually separated from facts)
            if finding.get('ai_decision_outcome'):
                import json
                html += self._render_ai_section(finding)
            else:
                html += '<div class="ai-unavailable">AI analysis not available for this finding</div>'
            
            html += '</div>'
        
        return html
    
    def _render_ai_section(self, finding: Dict[str, Any]) -> str:
        """Render AI decision and explanation section."""
        import json
        
        html = '<div class="ai-section">'
        html += '<h4>AI Analysis</h4>'
        
        # Decision
        decision = finding.get('ai_decision_outcome', 'N/A')
        decider = finding.get('ai_decider_used', 'unknown')
        html += f'<div class="ai-decision">Decision: {decision} <span class="ai-decision-badge">via {decider}</span></div>'
        
        # Verification evidence
        if finding.get('verification_evidence'):
            try:
                evidence = json.loads(finding['verification_evidence'])
                html += '<div class="verification-evidence">'
                html += f'<strong>Verification Source:</strong> {evidence.get("source", "unknown")}<br>'
                html += f'<strong>Status:</strong> {evidence.get("verification_status", "unknown")}<br>'
                if evidence.get('advisories_found'):
                    html += f'<strong>Advisories Found:</strong> {len(evidence["advisories_found"])}'
                html += '</div>'
            except json.JSONDecodeError:
                pass
        
        # AI Explanation
        if finding.get('ai_explanation'):
            html += f'<div class="ai-explanation">{finding["ai_explanation"]}</div>'
        
        html += '</div>'
        return html

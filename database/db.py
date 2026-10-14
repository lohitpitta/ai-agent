"""
SQLite database operations for storing scan results.
Tables: scans, findings, audit_logs, error_logs.
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from vulnerability.version_matcher import Finding, FindingStatus


class Database:
    """SQLite database for vulnerability scan results."""
    
    def __init__(self):
        self.db_path = os.getenv("DB_PATH", "vulnerability_scanner.db")
        self.conn = None
        self._initialize()
    
    def _initialize(self):
        """Initialize database connection and create tables."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Create all required tables."""
        cursor = self.conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                project_path TEXT NOT NULL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT DEFAULT 'in_progress',
                total_dependencies INTEGER DEFAULT 0,
                confirmed_findings INTEGER DEFAULT 0,
                ambiguous_findings INTEGER DEFAULT 0,
                failed_lookups INTEGER DEFAULT 0,
                ai_decisions_made INTEGER DEFAULT 0,
                ai_verifications_performed INTEGER DEFAULT 0,
                ai_flags_for_review INTEGER DEFAULT 0
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                dependency_name TEXT NOT NULL,
                dependency_version TEXT NOT NULL,
                is_direct BOOLEAN NOT NULL,
                source_file TEXT NOT NULL,
                status TEXT NOT NULL,
                advisory_ids TEXT,
                error_message TEXT,
                ai_decision_outcome TEXT,
                ai_decider_used TEXT,
                verification_evidence TEXT,
                ai_explanation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)
        
        # Error logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS error_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                error_message TEXT NOT NULL,
                error_context TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)
        
        self.conn.commit()
    
    def create_scan(self, project_path: str) -> str:
        """
        Create a new scan record.
        
        Args:
            project_path: Path to the scanned project
            
        Returns:
            Scan ID (UUID-like string)
        """
        scan_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (scan_id, project_path, started_at)
            VALUES (?, ?, ?)
            """,
            (scan_id, project_path, datetime.utcnow().isoformat())
        )
        self.conn.commit()
        
        return scan_id
    
    def complete_scan(self, scan_id: str):
        """Mark a scan as completed."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET completed_at = ?, status = 'completed'
            WHERE scan_id = ?
            """,
            (datetime.utcnow().isoformat(), scan_id)
        )
        self.conn.commit()
    
    def record_finding(self, scan_id: str, finding: Finding):
        """
        Record a vulnerability finding.
        
        Args:
            scan_id: The scan ID
            finding: Finding object to record
        """
        import json
        cursor = self.conn.cursor()
        
        # Serialize advisory IDs
        advisory_ids = ",".join([adv.id for adv in finding.advisories])
        
        cursor.execute(
            """
            INSERT INTO findings (
                scan_id, dependency_name, dependency_version,
                is_direct, source_file, status, advisory_ids, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding.dependency_name,
                finding.dependency_version,
                finding.is_direct,
                finding.source_file,
                finding.status.value,
                advisory_ids,
                finding.error_message
            )
        )
        
        # Update scan counters
        if finding.status == FindingStatus.CONFIRMED_AFFECTED:
            cursor.execute(
                "UPDATE scans SET confirmed_findings = confirmed_findings + 1 WHERE scan_id = ?",
                (scan_id,)
            )
        elif finding.status == FindingStatus.POTENTIAL_OR_AMBIGUOUS:
            cursor.execute(
                "UPDATE scans SET ambiguous_findings = ambiguous_findings + 1 WHERE scan_id = ?",
                (scan_id,)
            )
        elif finding.status == FindingStatus.LOOKUP_FAILED:
            cursor.execute(
                "UPDATE scans SET failed_lookups = failed_lookups + 1 WHERE scan_id = ?",
                (scan_id,)
            )
        
        cursor.execute(
            "UPDATE scans SET total_dependencies = total_dependencies + 1 WHERE scan_id = ?",
            (scan_id,)
        )
        
        self.conn.commit()
    
    def update_ai_decision(
        self,
        finding_id: int,
        decision_outcome: str,
        decider_used: str,
        verification_evidence: Optional[Dict[str, Any]] = None,
        explanation: Optional[str] = None
    ):
        """
        Update a finding with AI decision results.
        
        Args:
            finding_id: The finding ID in the database
            decision_outcome: The decision outcome
            decider_used: Which decider was used (decider/bedrock/none)
            verification_evidence: Evidence from verification sources
            explanation: AI-generated explanation
        """
        import json
        cursor = self.conn.cursor()
        
        evidence_json = json.dumps(verification_evidence) if verification_evidence else None
        
        cursor.execute(
            """
            UPDATE findings
            SET ai_decision_outcome = ?, ai_decider_used = ?, 
                verification_evidence = ?, ai_explanation = ?
            WHERE id = ?
            """,
            (decision_outcome, decider_used, evidence_json, explanation, finding_id)
        )
        
        self.conn.commit()
    
    def increment_ai_decision_counter(self, scan_id: str, outcome: str):
        """
        Increment AI decision counters for a scan.
        
        Args:
            scan_id: The scan ID
            outcome: The decision outcome
        """
        cursor = self.conn.cursor()
        
        cursor.execute(
            "UPDATE scans SET ai_decisions_made = ai_decisions_made + 1 WHERE scan_id = ?",
            (scan_id,)
        )
        
        if outcome == "VERIFY_WITH_ANOTHER_SOURCE":
            cursor.execute(
                "UPDATE scans SET ai_verifications_performed = ai_verifications_performed + 1 WHERE scan_id = ?",
                (scan_id,)
            )
        elif outcome == "FLAG_FOR_REVIEW":
            cursor.execute(
                "UPDATE scans SET ai_flags_for_review = ai_flags_for_review + 1 WHERE scan_id = ?",
                (scan_id,)
            )
        
        self.conn.commit()
    
    def get_scan_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of a scan."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scans WHERE scan_id = ?
            """,
            (scan_id,)
        )
        row = cursor.fetchone()
        
        if row:
            return dict(row)
        return None
    
    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a scan."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM findings WHERE scan_id = ?
            """,
            (scan_id,)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def get_findings_by_status(self, scan_id: str, status: FindingStatus) -> List[Dict[str, Any]]:
        """Get findings filtered by status."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM findings WHERE scan_id = ? AND status = ?
            """,
            (scan_id, status.value)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def log_audit_event(self, scan_id: str, event_type: str, event_data: Dict[str, Any]):
        """
        Log an audit event.
        
        Args:
            scan_id: The scan ID
            event_type: Type of event
            event_data: Event data as dictionary
        """
        import json
        cursor = self.conn.cursor()
        event_data_json = json.dumps(event_data) if event_data else None
        
        cursor.execute(
            """
            INSERT INTO audit_logs (scan_id, event_type, event_data)
            VALUES (?, ?, ?)
            """,
            (scan_id, event_type, event_data_json)
        )
        self.conn.commit()
    
    def log_error(self, scan_id: str, error_message: str, context: Optional[str] = None):
        """
        Log an error event.
        
        Args:
            scan_id: The scan ID
            error_message: The error message (sanitized)
            context: Optional error context
        """
        cursor = self.conn.cursor()
        sanitized_message = self._sanitize_error_message(error_message)
        
        cursor.execute(
            """
            INSERT INTO error_logs (scan_id, error_message, error_context)
            VALUES (?, ?, ?)
            """,
            (scan_id, sanitized_message, context)
        )
        self.conn.commit()
    
    def _sanitize_error_message(self, message: str) -> str:
        """
        Sanitize error message to remove potential secrets.
        
        Args:
            message: Raw error message
            
        Returns:
            Sanitized error message
        """
        import re
        sanitized = message
        sanitized = re.sub(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]', sanitized)
        sanitized = re.sub(r'api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]+', 'api_key=[REDACTED]', sanitized)
        sanitized = re.sub(r'token["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]+', 'token=[REDACTED]', sanitized)
        return sanitized
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
    
    def __del__(self):
        """Cleanup on deletion."""
        self.close()

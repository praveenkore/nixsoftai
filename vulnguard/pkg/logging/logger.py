# VulnGuard - Linux Security Compliance Agent
# Copyright (c) Nixsoft Technologies Pvt. Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Audit Logger Module - Structured JSON-Line Logging

Provides structured logging for all audit trails in VulnGuard.
All logs are written as JSON lines for easy parsing and analysis.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from pythonjsonlogger import jsonlogger


class AuditLogger:
    """
    Structured audit logger for VulnGuard operations.
    
    All audit events are logged as JSON lines with consistent schema
    for easy parsing, analysis, and compliance reporting.
    """
    
    def __init__(
        self,
        log_file: str = "/var/log/vulnguard/audit.log",
        log_level: str = "INFO",
        log_format: str = "json",
        max_size_mb: int = 100,
        backup_count: int = 10
    ):
        """
        Initialize the audit logger.
        
        Args:
            log_file: Path to the log file
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_format: Log format (json or text)
            max_size_mb: Maximum size of log file in MB before rotation
            backup_count: Number of backup files to keep
        """
        self.log_file = log_file
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.log_format = log_format
        
        # Ensure log directory exists
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger("vulnguard")
        self.logger.setLevel(self.log_level)
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Create file handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count
        )
        file_handler.setLevel(self.log_level)
        
        # Set formatter based on format type
        if log_format == "json":
            formatter = jsonlogger.JsonFormatter(
                '%(asctime)s %(name)s %(levelname)s %(message)s'
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Also add console handler for visibility
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def _log(
        self,
        level: str,
        event_type: str,
        data: Dict[str, Any],
        message: Optional[str] = None
    ) -> None:
        """
        Internal method to log an event with structured data.
        
        Args:
            level: Log level (info, warning, error, critical)
            event_type: Type of event (scan, remediation, etc.)
            data: Structured data to include in the log
            message: Optional human-readable message
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "data": data
        }
        
        if message:
            log_entry["message"] = message
        
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(json.dumps(log_entry))
    
    def log_scan_start(
        self,
        benchmark: str,
        rule_id: str,
        system_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log the start of a compliance scan.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            system_info: Optional system information
        """
        self._log(
            level="info",
            event_type="scan_start",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "system_info": system_info or {}
            },
            message=f"Starting scan for {benchmark} rule {rule_id}"
        )
    
    def log_scan_result(
        self,
        benchmark: str,
        rule_id: str,
        compliant: bool,
        expected_state: str,
        actual_state: str,
        check_output: str
    ) -> None:
        """
        Log the result of a compliance scan.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            compliant: Whether the system is compliant
            expected_state: Expected state from the rule
            actual_state: Actual state found
            check_output: Output from the check command
        """
        self._log(
            level="info",
            event_type="scan_result",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "compliant": compliant,
                "expected_state": expected_state,
                "actual_state": actual_state,
                "check_output": check_output
            },
            message=f"Scan result for {benchmark} rule {rule_id}: {'compliant' if compliant else 'non-compliant'}"
        )
    
    def log_evaluation(
        self,
        benchmark: str,
        rule_id: str,
        severity: str,
        risk_level: str,
        ai_assist_required: bool
    ) -> None:
        """
        Log the compliance evaluation result.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            severity: Normalized severity level
            risk_level: Risk level (low, medium, high, critical)
            ai_assist_required: Whether AI assistance is required
        """
        self._log(
            level="info",
            event_type="evaluation",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "severity": severity,
                "risk_level": risk_level,
                "ai_assist_required": ai_assist_required
            },
            message=f"Evaluation for {benchmark} rule {rule_id}: severity={severity}, risk={risk_level}"
        )
    
    def log_ai_advisory(
        self,
        rule_id: str,
        confidence: float,
        recommendation: str,
        commands: Optional[list] = None
    ) -> None:
        """
        Log AI advisory output.
        
        Args:
            rule_id: Rule identifier
            confidence: Confidence score (0.0 - 1.0)
            recommendation: AI recommendation
            commands: Optional list of recommended commands
        """
        self._log(
            level="info",
            event_type="ai_advisory",
            data={
                "rule_id": rule_id,
                "confidence": confidence,
                "recommendation": recommendation,
                "commands": commands or []
            },
            message=f"AI advisory for rule {rule_id}: confidence={confidence:.2f}"
        )
    
    def log_remediation_start(
        self,
        benchmark: str,
        rule_id: str,
        mode: str,
        commands: list
    ) -> None:
        """
        Log the start of a remediation action.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            mode: Remediation mode (dry-run or commit)
            commands: List of commands to execute
        """
        self._log(
            level="info",
            event_type="remediation_start",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "mode": mode,
                "commands": commands
            },
            message=f"Starting remediation for {benchmark} rule {rule_id} in {mode} mode"
        )
    
    def log_remediation_result(
        self,
        benchmark: str,
        rule_id: str,
        success: bool,
        output: str,
        error: Optional[str] = None
    ) -> None:
        """
        Log the result of a remediation action.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            success: Whether the remediation was successful
            output: Command output
            error: Optional error message
        """
        self._log(
            level="info" if success else "error",
            event_type="remediation_result",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "success": success,
                "output": output,
                "error": error
            },
            message=f"Remediation for {benchmark} rule {rule_id}: {'success' if success else 'failed'}"
        )
    
    def log_rollback(
        self,
        benchmark: str,
        rule_id: str,
        reason: str,
        commands: list
    ) -> None:
        """
        Log a rollback action.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            reason: Reason for rollback
            commands: List of rollback commands executed
        """
        self._log(
            level="warning",
            event_type="rollback",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "reason": reason,
                "commands": commands
            },
            message=f"Rollback for {benchmark} rule {rule_id}: {reason}"
        )
    
    def log_backup(
        self,
        benchmark: str,
        rule_id: str,
        backup_path: str,
        files_backed_up: list
    ) -> None:
        """
        Log a configuration backup action.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            backup_path: Path to backup directory
            files_backed_up: List of files that were backed up
        """
        self._log(
            level="info",
            event_type="backup",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "backup_path": backup_path,
                "files_backed_up": files_backed_up
            },
            message=f"Backup created for {benchmark} rule {rule_id}: {len(files_backed_up)} files"
        )
    
    def log_approval_request(
        self,
        benchmark: str,
        rule_id: str,
        severity: str,
        reason: str
    ) -> None:
        """
        Log an approval request.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            rule_id: Rule identifier
            severity: Severity level
            reason: Reason approval is required
        """
        self._log(
            level="warning",
            event_type="approval_request",
            data={
                "benchmark": benchmark,
                "rule_id": rule_id,
                "severity": severity,
                "reason": reason
            },
            message=f"Approval required for {benchmark} rule {rule_id} ({severity}): {reason}"
        )
    
    def log_error(
        self,
        event_type: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an error event.
        
        Args:
            event_type: Type of event where error occurred
            error_message: Error message
            context: Optional context information
        """
        self._log(
            level="error",
            event_type="error",
            data={
                "event_type": event_type,
                "error_message": error_message,
                "context": context or {}
            },
            message=f"Error in {event_type}: {error_message}"
        )
    
    def log_system_info(
        self,
        os_name: str,
        os_version: str,
        hostname: str,
        additional_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log system information at the start of a scan.
        
        Args:
            os_name: Operating system name
            os_version: Operating system version
            hostname: System hostname
            additional_info: Additional system information
        """
        self._log(
            level="info",
            event_type="system_info",
            data={
                "os_name": os_name,
                "os_version": os_version,
                "hostname": hostname,
                "additional_info": additional_info or {}
            },
            message=f"System info: {os_name} {os_version} on {hostname}"
        )

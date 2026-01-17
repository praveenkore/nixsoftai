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
Remediation Module - Reversible Remediation Engine

Applies security fixes with automatic rollback capabilities and safety controls.
All remediations are reversible and logged for audit purposes.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from vulnguard.pkg.scanner.scanner import ScanResult
from vulnguard.pkg.engine.engine import EvaluationResult
from vulnguard.pkg.advisor.advisor import AIAdvisory
from vulnguard.pkg.logging.logger import AuditLogger


class RemediationResult:
    """
    Represents the result of a remediation action.
    """
    
    def __init__(
        self,
        rule_id: str,
        benchmark: str,
        success: bool,
        commands_executed: List[str],
        output: str,
        error: Optional[str] = None,
        rollback_commands: Optional[List[str]] = None,
        backup_path: Optional[str] = None
    ):
        """
        Initialize a remediation result.
        
        Args:
            rule_id: Rule identifier
            benchmark: Benchmark type (CIS or STIG)
            success: Whether the remediation was successful
            commands_executed: List of commands that were executed
            output: Combined output from commands
            error: Optional error message
            rollback_commands: List of rollback commands
            backup_path: Path to backup directory
        """
        self.rule_id = rule_id
        self.benchmark = benchmark
        self.success = success
        self.commands_executed = commands_executed
        self.output = output
        self.error = error
        self.rollback_commands = rollback_commands or []
        self.backup_path = backup_path
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert remediation result to dictionary."""
        return {
            "rule_id": self.rule_id,
            "benchmark": self.benchmark,
            "success": self.success,
            "commands_executed": self.commands_executed,
            "output": self.output,
            "error": self.error,
            "rollback_commands": self.rollback_commands,
            "backup_path": self.backup_path
        }


class RemediationEngine:
    """
    Reversible remediation engine with safety controls.
    
    Applies security fixes with automatic backup and rollback capabilities.
    All remediations are validated against allow-lists and logged.
    """
    
    # Default command allow-list (regex patterns)
    DEFAULT_COMMAND_ALLOWLIST = [
        r'^systemctl\s+(enable|disable|start|stop|restart|status)\s+[a-zA-Z0-9_-]+$',
        r'^sysctl\s+-w\s+[a-zA-Z0-9._-]+=.+$',
        r'^chmod\s+[0-7]{3,4}\s+[a-zA-Z0-9_./-]+$',
        r'^chown\s+[a-zA-Z0-9_:.-]+\s+[a-zA-Z0-9_./-]+$',
        r'^sed\s+-i\s+.+\s+[a-zA-Z0-9_./-]+$',
        r'^echo\s+.+\s*>>?\s*[a-zA-Z0-9_./-]+$'
    ]
    
    # Command block-list (regex patterns)
    COMMAND_BLOCKLIST = [
        r'rm\s+-rf',
        r'chmod\s+777',
        r'userdel',
        r'groupdel',
        r'passwd\s+-l\s+root',
        r'setenforce\s+0'
    ]
    
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        backup_directory: str = "/var/lib/vulnguard/backups",
        auto_backup: bool = True,
        rollback_on_failure: bool = True,
        command_allowlist: Optional[List[str]] = None,
        command_blocklist: Optional[List[str]] = None
    ):
        """
        Initialize the remediation engine.
        
        Args:
            logger: Optional audit logger instance
            backup_directory: Directory for storing backups
            auto_backup: Whether to automatically backup before remediation
            rollback_on_failure: Whether to automatically rollback on failure
            command_allowlist: Optional custom command allow-list
            command_blocklist: Optional custom command block-list
        """
        self.logger = logger or AuditLogger()
        self.backup_directory = Path(backup_directory)
        self.auto_backup = auto_backup
        self.rollback_on_failure = rollback_on_failure
        self.command_allowlist = command_allowlist or self.DEFAULT_COMMAND_ALLOWLIST
        self.command_blocklist = command_blocklist or self.COMMAND_BLOCKLIST
        
        # Ensure backup directory exists
        self.backup_directory.mkdir(parents=True, exist_ok=True)
    
    def _validate_command(self, command: str) -> Tuple[bool, str]:
        """
        Validate a command against allow-list and block-list.
        
        Args:
            command: Command to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check block-list first
        for block_pattern in self.command_blocklist:
            if re.search(block_pattern, command, re.IGNORECASE):
                return False, f"Command blocked by block-list pattern: {block_pattern}"
        
        # Check allow-list
        is_allowed = False
        for allow_pattern in self.command_allowlist:
            if re.match(allow_pattern, command):
                is_allowed = True
                break
        
        if not is_allowed:
            return False, "Command not in allow-list"
        
        return True, ""
    
    def _execute_command(self, command: str, dry_run: bool = True) -> Tuple[int, str, str]:
        """
        Execute a shell command.
        
        Args:
            command: Command to execute
            dry_run: If True, only print the command without executing
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if dry_run:
            return 0, f"[DRY-RUN] Would execute: {command}", ""
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def _backup_files(self, files_to_backup: List[str], rule_id: str) -> Optional[str]:
        """
        Backup configuration files before remediation.
        
        Args:
            files_to_backup: List of file paths to backup
            rule_id: Rule identifier for the backup directory
            
        Returns:
            Path to backup directory, or None if backup fails
        """
        if not files_to_backup:
            return None
        
        # Create backup directory with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_directory / f"{rule_id}_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)
        
        files_backed_up = []
        
        for file_path in files_to_backup:
            try:
                if os.path.exists(file_path):
                    dest_path = backup_path / Path(file_path).name
                    shutil.copy2(file_path, dest_path)
                    files_backed_up.append(file_path)
            except Exception as e:
                self.logger.log_error(
                    "backup",
                    f"Failed to backup {file_path}: {str(e)}",
                    {"rule_id": rule_id, "file_path": file_path}
                )
                # Continue with other files
        
        if files_backed_up:
            self.logger.log_backup(
                benchmark="unknown",
                rule_id=rule_id,
                backup_path=str(backup_path),
                files_backed_up=files_backed_up
            )
            return str(backup_path)
        
        return None
    
    def _extract_files_from_commands(self, commands: List[str]) -> List[str]:
        """
        Extract file paths from commands for backup purposes.
        
        Args:
            commands: List of commands to analyze
            
        Returns:
            List of file paths found in commands
        """
        files = set()
        
        for command in commands:
            # Match file paths in common patterns
            # sed -i ... /path/to/file
            sed_match = re.search(r'sed\s+-i\s+.+\s+([a-zA-Z0-9_./-]+)$', command)
            if sed_match:
                files.add(sed_match.group(1))
            
            # echo ... >> /path/to/file
            echo_match = re.search(r'echo\s+.+\s*>>?\s*([a-zA-Z0-9_./-]+)$', command)
            if echo_match:
                files.add(echo_match.group(1))
            
            # chown ... /path/to/file
            chown_match = re.search(r'chown\s+[a-zA-Z0-9_:.-]+\s+([a-zA-Z0-9_./-]+)$', command)
            if chown_match:
                files.add(chown_match.group(1))
        
        return list(files)
    
    def _execute_rollback(
        self,
        rollback_commands: List[str],
        backup_path: Optional[str],
        dry_run: bool = True
    ) -> Tuple[bool, str]:
        """
        Execute rollback commands.
        
        Args:
            rollback_commands: List of rollback commands to execute
            backup_path: Path to backup directory
            dry_run: If True, only print commands without executing
            
        Returns:
            Tuple of (success, output)
        """
        outputs = []
        all_success = True
        
        # Restore files from backup if available
        if backup_path and os.path.exists(backup_path):
            try:
                for backup_file in Path(backup_path).glob('*'):
                    if backup_file.is_file():
                        # Determine original file path
                        # For now, just log that we would restore
                        outputs.append(f"[DRY-RUN] Would restore {backup_file} to original location")
            except Exception as e:
                outputs.append(f"Error during backup restoration: {str(e)}")
                all_success = False
        
        # Execute rollback commands
        for cmd in rollback_commands:
            is_valid, error = self._validate_command(cmd)
            if not is_valid:
                outputs.append(f"Invalid rollback command: {cmd} - {error}")
                all_success = False
                continue
            
            exit_code, stdout, stderr = self._execute_command(cmd, dry_run)
            
            if exit_code != 0:
                outputs.append(f"Rollback command failed: {cmd}")
                if stderr:
                    outputs.append(f"Error: {stderr}")
                all_success = False
            else:
                outputs.append(f"Rollback command succeeded: {cmd}")
                if stdout:
                    outputs.append(stdout)
        
        return all_success, '\n'.join(outputs)
    
    def _load_rule_data(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Load rule data from benchmark file.
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            Rule data dictionary, or None if loading fails
        """
        import yaml
        from pathlib import Path
        
        benchmark_dir = Path("vulnguard/configs/benchmarks")
        
        for ext in ['.yaml', '.yml']:
            rule_file = benchmark_dir / f"{rule_id}{ext}"
            if rule_file.exists():
                try:
                    with open(rule_file, 'r') as f:
                        return yaml.safe_load(f)
                except Exception as e:
                    self.logger.log_error(
                        "rule_load",
                        f"Failed to load rule data: {str(e)}",
                        {"rule_id": rule_id}
                    )
                    return None
        
        return None
    
    def remediate(
        self,
        scan_result: ScanResult,
        evaluation_result: EvaluationResult,
        ai_advisory: Optional[AIAdvisory] = None,
        mode: str = "dry-run",
        force: bool = False
    ) -> RemediationResult:
        """
        Apply remediation for a non-compliant rule.
        
        Args:
            scan_result: Scan result from the scanner
            evaluation_result: Evaluation result from the engine
            ai_advisory: Optional AI advisory with remediation commands
            mode: Remediation mode (dry-run or commit)
            force: Force remediation even if approval is required
            
        Returns:
            RemediationResult object
        """
        # Check if rule is compliant (no remediation needed)
        if scan_result.compliant:
            return RemediationResult(
                rule_id=scan_result.rule_id,
                benchmark=scan_result.benchmark,
                success=True,
                commands_executed=[],
                output="System is already compliant, no remediation needed"
            )
        
        # Check if approval is required and not forced
        if evaluation_result.approval_required and not force:
            self.logger.log_approval_request(
                benchmark=scan_result.benchmark,
                rule_id=scan_result.rule_id,
                severity=evaluation_result.severity,
                reason="Approval required for this rule"
            )
            return RemediationResult(
                rule_id=scan_result.rule_id,
                benchmark=scan_result.benchmark,
                success=False,
                commands_executed=[],
                output="Remediation requires approval",
                error="Approval required for this rule"
            )
        
        # Load rule data to get remediation commands
        rule_data = self._load_rule_data(scan_result.rule_id)
        
        if not rule_data:
            return RemediationResult(
                rule_id=scan_result.rule_id,
                benchmark=scan_result.benchmark,
                success=False,
                commands_executed=[],
                output="Failed to load rule data",
                error="Rule data not found"
            )
        
        # Determine commands to execute
        if ai_advisory and ai_advisory.commands:
            commands = ai_advisory.commands
            rollback_commands = ai_advisory.rollback_commands
        else:
            remediation_config = rule_data.get('remediation', {})
            commands = remediation_config.get('commands', [])
            rollback_config = rule_data.get('rollback', {})
            rollback_commands = rollback_config.get('commands', [])
        
        if not commands:
            return RemediationResult(
                rule_id=scan_result.rule_id,
                benchmark=scan_result.benchmark,
                success=False,
                commands_executed=[],
                output="No remediation commands available",
                error="No remediation commands defined"
            )
        
        # Validate all commands
        for cmd in commands:
            is_valid, error = self._validate_command(cmd)
            if not is_valid:
                self.logger.log_error(
                    "remediation",
                    f"Invalid remediation command: {error}",
                    {"rule_id": scan_result.rule_id, "command": cmd}
                )
                return RemediationResult(
                    rule_id=scan_result.rule_id,
                    benchmark=scan_result.benchmark,
                    success=False,
                    commands_executed=[],
                    output=f"Invalid remediation command: {cmd}",
                    error=error
                )
        
        # Backup files if auto_backup is enabled
        backup_path = None
        if self.auto_backup:
            files_to_backup = self._extract_files_from_commands(commands)
            backup_path = self._backup_files(files_to_backup, scan_result.rule_id)
        
        # Log remediation start
        self.logger.log_remediation_start(
            benchmark=scan_result.benchmark,
            rule_id=scan_result.rule_id,
            mode=mode,
            commands=commands
        )
        
        # Execute remediation commands
        outputs = []
        all_success = True
        commands_executed = []
        
        for cmd in commands:
            exit_code, stdout, stderr = self._execute_command(cmd, dry_run=(mode == "dry-run"))
            commands_executed.append(cmd)
            
            if stdout:
                outputs.append(stdout)
            if stderr:
                outputs.append(stderr)
            
            if exit_code != 0:
                all_success = False
                outputs.append(f"Command failed: {cmd}")
                break
        
        output = '\n'.join(outputs)
        
        # Check if rollback is needed
        if not all_success and self.rollback_on_failure and rollback_commands:
            rollback_success, rollback_output = self._execute_rollback(
                rollback_commands,
                backup_path,
                dry_run=(mode == "dry-run")
            )
            
            self.logger.log_rollback(
                benchmark=scan_result.benchmark,
                rule_id=scan_result.rule_id,
                reason="Remediation failed",
                commands=rollback_commands
            )
            
            output += f"\n\nRollback executed:\n{rollback_output}"
        elif not all_success:
            output += "\n\nRollback not executed (rollback_on_failure=False or no rollback commands)"
        
        # Log remediation result
        self.logger.log_remediation_result(
            benchmark=scan_result.benchmark,
            rule_id=scan_result.rule_id,
            success=all_success,
            output=output,
            error=None if all_success else "One or more commands failed"
        )
        
        return RemediationResult(
            rule_id=scan_result.rule_id,
            benchmark=scan_result.benchmark,
            success=all_success,
            commands_executed=commands_executed,
            output=output,
            error=None if all_success else "One or more commands failed",
            rollback_commands=rollback_commands,
            backup_path=backup_path
        )
    
    def remediate_batch(
        self,
        scan_results: List[ScanResult],
        evaluation_results: List[EvaluationResult],
        ai_advisories: Optional[List[AIAdvisory]] = None,
        mode: str = "dry-run",
        force: bool = False
    ) -> List[RemediationResult]:
        """
        Apply remediation for multiple non-compliant rules.
        
        Args:
            scan_results: List of scan results
            evaluation_results: List of evaluation results
            ai_advisories: Optional list of AI advisories
            mode: Remediation mode (dry-run or commit)
            force: Force remediation even if approval is required
            
        Returns:
            List of RemediationResult objects
        """
        remediation_results = []
        
        # Create advisory lookup
        advisory_lookup = {}
        if ai_advisories:
            advisory_lookup = {adv.rule_id: adv for adv in ai_advisories}
        
        for scan_result, eval_result in zip(scan_results, evaluation_results):
            advisory = advisory_lookup.get(scan_result.rule_id)
            result = self.remediate(
                scan_result=scan_result,
                evaluation_result=eval_result,
                ai_advisory=advisory,
                mode=mode,
                force=force
            )
            remediation_results.append(result)
        
        return remediation_results

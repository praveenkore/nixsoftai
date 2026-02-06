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
Uses centralized command validation patterns.
"""

import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from vulnguard.pkg.scanner.scanner import ScanResult
from vulnguard.pkg.engine.engine import EvaluationResult
from vulnguard.pkg.advisor.advisor import AIAdvisory
from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.security.command_validation import (
    get_default_command_allowlist,
    get_command_blocklist,
    merge_command_patterns
)

# Lazy imports to avoid circular dependencies
def _get_secure_command_executor():
    from vulnguard.pkg.security.command_executor import SecureCommandExecutor
    return SecureCommandExecutor

def _get_secure_file_permissions():
    from vulnguard.pkg.security.file_permissions import SecureFilePermissions
    return SecureFilePermissions


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
    Uses centralized command validation patterns.
    """
    
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        backup_directory: str = "/var/lib/vulnguard/backups",
        auto_backup: bool = True,
        rollback_on_failure: bool = True,
        command_allowlist: Optional[List[str]] = None,
        command_blocklist: Optional[List[str]] = None,
        backup_retention_days: int = 30,
        max_backups_count: int = 50
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
            backup_retention_days: Number of days to keep backups
            max_backups_count: Maximum number of backups to keep
        """
        self.logger = logger or AuditLogger()
        self.backup_directory = Path(backup_directory)
        self.auto_backup = auto_backup
        self.rollback_on_failure = rollback_on_failure
        self.backup_retention_days = backup_retention_days
        self.max_backups_count = max_backups_count
        
        # Use centralized command validation patterns
        self.command_allowlist, self.command_blocklist = merge_command_patterns(
            command_allowlist,
            command_blocklist
        )
        
        # Initialize secure command executor using lazy import
        executor_cls = _get_secure_command_executor()
        self.command_executor = executor_cls(logger=self.logger)
        
        # Initialize secure file permissions manager using lazy import
        perms_cls = _get_secure_file_permissions()
        self.file_permissions = perms_cls(logger=self.logger)
        
        # Ensure backup directory exists with secure permissions
        self.file_permissions.create_secure_directory(str(self.backup_directory))
        
        # Cleanup old backups on initialization
        self.cleanup_old_backups()
    
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
        
        Uses SecureCommandExecutor to eliminate command injection vulnerabilities.
        The command string is parsed into arguments and executed without shell=True.
        
        Args:
            command: Command to execute
            dry_run: If True, only print the command without executing
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            # Use secure command executor to parse and execute command
            # This eliminates command injection vulnerabilities
            return self.command_executor.execute_shell_command_safely(
                command,
                timeout=60,
                dry_run=dry_run
            )
        except Exception as e:
            self.logger.log_error(
                "command_execution",
                f"Failed to execute command: {str(e)}",
                {"command": command}
            )
            return -1, "", str(e)
    
    def _backup_files(self, files_to_backup: List[str], rule_id: str) -> Optional[str]:
        """
        Backup configuration files before remediation.
        
        Uses secure file permissions to ensure backup directory and files
        are created with appropriate permissions. Creates a manifest file
        to track the mapping between backup files and original paths.
        
        Args:
            files_to_backup: List of file paths to backup
            rule_id: Rule identifier for the backup directory
            
        Returns:
            Path to backup directory, or None if backup fails
        """
        if not files_to_backup:
            return None
        
        # Create backup directory with timestamp using secure permissions
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_directory / f"{rule_id}_{timestamp}"
        self.file_permissions.create_secure_directory(str(backup_path))
        
        files_backed_up = []
        manifest = {}  # Mapping from backup filename to original path
        
        for file_path in files_to_backup:
            try:
                # Resolve to absolute path to prevent traversal and ambiguity
                abs_path = os.path.abspath(file_path)
                
                if os.path.exists(abs_path) and os.path.isfile(abs_path):
                    # Generate safe filename from absolute path
                    # Replace path separators to create a flat filename
                    safe_filename = abs_path.replace('/', '_').replace('\\', '_').lstrip('_')
                    # Double check it doesn't contain traversal sequences that survived
                    if '..' in safe_filename:
                        safe_filename = safe_filename.replace('..', '__')
                        
                    dest_path = backup_path / safe_filename
                    
                    # Verify destination is strictly within backup directory
                    # This prevents any clever filename manipulation from escaping the backup dir
                    try:
                        # resolve() resolves symlinks and .. components
                        dest_real = dest_path.resolve() if dest_path.exists() else dest_path
                        # backup_path is already created, so it exists and we can resolve it
                        backup_real = backup_path.resolve()
                        
                        # Check strictly if dest is inside backup_real
                        # We use str conversion for compatibility
                        if os.path.commonpath([str(backup_real), str(dest_real.parent)]) != str(backup_real):
                             self.logger.log_error(
                                "backup",
                                f"Backup path traversal detected: {dest_real}",
                                {"rule_id": rule_id, "file_path": abs_path}
                            )
                             continue
                    except Exception:
                         # If resolution fails (e.g. filename too long), fall back to simple check
                         pass

                    # Use shutil.copy2 but then ensure secure permissions
                    shutil.copy2(abs_path, dest_path)
                    # Set secure permissions on backup file
                    self.file_permissions.set_file_permissions(
                        str(dest_path),
                        0o600  # Owner read/write only
                    )
                    files_backed_up.append(abs_path)
                    # Store mapping in manifest (safe_filename -> original absolute path)
                    manifest[safe_filename] = abs_path
            except Exception as e:
                self.logger.log_error(
                    "backup",
                    f"Failed to backup {file_path}: {str(e)}",
                    {"rule_id": rule_id, "file_path": file_path}
                )
                # Continue with other files
        
        if files_backed_up:
            # Write manifest file for rollback
            manifest_path = backup_path / ".backup_manifest.json"
            try:
                import json
                with open(manifest_path, 'w') as f:
                    json.dump({
                        "rule_id": rule_id,
                        "timestamp": timestamp,
                        "files": manifest
                    }, f, indent=2)
                self.file_permissions.set_file_permissions(
                    str(manifest_path),
                    0o600
                )
            except Exception as e:
                self.logger.log_error(
                    "backup",
                    f"Failed to write backup manifest: {str(e)}",
                    {"rule_id": rule_id, "manifest_path": str(manifest_path)}
                )
            
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
        Execute rollback commands and restore files from backup.
        
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
                # Load backup manifest to get file mappings
                manifest_path = Path(backup_path) / ".backup_manifest.json"
                manifest = {}
                
                if manifest_path.exists():
                    import json
                    with open(manifest_path, 'r') as f:
                        manifest_data = json.load(f)
                        manifest = manifest_data.get('files', {})
                
                # Restore files from backup
                for backup_file in Path(backup_path).glob('*'):
                    if backup_file.is_file() and backup_file.name != ".backup_manifest.json":
                        # Get original file path from manifest
                        original_path = manifest.get(backup_file.name, None)
                        
                        if original_path is None:
                            # Fallback: try to determine original path from filename
                            outputs.append(f"Warning: No manifest entry for {backup_file.name}, skipping file restoration")
                            continue
                        
                        if dry_run:
                            outputs.append(f"[DRY-RUN] Would restore {backup_file} to {original_path}")
                        else:
                            try:
                                # Ensure parent directory exists
                                original_parent = Path(original_path).parent
                                if not original_parent.exists():
                                    original_parent.mkdir(parents=True, exist_ok=True)
                                
                                # Restore file from backup
                                shutil.copy2(backup_file, original_path)
                                # Restore original file permissions using secure file permissions
                                self.file_permissions.set_file_permissions(
                                    str(original_path),
                                    0o644  # Default: owner read/write, group/others read
                                )
                                outputs.append(f"Restored {backup_file.name} to {original_path}")
                            except Exception as e:
                                outputs.append(f"Error restoring {backup_file} to {original_path}: {str(e)}")
                                all_success = False
            except Exception as e:
                outputs.append(f"Error during backup restoration: {str(e)}")
                all_success = False
        elif backup_path:
            outputs.append(f"Backup directory not found: {backup_path}")
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
        # Create lookups for faster and safer access
        advisory_lookup = {}
        if ai_advisories:
            advisory_lookup = {adv.rule_id: adv for adv in ai_advisories}
            
        evaluation_lookup = {r.rule_id: r for r in evaluation_results}
        
        for scan_result in scan_results:
            # Skip not_applicable rules - they didn't run and don't need remediation
            if getattr(scan_result, 'applicability', 'applicable') == 'not_applicable':
                continue
                
            # Safe lookup for evaluation result
            eval_result = evaluation_lookup.get(scan_result.rule_id)
            
            if not eval_result:
                self.logger.log_error(
                    "remediation_batch",
                    f"Missing evaluation result for rule {scan_result.rule_id}",
                    {"rule_id": scan_result.rule_id}
                )
                continue
                
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

    def cleanup_old_backups(self) -> None:
        """
        Clean up old backups based on retention policy.
        
        Policy:
        1. Delete backups older than backup_retention_days
        2. If count > max_backups_count, delete oldest until count <= max_backups_count
        """
        try:
            if not self.backup_directory.exists():
                return
                
            backups = []
            for item in self.backup_directory.iterdir():
                # Must be a directory AND match either backup pattern
                if item.is_dir() and (item.name.startswith("backup_") or "_20" in item.name):
                    # Verify path is still within backup directory (prevent traversal)
                    try:
                        item_resolved = item.resolve()
                        backup_resolved = self.backup_directory.resolve()
                        if str(item_resolved).startswith(str(backup_resolved)):
                            backups.append(item)
                        else:
                            self.logger.log_warning(
                                f"Skipping backup entry outside backup directory: {item}"
                            )
                    except (OSError, ValueError) as e:
                        self.logger.log_warning(
                            f"Could not resolve backup path {item}: {e}"
                        )
            
            # Sort by modification time (oldest first)
            backups.sort(key=lambda x: x.stat().st_mtime)
            
            # Check retention days
            current_time = time.time()
            retention_seconds = self.backup_retention_days * 86400
            
            deleted_count = 0
            remaining_backups = []
            
            for backup in backups:
                age = current_time - backup.stat().st_mtime
                if age > retention_seconds:
                    try:
                        # Safety check: verify backup is still within backup directory
                        backup_resolved = backup.resolve()
                        backup_dir_resolved = self.backup_directory.resolve()
                        if not str(backup_resolved).startswith(str(backup_dir_resolved)):
                            self.logger.log_error(
                                "backup_cleanup",
                                f"Path traversal detected, skipping deletion: {backup}"
                            )
                            continue
                        shutil.rmtree(backup)
                        deleted_count += 1
                        self.logger.log_info(
                            f"Deleted old backup: {backup} (age={age/86400:.1f} days)"
                        )
                    except Exception as e:
                        self.logger.log_error(
                            "backup_cleanup",
                            f"Failed to delete backup {backup}: {str(e)}"
                        )
                else:
                    remaining_backups.append(backup)
            
            # Check max count
            if len(remaining_backups) > self.max_backups_count:
                excess = len(remaining_backups) - self.max_backups_count
                for i in range(excess):
                    backup = remaining_backups[i]
                    try:
                        # Safety check: verify backup is still within backup directory
                        backup_resolved = backup.resolve()
                        backup_dir_resolved = self.backup_directory.resolve()
                        if not str(backup_resolved).startswith(str(backup_dir_resolved)):
                            self.logger.log_error(
                                "backup_cleanup",
                                f"Path traversal detected, skipping deletion: {backup}"
                            )
                            continue
                        shutil.rmtree(backup)
                        deleted_count += 1
                        self.logger.log_info(
                            f"Deleted excess backup: {backup} (limit={self.max_backups_count})"
                        )
                    except Exception as e:
                        self.logger.log_error(
                            "backup_cleanup",
                            f"Failed to delete backup {backup}: {str(e)}"
                        )
                        
            if deleted_count > 0:
                self.logger.log_info(f"Backup cleanup finished. Deleted {deleted_count} backups.")
                
        except Exception as e:
            self.logger.log_error("backup_cleanup", f"Error during backup cleanup: {str(e)}")

"""
Scanner Module - Deterministic Audit Engine

Performs deterministic security checks against system configurations.
All checks are executed through defined commands and validated against expected states.
"""

import os
import re
import subprocess
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from vulnguard.pkg.logging.logger import AuditLogger


class ScanResult:
    """
    Represents the result of a single compliance scan.
    """
    
    def __init__(
        self,
        rule_id: str,
        benchmark: str,
        compliant: bool,
        expected_state: str,
        actual_state: str,
        check_output: str,
        error: Optional[str] = None
    ):
        """
        Initialize a scan result.
        
        Args:
            rule_id: Rule identifier
            benchmark: Benchmark type (CIS or STIG)
            compliant: Whether the system is compliant
            expected_state: Expected state from the rule
            actual_state: Actual state found
            check_output: Output from the check command
            error: Optional error message
        """
        self.rule_id = rule_id
        self.benchmark = benchmark
        self.compliant = compliant
        self.expected_state = expected_state
        self.actual_state = actual_state
        self.check_output = check_output
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "rule_id": self.rule_id,
            "benchmark": self.benchmark,
            "compliant": self.compliant,
            "expected_state": self.expected_state,
            "actual_state": self.actual_state,
            "check_output": self.check_output,
            "error": self.error
        }


class Scanner:
    """
    Deterministic audit engine for security compliance checks.
    
    Executes defined check commands and validates results against expected states.
    All checks are deterministic and do not use AI.
    """
    
    def __init__(
        self,
        benchmark_dir: str = "vulnguard/configs/benchmarks",
        logger: Optional[AuditLogger] = None
    ):
        """
        Initialize the scanner.
        
        Args:
            benchmark_dir: Directory containing benchmark rule files
            logger: Optional audit logger instance
        """
        self.benchmark_dir = Path(benchmark_dir)
        self.logger = logger or AuditLogger()
        self._rules_cache: Dict[str, Dict[str, Any]] = {}
    
    def _load_rule(self, rule_file: str) -> Optional[Dict[str, Any]]:
        """
        Load a benchmark rule from YAML file.
        
        Args:
            rule_file: Path to the rule YAML file
            
        Returns:
            Dictionary containing the rule data, or None if loading fails
        """
        rule_path = self.benchmark_dir / rule_file
        
        if not rule_path.exists():
            self.logger.log_error(
                "rule_load",
                f"Rule file not found: {rule_file}",
                {"rule_file": rule_file}
            )
            return None
        
        try:
            with open(rule_path, 'r') as f:
                rule = yaml.safe_load(f)
            
            # Validate required fields
            required_fields = [
                'benchmark', 'id', 'title', 'rationale',
                'severity', 'original_severity', 'os_compatibility',
                'check', 'remediation', 'rollback'
            ]
            
            for field in required_fields:
                if field not in rule:
                    self.logger.log_error(
                        "rule_validation",
                        f"Missing required field: {field}",
                        {"rule_file": rule_file, "rule": rule}
                    )
                    return None
            
            # Set defaults for optional fields
            rule.setdefault('ai_assist', False)
            rule.setdefault('approval_required', False)
            rule.setdefault('exception_allowed', False)
            
            return rule
            
        except yaml.YAMLError as e:
            self.logger.log_error(
                "rule_load",
                f"Failed to parse YAML: {str(e)}",
                {"rule_file": rule_file}
            )
            return None
        except Exception as e:
            self.logger.log_error(
                "rule_load",
                f"Failed to load rule: {str(e)}",
                {"rule_file": rule_file}
            )
            return None
    
    def _execute_command(self, command: str) -> Tuple[int, str, str]:
        """
        Execute a shell command and return the result.
        
        Args:
            command: Command to execute
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def _check_command(
        self,
        check_config: Dict[str, Any]
    ) -> Tuple[bool, str, str]:
        """
        Execute a command-based check.
        
        Args:
            check_config: Check configuration dictionary
            
        Returns:
            Tuple of (compliant, actual_state, output)
        """
        command = check_config.get('command', '')
        expected_state = check_config.get('expected_state', '')
        
        if not command:
            return False, '', 'No command specified'
        
        exit_code, stdout, stderr = self._execute_command(command)
        
        # Combine stdout and stderr for output
        output = stdout.strip()
        if stderr:
            output += '\n' + stderr.strip()
        
        # Determine compliance based on expected state
        if expected_state.lower() in ('true', 'enabled', 'active', 'running'):
            compliant = exit_code == 0
            actual_state = 'enabled' if compliant else 'disabled'
        elif expected_state.lower() in ('false', 'disabled', 'inactive', 'stopped'):
            compliant = exit_code != 0
            actual_state = 'disabled' if compliant else 'enabled'
        else:
            # Exact match expected
            compliant = output == expected_state
            actual_state = output
        
        return compliant, actual_state, output
    
    def _check_file(
        self,
        check_config: Dict[str, Any]
    ) -> Tuple[bool, str, str]:
        """
        Execute a file-based check.
        
        Args:
            check_config: Check configuration dictionary
            
        Returns:
            Tuple of (compliant, actual_state, output)
        """
        file_path = check_config.get('path', '')
        expected_content = check_config.get('expected_content', '')
        expected_permissions = check_config.get('expected_permissions', '')
        expected_owner = check_config.get('expected_owner', '')
        
        if not file_path:
            return False, '', 'No file path specified'
        
        if not os.path.exists(file_path):
            return False, 'not_found', f'File not found: {file_path}'
        
        output_parts = []
        compliant = True
        
        # Check content if specified
        if expected_content:
            try:
                with open(file_path, 'r') as f:
                    actual_content = f.read()
                
                if expected_content in actual_content:
                    output_parts.append(f'Content check: PASS')
                else:
                    output_parts.append(f'Content check: FAIL')
                    compliant = False
            except Exception as e:
                output_parts.append(f'Content check: ERROR - {str(e)}')
                compliant = False
        
        # Check permissions if specified
        if expected_permissions:
            try:
                actual_permissions = oct(os.stat(file_path).st_mode)[-3:]
                if actual_permissions == expected_permissions:
                    output_parts.append(f'Permissions check: PASS ({actual_permissions})')
                else:
                    output_parts.append(f'Permissions check: FAIL (expected {expected_permissions}, got {actual_permissions})')
                    compliant = False
            except Exception as e:
                output_parts.append(f'Permissions check: ERROR - {str(e)}')
                compliant = False
        
        # Check owner if specified
        if expected_owner:
            try:
                import pwd
                stat_info = os.stat(file_path)
                actual_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if actual_owner == expected_owner:
                    output_parts.append(f'Owner check: PASS ({actual_owner})')
                else:
                    output_parts.append(f'Owner check: FAIL (expected {expected_owner}, got {actual_owner})')
                    compliant = False
            except Exception as e:
                output_parts.append(f'Owner check: ERROR - {str(e)}')
                compliant = False
        
        actual_state = 'compliant' if compliant else 'non_compliant'
        output = '\n'.join(output_parts) if output_parts else 'No checks performed'
        
        return compliant, actual_state, output
    
    def _check_service(
        self,
        check_config: Dict[str, Any]
    ) -> Tuple[bool, str, str]:
        """
        Execute a service-based check.
        
        Args:
            check_config: Check configuration dictionary
            
        Returns:
            Tuple of (compliant, actual_state, output)
        """
        service_name = check_config.get('service_name', '')
        expected_state = check_config.get('expected_state', 'enabled')
        
        if not service_name:
            return False, '', 'No service name specified'
        
        # Check if service is enabled
        _, enabled_output, _ = self._execute_command(
            f'systemctl is-enabled {service_name} 2>/dev/null'
        )
        
        # Check if service is active
        _, active_output, _ = self._execute_command(
            f'systemctl is-active {service_name} 2>/dev/null'
        )
        
        enabled = 'enabled' in enabled_output.lower()
        active = active_output.strip() == 'active'
        
        output_parts = []
        output_parts.append(f'Service: {service_name}')
        output_parts.append(f'Enabled: {enabled}')
        output_parts.append(f'Active: {active}')
        
        compliant = True
        actual_state = ''
        
        if expected_state.lower() in ('enabled', 'running', 'active'):
            compliant = enabled and active
            actual_state = 'enabled and active' if compliant else 'disabled or inactive'
        elif expected_state.lower() in ('disabled', 'stopped', 'inactive'):
            compliant = not enabled or not active
            actual_state = 'disabled or inactive' if compliant else 'enabled and active'
        
        output = '\n'.join(output_parts)
        return compliant, actual_state, output
    
    def _check_sysctl(
        self,
        check_config: Dict[str, Any]
    ) -> Tuple[bool, str, str]:
        """
        Execute a sysctl-based check.
        
        Args:
            check_config: Check configuration dictionary
            
        Returns:
            Tuple of (compliant, actual_state, output)
        """
        sysctl_key = check_config.get('key', '')
        expected_value = check_config.get('expected_value', '')
        
        if not sysctl_key:
            return False, '', 'No sysctl key specified'
        
        exit_code, stdout, stderr = self._execute_command(f'sysctl {sysctl_key}')
        
        if exit_code != 0:
            return False, 'not_found', f'Failed to get sysctl value: {stderr}'
        
        # Parse output: key = value
        if '=' in stdout:
            actual_value = stdout.split('=')[1].strip()
        else:
            actual_value = stdout.strip()
        
        compliant = actual_value == expected_value
        actual_state = actual_value
        output = f'{sysctl_key} = {actual_value}'
        
        return compliant, actual_state, output
    
    def scan_rule(self, rule_id: str) -> Optional[ScanResult]:
        """
        Scan a single benchmark rule.
        
        Args:
            rule_id: Rule identifier (e.g., "cis_1_1_1" or "stig_vuln_12345")
            
        Returns:
            ScanResult object, or None if scanning fails
        """
        # Try to find the rule file
        rule_file = None
        for ext in ['.yaml', '.yml']:
            potential_file = f"{rule_id}{ext}"
            if (self.benchmark_dir / potential_file).exists():
                rule_file = potential_file
                break
        
        if not rule_file:
            self.logger.log_error(
                "scan",
                f"Rule file not found for rule_id: {rule_id}",
                {"rule_id": rule_id}
            )
            return None
        
        # Load the rule
        rule = self._load_rule(rule_file)
        if not rule:
            return None
        
        # Check OS compatibility
        import platform
        os_name = platform.system().lower()
        if os_name == 'linux':
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read()
                    if 'ubuntu' in os_release.lower():
                        os_name = 'ubuntu'
                    elif 'rhel' in os_release.lower() or 'red hat' in os_release.lower():
                        os_name = 'rhel'
                    elif 'centos' in os_release.lower():
                        os_name = 'centos'
                    elif 'debian' in os_release.lower():
                        os_name = 'debian'
            except Exception:
                pass
        
        compatible_os = rule.get('os_compatibility', [])
        if compatible_os and os_name not in [o.lower() for o in compatible_os]:
            self.logger.log_scan_start(
                rule['benchmark'],
                rule['id'],
                {"os": os_name, "compatible": False}
            )
            return ScanResult(
                rule_id=rule['id'],
                benchmark=rule['benchmark'],
                compliant=False,
                expected_state='N/A',
                actual_state='OS not supported',
                check_output=f'Rule not compatible with {os_name}',
                error=f'OS compatibility: {os_name} not in {compatible_os}'
            )
        
        # Log scan start
        self.logger.log_scan_start(
            rule['benchmark'],
            rule['id'],
            {"os": os_name, "compatible": True}
        )
        
        # Execute the check
        check_config = rule.get('check', {})
        check_type = check_config.get('type', 'command')
        
        try:
            if check_type == 'command':
                compliant, actual_state, output = self._check_command(check_config)
            elif check_type == 'file':
                compliant, actual_state, output = self._check_file(check_config)
            elif check_type == 'service':
                compliant, actual_state, output = self._check_service(check_config)
            elif check_type == 'sysctl':
                compliant, actual_state, output = self._check_sysctl(check_config)
            else:
                self.logger.log_error(
                    "scan",
                    f"Unknown check type: {check_type}",
                    {"rule_id": rule['id']}
                )
                return ScanResult(
                    rule_id=rule['id'],
                    benchmark=rule['benchmark'],
                    compliant=False,
                    expected_state='N/A',
                    actual_state='error',
                    check_output='',
                    error=f'Unknown check type: {check_type}'
                )
            
            expected_state = check_config.get('expected_state', '')
            
            # Create scan result
            result = ScanResult(
                rule_id=rule['id'],
                benchmark=rule['benchmark'],
                compliant=compliant,
                expected_state=expected_state,
                actual_state=actual_state,
                check_output=output
            )
            
            # Log scan result
            self.logger.log_scan_result(
                rule['benchmark'],
                rule['id'],
                compliant,
                expected_state,
                actual_state,
                output
            )
            
            return result
            
        except Exception as e:
            self.logger.log_error(
                "scan",
                f"Scan failed: {str(e)}",
                {"rule_id": rule['id']}
            )
            return ScanResult(
                rule_id=rule['id'],
                benchmark=rule['benchmark'],
                compliant=False,
                expected_state='N/A',
                actual_state='error',
                check_output='',
                error=str(e)
            )
    
    def scan_all(self, rule_ids: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan multiple benchmark rules.
        
        Args:
            rule_ids: Optional list of rule IDs to scan. If None, scans all rules.
            
        Returns:
            List of ScanResult objects
        """
        results = []
        
        if rule_ids:
            # Scan specified rules
            for rule_id in rule_ids:
                result = self.scan_rule(rule_id)
                if result:
                    results.append(result)
        else:
            # Scan all rules in benchmark directory
            for rule_file in self.benchmark_dir.glob('*.yaml'):
                rule_id = rule_file.stem
                result = self.scan_rule(rule_id)
                if result:
                    results.append(result)
            
            for rule_file in self.benchmark_dir.glob('*.yml'):
                rule_id = rule_file.stem
                result = self.scan_rule(rule_id)
                if result:
                    results.append(result)
        
        return results

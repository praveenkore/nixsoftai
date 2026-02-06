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
Scanner Module - Deterministic Audit Engine

Performs deterministic security checks against system configurations.
All checks are executed through defined commands and validated against expected states.
"""

import os
import re
import subprocess
import shlex
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import jsonschema
from vulnguard.pkg.logging.logger import AuditLogger

# Rule Schema Definition
# Supports both legacy format (check/remediation/rollback at root level)
# and canonical format (implementations map with OS family-specific check/remediation/rollback)
RULE_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "benchmark": {"type": "string"},
        "title": {"type": "string"},
        "rationale": {"type": "string"},
        "severity": {"type": "string"},
        "original_severity": {"type": "string"},
        "stig_id": {"type": "string"},
        "cci": {"type": "string"},
        "srg": {"type": "string"},
        "os_compatibility": {"type": "array", "items": {"type": "string"}},
        # Legacy format: check/remediation/rollback at root level
        "check": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["command", "file", "service", "sysctl"]},
                # Legacy: command as string, Canonical: command as list
                "command": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "expected_state": {"type": "string"},
                "path": {"type": "string"},
                "pattern": {"type": "string"},  # Canonical: pattern to search in file
                "expected_content": {"type": "string"},
                "expected_permissions": {"type": "string"},
                "expected_owner": {"type": "string"},
                # Legacy: service_name, Canonical: service
                "service_name": {"type": "string"},
                "service": {"type": "string"},
                # Legacy: key, Canonical: sysctl
                "key": {"type": "string"},
                "sysctl": {"type": "string"},
                "expected_value": {"type": "string"},
                "expected_type": {"type": "string", "enum": ["string", "integer", "boolean"]},
                "description": {"type": "string"}
            },
            "required": ["type"]
        },
        "remediation": {
            "type": "object",
            "properties": {
                "commands": {"type": "array", "items": {"type": "string"}},
                "requires_restart": {"type": "boolean"},
                "requires_reboot": {"type": "boolean"},
                "description": {"type": "string"},
                "service_restart": {"type": "string"}
            }
        },
        "rollback": {
            "type": "object",
            "properties": {
                "commands": {"type": "array", "items": {"type": "string"}},
                "description": {"type": "string"},
                "service_restart": {"type": "string"},
                "requires_reboot": {"type": "boolean"}
            }
        },
        # Canonical format: implementations map with OS family-specific implementations
        "implementations": {
            "type": "object",
            "patternProperties": {
                "^(rhel_family|debian_family)$": {
                    "type": "object",
                    "properties": {
                        "os": {"type": "array", "items": {"type": "string"}},
                        "check": {"type": "object"},
                        "remediation": {"type": "object"},
                        "rollback": {"type": "object"}
                    },
                    "required": ["os", "check"]
                }
            }
        },
        "ai_assist": {"type": "boolean"},
        "approval_required": {"type": "boolean"},
        "exception_allowed": {"type": "boolean"}
    },
    "oneOf": [
        # Legacy format: check, remediation, rollback at root level
        {
            "required": ["id", "benchmark", "title", "rationale", "severity", "check", "remediation", "rollback"]
        },
        # Canonical format: implementations map present
        {
            "required": ["id", "benchmark", "title", "rationale", "severity", "implementations"]
        }
    ]
}

# OS Family Mapping
# Maps base OS distributions to their compatible variants based on ID_LIKE relationships.
# This allows rules targeting RHEL to work on RHEL-compatible distributions (CentOS, AlmaLinux, Rocky).
# Similarly, Debian-based systems (Ubuntu) share compatibility.
OS_FAMILY_MAP = {
    "rhel": ["rhel", "red hat", "centos", "almalinux", "rocky"],
    "debian": ["debian", "ubuntu"],
}


def _parse_os_release() -> Tuple[Optional[str], Optional[str]]:
    """
    Parse /etc/os-release to detect OS ID and ID_LIKE fields.
    
    This function properly parses the /etc/os-release file following the
    freedesktop.org standard to extract the ID and ID_LIKE fields.
    The ID_LIKE field contains a space-separated list of OS families that
    this distribution is compatible with (e.g., AlmaLinux has ID_LIKE="rhel centos").
    
    Returns:
        Tuple of (detected_os, os_family) where:
        - detected_os: The normalized OS ID from the ID field (lowercase)
        - os_family: The primary OS family from ID_LIKE (lowercase)
        
    Note:
        - Returns (None, None) if /etc/os-release doesn't exist or parsing fails
        - detected_os is normalized to lowercase for consistency
        - os_family is the first entry in ID_LIKE space-separated list
    """
    try:
        with open('/etc/os-release', 'r') as f:
            os_release = f.read()
        
        detected_os = None
        os_family = None
        
        # Parse ID field - the primary distribution identifier
        for line in os_release.splitlines():
            if line.startswith('ID='):
                # Remove quotes and normalize to lowercase
                detected_os = line.split('=', 1)[1].strip().strip('"\'').lower()
                break
        
        # Parse ID_LIKE field - space-separated list of compatible OS families
        for line in os_release.splitlines():
            if line.startswith('ID_LIKE='):
                # Get the value, remove quotes, split by space
                id_like_value = line.split('=', 1)[1].strip().strip('"\'')
                # Get first family in the list (most specific)
                if id_like_value:
                    os_family = id_like_value.split()[0].lower()
                break
        
        return detected_os, os_family
        
    except FileNotFoundError:
        return None, None
    except Exception:
        return None, None


def _get_os_family(detected_os: Optional[str]) -> Optional[str]:
    """
    Get the OS family for a detected OS using OS_FAMILY_MAP.
    
    This function maps a detected OS (from ID field or fallback detection)
    to its primary OS family. For example, "almalinux" maps to "rhel".
    
    Args:
        detected_os: The detected OS identifier (lowercase)
        
    Returns:
        The OS family identifier (lowercase), or None if not found
        
    Example:
        >>> _get_os_family("almalinux")
        "rhel"
        >>> _get_os_family("ubuntu")
        "debian"
        >>> _get_os_family("unknown")
        None
    """
    if not detected_os:
        return None
    
    for family, variants in OS_FAMILY_MAP.items():
        if detected_os in variants:
            return family
    
    # If no family found, return the detected_os itself
    # This maintains backward compatibility for OS not in the map
    return detected_os


def _is_os_compatible(detected_os: str, os_family: Optional[str], compatible_os: List[str]) -> bool:
    """
    Check if the detected OS is compatible with the rule's OS compatibility list.
    
    This function performs a comprehensive compatibility check:
    1. Checks if detected_os directly matches any OS in the rule's list
    2. Checks if os_family matches any OS in the rule's list (family-based compatibility)
    
    This allows rules targeting "rhel" to work on RHEL-compatible distributions
    like AlmaLinux, Rocky Linux, and CentOS without modifying rule files.
    
    Args:
        detected_os: The detected OS identifier (lowercase)
        os_family: The OS family identifier (lowercase), or None
        compatible_os: List of OS identifiers from the rule's os_compatibility field
        
    Returns:
        True if the OS is compatible, False otherwise
        
    Example:
        >>> _is_os_compatible("almalinux", "rhel", ["rhel"])
        True
        >>> _is_os_compatible("rocky", "rhel", ["rhel", "centos"])
        True
        >>> _is_os_compatible("ubuntu", "debian", ["debian"])
        True
        >>> _is_os_compatible("fedora", None, ["rhel"])
        False
    """
    if not compatible_os:
        # No OS restrictions - rule is compatible with all systems
        return True
    
    # Normalize rule OS list to lowercase for case-insensitive comparison
    rule_os_list = [o.lower() for o in compatible_os]
    
    # Direct match with detected OS (maintains backward compatibility)
    if detected_os in rule_os_list:
        return True
    
    # Family-based match (new feature for RHEL/Debian families)
    if os_family and os_family in rule_os_list:
        return True
    
    return False


def _select_os_family_implementation(
    rule: Dict[str, Any],
    os_name: str,
    os_family: Optional[str]
) -> Optional[Dict[str, Any]]:
    """
    Select the appropriate OS family implementation from canonical rule format.

    For canonical format rules with 'implementations' map, this function selects
    the implementation that matches the detected OS family.

    Args:
        rule: Rule dictionary
        os_name: Detected OS name (e.g., "almalinux", "ubuntu")
        os_family: Detected OS family (e.g., "rhel", "debian")

    Returns:
        Selected implementation dictionary, or None if not found

    Examples:
        >>> rule = {
        ...     "implementations": {
        ...         "rhel_family": {"os": ["rhel", "almalinux"], "check": {...}},
        ...         "debian_family": {"os": ["debian", "ubuntu"], "check": {...}}
        ...     }
        ... }
        >>> _select_os_family_implementation(rule, "almalinux", "rhel")
        {"os": ["rhel", "almalinux"], "check": {...}}

        >>> _select_os_family_implementation(rule, "ubuntu", "debian")
        {"os": ["debian", "ubuntu"], "check": {...}}
    """
    # Check if rule uses canonical format with implementations map
    implementations = rule.get('implementations')
    if not implementations:
        # Legacy format - no OS-specific implementation needed
        return None

    # If OS family is determined, try to match canonical family names
    if os_family == 'rhel':
        family_key = 'rhel_family'
    elif os_family == 'debian':
        family_key = 'debian_family'
    else:
        # Unknown OS family - try to determine from OS name
        if os_name in ['rhel', 'red hat', 'centos', 'almalinux', 'rocky']:
            family_key = 'rhel_family'
        elif os_name in ['debian', 'ubuntu']:
            family_key = 'debian_family'
        else:
            # No matching family
            return None

    # Select implementation for the family
    implementation = implementations.get(family_key)
    if not implementation:
        # No implementation for this OS family
        return None

    # Verify OS is in the implementation's OS list
    compatible_os_list = implementation.get('os', [])
    if compatible_os_list and os_name not in compatible_os_list:
        # OS not in compatible list for this family implementation
        return None

    return implementation


# Lazy import to avoid circular dependency
def _get_secure_command_executor():
    from vulnguard.pkg.security.command_executor import SecureCommandExecutor
    return SecureCommandExecutor


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
        error: Optional[str] = None,
        status: str = "checked",
        applicability: str = "applicable"
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
            status: Execution status of the rule. Valid values:
                - "checked": Rule was executed (compliant or not compliant)
                - "skipped_os": Rule skipped due to OS incompatibility
                - "skipped_manual": Rule manually disabled in configuration
                - "not_applicable": Rule not applicable for other reasons
                Default: "checked"
            applicability: Applicability of the rule. Valid values:
                - "applicable": Rule ran and was evaluated
                - "not_applicable": Rule skipped due to OS incompatibility
                Default: "applicable"
        """
        self.rule_id = rule_id
        self.benchmark = benchmark
        self.compliant = compliant
        self.expected_state = expected_state
        self.actual_state = actual_state
        self.check_output = check_output
        self.error = error
        self.status = status
        self.applicability = applicability
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "rule_id": self.rule_id,
            "benchmark": self.benchmark,
            "compliant": self.compliant,
            "expected_state": self.expected_state,
            "actual_state": self.actual_state,
            "check_output": self.check_output,
            "error": self.error,
            "status": self.status,
            "applicability": self.applicability
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
        logger: Optional[AuditLogger] = None,
        max_workers: int = 4,
        command_timeout: int = 30
    ):
        """
        Initialize the scanner.
        
        Args:
            benchmark_dir: Directory containing benchmark rule files
            logger: Optional audit logger instance
            max_workers: Maximum number of threads for parallel scanning
            command_timeout: Timeout for command execution in seconds (default: 30)
        """
        self.benchmark_dir = Path(benchmark_dir)
        self.logger = logger or AuditLogger()
        self.max_workers = max_workers
        self.command_timeout = command_timeout
        self._rules_cache: Dict[str, Dict[str, Any]] = {}
        # Initialize secure command executor using lazy import
        executor_cls = _get_secure_command_executor()
        self.command_executor = executor_cls(logger=self.logger)
    
    def _load_rule(self, rule_file: str) -> Optional[Dict[str, Any]]:
        """
        Load a benchmark rule from YAML file with caching.
        
        Args:
            rule_file: Path to the rule YAML file
            
        Returns:
            Dictionary containing the rule data, or None if loading fails
        """
        # Check cache first
        if rule_file in self._rules_cache:
            return self._rules_cache[rule_file]
            
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
            
            # Validate against schema
            try:
                jsonschema.validate(instance=rule, schema=RULE_SCHEMA)
            except jsonschema.ValidationError as e:
                self.logger.log_error(
                    "rule_validation",
                    f"Rule schema validation failed: {str(e)}",
                    {"rule_file": rule_file, "path": list(e.path)}
                )
                return None
            
            # Set defaults for optional fields
            rule.setdefault('ai_assist', False)
            rule.setdefault('approval_required', False)
            rule.setdefault('exception_allowed', False)
            
            # Cache the successfully loaded rule
            self._rules_cache[rule_file] = rule
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

    # ... (skipping unchanged methods) ...

    def scan_all(self, rule_ids: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan multiple benchmark rules in parallel.
        
        Args:
            rule_ids: Optional list of rule IDs to scan. If None, scans all rules.
            
        Returns:
            List of ScanResult objects
        """
        target_rule_ids = []
        
        if rule_ids:
            target_rule_ids = rule_ids
        else:
            # Find all rules
            for ext in ['*.yaml', '*.yml']:
                for rule_file in self.benchmark_dir.glob(ext):
                    target_rule_ids.append(rule_file.stem)
        
        if not target_rule_ids:
            return []
            
        # Deduplicate ids
        target_rule_ids = list(set(target_rule_ids))
        
        results = []
        import concurrent.futures
        
        # Use ThreadPoolExecutor for parallel scanning
        # Most checks are I/O bound (subprocess calls), so threads are efficient
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_rule = {
                executor.submit(self.scan_rule, rule_id): rule_id 
                for rule_id in target_rule_ids
            }
            
            for future in concurrent.futures.as_completed(future_to_rule):
                rule_id = future_to_rule[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.log_error(
                        "scan_parallel",
                        f"Unhandled exception scanning rule {rule_id}: {str(e)}",
                        {"rule_id": rule_id}
                    )
        
        # Sort results by rule ID for deterministic output order
        results.sort(key=lambda x: x.rule_id)
        
        return results
    
    def _execute_command(self, command: str) -> Tuple[int, str, str]:
        """
        Execute a shell command and return the result.
        
        Uses SecureCommandExecutor to eliminate command injection vulnerabilities.
        The command string is parsed into arguments and executed without shell=True.
        
        Args:
            command: Command to execute
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            # Use secure command executor to parse and execute command
            # This eliminates command injection vulnerabilities
            return self.command_executor.execute_shell_command_safely(
                command, timeout=self.command_timeout
            )
        except Exception as e:
            self.logger.log_error(
                "command_execution",
                f"Failed to execute command: {str(e)}",
                {"command": command}
            )
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

        # Handle canonical format: command can be a list
        if isinstance(command, list):
            # For canonical format, join list into command string
            # This supports both ["grep", "-rs", "maxlogins", "/path"]
            # and legacy "grep -rs maxlogins /path" formats
            command = ' '.join(shlex.quote(arg) if isinstance(arg, str) and ' ' in arg else str(arg) for arg in command)
        else:
            command = str(command)

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
        pattern = check_config.get('pattern', '')  # Canonical format: pattern to search
        expected_permissions = check_config.get('expected_permissions', '')
        expected_owner = check_config.get('expected_owner', '')

        if not file_path:
            return False, '', 'No file path specified'

        if not os.path.exists(file_path):
            return False, 'not_found', f'File not found: {file_path}'

        output_parts = []
        compliant = True

        # Use pattern for canonical format, expected_content for legacy
        search_pattern = pattern or expected_content

        # Check content/pattern if specified
        if search_pattern:
            try:
                with open(file_path, 'r') as f:
                    actual_content = f.read()

                if search_pattern in actual_content:
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
        # Support both legacy 'service_name' and canonical 'service' fields
        service_name = check_config.get('service_name') or check_config.get('service', '')
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
        # Support both legacy 'key' and canonical 'sysctl' fields
        sysctl_key = check_config.get('key') or check_config.get('sysctl', '')
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
        
        # Check OS compatibility with enhanced detection
        import platform
        os_name = platform.system().lower()
        os_family = None
        
        if os_name == 'linux':
            # Try to parse /etc/os-release for proper OS detection
            detected_os, os_family = _parse_os_release()
            
            if detected_os:
                # Use parsed OS ID (e.g., "almalinux", "rocky", "ubuntu")
                os_name = detected_os
                
                # If ID_LIKE parsing failed, determine family from detected OS
                if not os_family:
                    os_family = _get_os_family(detected_os)
            else:
                # Fallback to legacy simple string matching for backward compatibility
                # This ensures systems without proper /etc/os-release still work
                try:
                    with open('/etc/os-release', 'r') as f:
                        os_release = f.read()
                        # Check for explicit OS IDs first (for explicit detection)
                        if 'ID="almalinux"' in os_release.lower() or "ID='almalinux'" in os_release.lower():
                            os_name = 'almalinux'
                            os_family = 'rhel'
                        elif 'ID="rocky"' in os_release.lower() or "ID='rocky'" in os_release.lower():
                            os_name = 'rocky'
                            os_family = 'rhel'
                        # Fallback to legacy pattern matching
                        elif 'ubuntu' in os_release.lower():
                            os_name = 'ubuntu'
                            os_family = 'debian'
                        elif 'rhel' in os_release.lower() or 'red hat' in os_release.lower():
                            os_name = 'rhel'
                            os_family = 'rhel'
                        elif 'centos' in os_release.lower():
                            os_name = 'centos'
                            os_family = 'rhel'
                        elif 'debian' in os_release.lower():
                            os_name = 'debian'
                            os_family = 'debian'
                except Exception:
                    pass

        # Handle canonical format with OS family implementations
        selected_implementation = None
        if 'implementations' in rule:
            # Select OS family implementation
            selected_implementation = _select_os_family_implementation(rule, os_name, os_family)

            if selected_implementation is None:
                # No implementation for this OS family
                self.logger.log_scan_start(
                    rule['benchmark'],
                    rule['id'],
                    {
                        "os": os_name,
                        "os_family": os_family,
                        "canonical_format": True,
                        "status": "not_applicable"
                    }
                )
                return ScanResult(
                    rule_id=rule['id'],
                    benchmark=rule['benchmark'],
                    compliant=None,  # None for not applicable
                    expected_state='N/A',
                    actual_state='not_applicable',
                    check_output='Rule skipped - no OS family implementation',
                    error=f'No implementation for OS: {os_name} (family: {os_family})',
                    status='not_applicable',
                    applicability='not_applicable'
                )

            # Merge selected implementation's check/remediation/rollback into rule
            # This allows existing check execution code to work without modification
            if 'check' in selected_implementation:
                rule['canonical_check'] = rule.get('check', {})
                rule['check'] = selected_implementation['check']
            if 'remediation' in selected_implementation:
                rule['canonical_remediation'] = rule.get('remediation', {})
                rule['remediation'] = selected_implementation['remediation']
            if 'rollback' in selected_implementation:
                rule['canonical_rollback'] = rule.get('rollback', {})
                rule['rollback'] = selected_implementation.get('rollback', {})

        compatible_os = rule.get('os_compatibility', [])
        
        # Check compatibility using both direct OS match and family-based match
        # This allows rules targeting "rhel" to work on RHEL-compatible distributions
        if compatible_os and not _is_os_compatible(os_name, os_family, compatible_os):
            # Log rule as skipped due to OS incompatibility
            self.logger.log_scan_start(
                rule['benchmark'],
                rule['id'],
                {
                    "os": os_name,
                    "os_family": os_family,
                    "compatible": False,
                    "status": "skipped_os"
                }
            )
            return ScanResult(
                rule_id=rule['id'],
                benchmark=rule['benchmark'],
                compliant=None,  # None for skipped rules (not applicable)
                expected_state='N/A',
                actual_state='not_applicable',
                check_output='Rule skipped due to OS incompatibility',
                error=f'OS compatibility: {os_name} (family: {os_family}) not in {compatible_os}',
                status='skipped_os',  # Explicitly set status for OS-incompatible rules
                applicability='not_applicable'  # Mark as not applicable for OS-incompatible rules
            )
        
        # Log scan start
        self.logger.log_scan_start(
            rule['benchmark'],
            rule['id'],
            {"os": os_name, "os_family": os_family, "compatible": True}
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
                    error=f'Unknown check type: {check_type}',
                    applicability="applicable"  # Rule is applicable, just had an error
                )
            
            expected_state = check_config.get('expected_state', '')
            
            # Create scan result
            result = ScanResult(
                rule_id=rule['id'],
                benchmark=rule['benchmark'],
                compliant=compliant,
                expected_state=expected_state,
                actual_state=actual_state,
                check_output=output,
                applicability="applicable"  # Explicitly mark as applicable
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
                error=str(e),
                applicability="applicable"  # Rule is applicable, just had an error
            )
    


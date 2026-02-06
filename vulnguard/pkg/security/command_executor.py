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
Secure Command Executor Module

Provides secure command execution that eliminates command injection
vulnerabilities by:
1. Never using shell=True
2. Using parameterized command execution with list arguments
3. Validating and sanitizing all inputs
4. Implementing strict allow-lists for commands
5. Logging all command executions for audit

This module is designed to pass security audits and penetration testing.
"""

import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnguard.pkg.logging.logger import AuditLogger


class CommandExecutionError(Exception):
    """Raised when command execution fails."""
    pass


class CommandValidationError(Exception):
    """Raised when command validation fails."""
    pass


class SecureCommandExecutor:
    """
    Secure command executor that eliminates command injection vulnerabilities.
    
    Key security features:
    - Never uses shell=True
    - Uses parameterized command execution with list arguments
    - Validates all commands against allow-lists and block-lists
    - Sanitizes all user inputs
    - Logs all command executions for audit trails
    
    Usage:
        executor = SecureCommandExecutor(logger=audit_logger)
        result = executor.execute(['systemctl', 'status', 'ssh'])
    """
    
    # Default command allow-list (regex patterns)
    # These patterns define which commands are allowed to execute
    DEFAULT_COMMAND_ALLOWLIST = [
        # System management commands
        r'^systemctl$',
        r'^sysctl$',
        r'^modprobe$',
        r'^lsmod$',
        r'^insmod$',
        r'^rmmod$',
        r'^depmod$',
        # Package management commands (RHEL-based)
        r'^rpm$',
        r'^yum$',
        r'^dnf$',
        r'^rpmkeys$',
        # Package management commands (Debian-based)
        r'^dpkg$',
        r'^apt-get$',
        r'^apt$',
        r'^apt-cache$',
        # File operations
        r'^chmod$',
        r'^chown$',
        r'^sed$',
        r'^echo$',
        r'^cat$',
        r'^grep$',
        r'^awk$',
        r'^stat$',
        r'^ls$',
        r'^find$',
        r'^test$',
        r'\ [$',
        r'^which$',
        r'^id$',
        r'^whoami$',
        r'^hostname$',
        r'^uname$',
        r'^df$',
        r'^du$',
        r'^mount$',
        r'^umount$',
        r'^ps$',
        r'^netstat$',
        r'^ss$',
        r'^ip$',
        r'^getent$',
        r'^pwd$',
        # Security commands
        r'^getenforce$',
        r'^setenforce$',
        r'^sestatus$',
        r'^semodule$',
        r'^ausearch$',
        r'^aureport$',
        r'^firewall-cmd$',
        r'^firewall-offline-cmd$',
        r'^aideinit$',
        r'^aide$',
        # Service management
        r'^service$',
        r'^chkconfig$',
        r'^update-rc.d$',
        # Other utilities
        r'^date$',
        r'^tail$',
        r'^head$',
        r'^sort$',
        r'^uniq$',
        r'^wc$',
        r'^cut$',
        r'^tr$',
        r'^xargs$',
        r'^dirname$',
        r'^basename$',
        r'^mktemp$',
        r'^touch$',
        r'^mkdir$',
        r'^rm$',
        r'^cp$',
        r'^mv$'
    ]
    
    # Command block-list (regex patterns)
    # These patterns define which commands are explicitly forbidden
    COMMAND_BLOCKLIST = [
        r'^rm\s+-rf\s*/',
        r'^chmod\s+777',
        r'^dd\s+',
        r'^mkfs',
        r'^fdisk',
        r'^userdel',
        r'^groupdel',
        r'^passwd\s+-l\s+root',
        r'^setenforce\s+0',
        r'^iptables\s+-F',
        r'^:(){:|:&};:',  # Shellshock
        r'eval\s*\(',
        r'exec\s*\(',
        r'\$\(',
        r'`[^`]*`',  # Backtick command substitution
        r';\s*rm\s',
        r'&&\s*rm\s',
        r'\|\|\s*rm\s',
        r'>\s*/dev/',
        r'>>\s*/etc/',
        r'nc\s+-l',  # Netcat listener
        r'ncat\s+-l',
        r'socat\s+TCP-LISTEN'
    ]
    
    # Argument patterns that are dangerous
    DANGEROUS_ARG_PATTERNS = [
        r';\s*\w+',  # Command chaining
        r'&&\s*\w+',  # Command chaining
        r'\|\|\s*\w+',  # Command chaining
        r'\|\s*\w+',  # Pipe to arbitrary command
        r'\$\(',  # Command substitution
        r'`[^`]*`',  # Backtick command substitution
        r'\$\{[^}]*\}',  # Variable expansion
        r'\\x[0-9a-fA-F]{2}',  # Hex encoding
        r'\\[0-7]{3}',  # Octal encoding
        r'\n',  # Newline injection
        r'\r',  # Carriage return injection
        r'\t',  # Tab injection
    ]
    
    def __init__(
        self,
        logger: Any = None,
        command_allowlist: Optional[List[str]] = None,
        command_blocklist: Optional[List[str]] = None,
        timeout: int = 30,
        max_output_size: int = 10485760  # 10MB
    ):
        """
        Initialize the secure command executor.
        
        Args:
            logger: Optional audit logger instance
            command_allowlist: Optional custom command allow-list
            command_blocklist: Optional custom command block-list
            timeout: Default timeout for command execution in seconds
            max_output_size: Maximum size of stdout/stderr in bytes
        """
        # Import at runtime to avoid circular dependency
        if logger is None:
            from vulnguard.pkg.logging.logger import AuditLogger as LoggerClass
            self.logger = LoggerClass()
        else:
            self.logger = logger
        self.command_allowlist = command_allowlist or self.DEFAULT_COMMAND_ALLOWLIST
        self.command_blocklist = command_blocklist or self.COMMAND_BLOCKLIST
        self.timeout = timeout
        self.max_output_size = max_output_size
    
    def _sanitize_input(self, input_str: str) -> str:
        """
        Sanitize user input to prevent command injection.
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            Sanitized string
            
        Raises:
            CommandValidationError: If input contains dangerous patterns
        """
        if not isinstance(input_str, str):
            raise CommandValidationError("Input must be a string")
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_ARG_PATTERNS:
            if re.search(pattern, input_str):
                raise CommandValidationError(
                    f"Input contains dangerous pattern: {pattern}"
                )
        
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        return sanitized
    
    def _validate_command(self, command: List[str]) -> None:
        """
        Validate a command against allow-lists and block-lists.
        
        Args:
            command: Command as a list of arguments
            
        Raises:
            CommandValidationError: If command is invalid
        """
        if not command or not isinstance(command, list):
            raise CommandValidationError("Command must be a non-empty list")
        
        if not command[0]:
            raise CommandValidationError("Command cannot be empty")
        
        # Get the base command (first argument)
        base_command = command[0]
        
        # Check block-list first
        for block_pattern in self.command_blocklist:
            # Check if the full command matches the block pattern
            full_command_str = ' '.join(command)
            if re.search(block_pattern, full_command_str, re.IGNORECASE):
                raise CommandValidationError(
                    f"Command blocked by block-list pattern: {block_pattern}"
                )
        
        # Check allow-list
        is_allowed = False
        for allow_pattern in self.command_allowlist:
            if re.match(allow_pattern, base_command):
                is_allowed = True
                break
        
        if not is_allowed:
            raise CommandValidationError(
                f"Command '{base_command}' not in allow-list"
            )
        
        # Validate all arguments
        for i, arg in enumerate(command):
            if not isinstance(arg, str):
                raise CommandValidationError(
                    f"Argument {i} must be a string, got {type(arg)}"
                )
            
            # Sanitize each argument
            sanitized = self._sanitize_input(arg)
            if sanitized != arg:
                raise CommandValidationError(
                    f"Argument {i} contains dangerous characters: {arg}"
                )
    
    def execute(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        dry_run: bool = False
    ) -> Tuple[int, str, str]:
        """
        Execute a command securely.
        
        Args:
            command: Command as a list of arguments (NEVER use shell=True)
            timeout: Optional timeout in seconds (overrides default)
            env: Optional environment variables dictionary
            cwd: Optional working directory
            dry_run: If True, only log without executing
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
            
        Raises:
            CommandValidationError: If command validation fails
            CommandExecutionError: If command execution fails
        """
        # Validate command
        self._validate_command(command)
        
        # Use provided timeout or default
        exec_timeout = timeout if timeout is not None else self.timeout
        
        # Log command execution
        self.logger.log_info(
            f"Executing command: {' '.join(command)}"
        )
        
        if dry_run:
            self.logger.log_info(
                f"[DRY-RUN] Would execute: {' '.join(command)}"
            )
            return 0, f"[DRY-RUN] Would execute: {' '.join(command)}", ""
        
        try:
            # Execute command WITHOUT shell=True - this prevents command injection
            result = subprocess.run(
                command,
                shell=False,  # CRITICAL: Never use shell=True
                capture_output=True,
                text=True,
                timeout=exec_timeout,
                env=env,
                cwd=cwd
            )
            
            # Truncate output if it exceeds max size
            stdout = result.stdout
            stderr = result.stderr
            
            if len(stdout) > self.max_output_size:
                stdout = stdout[:self.max_output_size] + "\n... [TRUNCATED]"
                self.logger.log_warning(
                    f"Stdout truncated to {self.max_output_size} bytes"
                )
            
            if len(stderr) > self.max_output_size:
                stderr = stderr[:self.max_output_size] + "\n... [TRUNCATED]"
                self.logger.log_warning(
                    f"Stderr truncated to {self.max_output_size} bytes"
                )
            
            # Log result
            self.logger.log_info(
                f"Command completed: exit_code={result.returncode}, "
                f"stdout_len={len(stdout)}, stderr_len={len(stderr)}"
            )
            
            return result.returncode, stdout, stderr
            
        except subprocess.TimeoutExpired as e:
            error_msg = f"Command timed out after {exec_timeout} seconds"
            self.logger.log_error(
                "command_execution",
                error_msg,
                {"command": command, "timeout": exec_timeout}
            )
            raise CommandExecutionError(error_msg) from e
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed with exit code {e.returncode}"
            self.logger.log_error(
                "command_execution",
                error_msg,
                {"command": command, "exit_code": e.returncode}
            )
            raise CommandExecutionError(error_msg) from e
            
        except FileNotFoundError as e:
            error_msg = f"Command not found: {command[0]}"
            self.logger.log_error(
                "command_execution",
                error_msg,
                {"command": command}
            )
            raise CommandExecutionError(error_msg) from e
            
        except PermissionError as e:
            error_msg = f"Permission denied executing command: {command[0]}"
            self.logger.log_error(
                "command_execution",
                error_msg,
                {"command": command}
            )
            raise CommandExecutionError(error_msg) from e
            
        except Exception as e:
            error_msg = f"Unexpected error executing command: {str(e)}"
            self.logger.log_error(
                "command_execution",
                error_msg,
                {"command": command, "error_type": type(e).__name__}
            )
            raise CommandExecutionError(error_msg) from e
    
    def _parse_shell_command_safely(self, shell_command: str) -> List[str]:
        """
        Parse a shell command string into arguments with strict validation.
        
        This method implements a safer alternative to shlex.split() with:
        1. Strict validation of command structure
        2. Detection of dangerous patterns before parsing
        3. Sanitization of special characters
        4. Protection against command injection
        
        Args:
            shell_command: Shell command string to parse
            
        Returns:
            List of command arguments
            
        Raises:
            CommandValidationError: If command contains dangerous patterns
        """
        # Check for dangerous patterns before parsing
        for pattern in self.DANGEROUS_ARG_PATTERNS:
            if re.search(pattern, shell_command):
                raise CommandValidationError(
                    f"Command contains dangerous pattern: {pattern}"
                )
        
        # Check for command chaining (multiple commands)
        if re.search(r'[;&|]', shell_command):
            raise CommandValidationError(
                "Command chaining detected. Only single commands are allowed."
            )
        
        # Check for command substitution
        if re.search(r'\$\(|`[^`]*`', shell_command):
            raise CommandValidationError(
                "Command substitution detected. This is not allowed."
            )
        
        # Check for variable expansion
        if re.search(r'\$\{[^}]*\}', shell_command):
            raise CommandValidationError(
                "Variable expansion detected. This is not allowed."
            )
        
        # Use shlex.split with strict mode
        try:
            args = shlex.split(shell_command, posix=True)
        except ValueError as e:
            raise CommandValidationError(
                f"Failed to parse shell command: {str(e)}"
            ) from e
        
        # Validate that we have at least a command
        if not args:
            raise CommandValidationError("Empty command")
        
        # Validate that the command doesn't contain special characters
        # that could lead to injection
        for i, arg in enumerate(args):
            # Check for null bytes
            if '\x00' in arg:
                raise CommandValidationError(
                    f"Argument {i} contains null byte"
                )
            
            # Check for newlines
            if '\n' in arg or '\r' in arg:
                raise CommandValidationError(
                    f"Argument {i} contains newline characters"
                )
            
            # Check for backslash escapes that might be suspicious
            if arg.count('\\') > len(arg) // 2:
                raise CommandValidationError(
                    f"Argument {i} contains excessive backslash escapes"
                )
        
        return args
    
    def execute_shell_command_safely(
        self,
        shell_command: str,
        timeout: Optional[int] = None,
        dry_run: bool = False
    ) -> Tuple[int, str, str]:
        """
        Execute a shell command safely by parsing it into arguments.
        
        This method is provided for compatibility with existing code that
        uses shell commands. It parses the shell command into a list of
        arguments and executes them securely without shell=True.
        
        SECURITY NOTES:
        - Uses strict validation before parsing
        - Rejects command chaining, substitution, and variable expansion
        - Validates all arguments for dangerous patterns
        - For maximum security, use execute() with explicit command arguments instead
        
        shlex.split() Usage:
        This method uses shlex.split() to parse shell commands into argument lists.
        shlex.split() is used because:
        1. It properly handles quoted arguments and escaping
        2. It preserves argument boundaries for security validation
        3. It allows us to reject dangerous patterns before execution
        
        If shlex.split() fails (e.g., unmatched quotes), the method returns an
        error result instead of falling back to shell=True execution.
        
        Args:
            shell_command: Shell command string to parse and execute
            timeout: Optional timeout in seconds
            dry_run: If True, only log without executing
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
            
        Raises:
            CommandValidationError: If command parsing or validation fails
            CommandExecutionError: If command execution fails
        """
        try:
            # Parse shell command into arguments with strict validation
            args = self._parse_shell_command_safely(shell_command)
            
            # Execute parsed arguments securely
            return self.execute(args, timeout=timeout, dry_run=dry_run)
            
        except CommandValidationError:
            # Re-raise validation errors as-is
            raise
        except ValueError as e:
            # Command syntax error from shlex (e.g., unmatched quotes)
            # This is a parsing failure, NOT a fallback to shell=True
            error_msg = f"Command syntax error, cannot parse safely: {str(e)}"
            self.logger.log_warning(
                "command_execution",
                error_msg,
                {"shell_command": shell_command}
            )
            return -1, "", error_msg
        except (subprocess.SubprocessError, OSError) as e:
            # Other execution errors (not parsing errors)
            error_msg = f"Command execution error: {str(e)}"
            self.logger.log_error(
                "command_execution",
                error_msg,
                {"shell_command": shell_command}
            )
            return -1, "", str(e)


"""
Plugin Sandbox & Context.

Implements the restricted environment (sandbox) for plugins.
Validation of capabilities happens here.
"""

import re
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from vulnguard.pkg.logging.logger import AuditLogger

# Capability Constants
CAP_EXEC_CMD = "EXEC_CMD"
CAP_FILE_READ = "FILE_READ"
CAP_FILE_WRITE = "FILE_WRITE"
CAP_NETWORK_OUTBOUND = "NETWORK_OUTBOUND"

class SecurityViolation(Exception):
    """Raised when a plugin attempts an unauthorized action."""
    pass

class SecureFileSystemProxy:
    """Restricted File System Access."""
    def __init__(self, allowed_read_paths: List[str], allowed_write_paths: List[str]):
        self.allowed_read_paths = allowed_read_paths
        self.allowed_write_paths = allowed_write_paths

    def _validate_path(self, path: str, write: bool = False) -> Path:
        """Validate path against allowed lists."""
        abs_path = os.path.abspath(path)
        allowed = self.allowed_write_paths if write else (self.allowed_read_paths + self.allowed_write_paths)
        
        valid = False
        for allowed_path in allowed:
            # Simple prefix check (can be enhanced with PathValidator)
            if abs_path.startswith(os.path.abspath(allowed_path)):
                valid = True
                break
        
        if not valid:
            action = "write" if write else "read"
            raise SecurityViolation(f"Access denied: Cannot {action} path '{path}'")
        
        return Path(abs_path)

    def read_text(self, path: str) -> str:
        """Securely read text file."""
        p = self._validate_path(path, write=False)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")
        return p.read_text(encoding='utf-8')

    def write_text(self, path: str, content: str) -> None:
        """Securely write text file."""
        p = self._validate_path(path, write=True)
        # Ensure directory exists if write is allowed
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')

class SecureExecutionProxy:
    """Restricted Command Execution."""
    def __init__(self, allowed_patterns: List[str], command_executor: Any):
        self.allowed_patterns = allowed_patterns
        self.executor = command_executor

    def run(self, command: str) -> Dict[str, Any]:
        """Securely run a shell command."""
        # 1. Check capability patterns specific to this plugin
        allowed = False
        for pattern in self.allowed_patterns:
            if re.match(pattern, command):
                allowed = True
                break
        
        if not allowed:
            raise SecurityViolation(f"Access denied: Command '{command}' not allowed by plugin capabilities.")
        
        # 2. Delegate to Core SecureCommandExecutor (Global Allow/Block lists)
        # This doubles restrictions: Plugin Allow List + System Global Allow List
        exit_code, stdout, stderr = self.executor.execute_shell_command_safely(
            command, timeout=30, dry_run=False
        )
        
        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr
        }

class PluginContext:
    """Concrete implementation of the Plugin Context."""
    def __init__(
        self,
        config: Dict[str, Any],
        capabilities: Dict[str, List[str]], # Map: CAP_NAME -> [params]
        logger: AuditLogger,
        command_executor: Any
    ):
        self._config = config
        self._logger = logger
        self._capabilities = capabilities
        
        # Initialize Proxies based on capabilities
        self.fs = SecureFileSystemProxy(
            allowed_read_paths=capabilities.get(CAP_FILE_READ, []),
            allowed_write_paths=capabilities.get(CAP_FILE_WRITE, [])
        )
        
        self.exec = SecureExecutionProxy(
            allowed_patterns=capabilities.get(CAP_EXEC_CMD, []),
            command_executor=command_executor
        )
        
        # Network proxy would go here

    @property
    def config(self) -> Dict[str, Any]:
        return self._config

    def log_info(self, message: str) -> None:
        self._logger.log_info(f"[PLUGIN] {message}")

    def log_error(self, message: str) -> None:
        self._logger.log_error("plugin_error", message)

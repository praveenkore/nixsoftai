
import unittest
from unittest.mock import MagicMock, patch
import os
from pathlib import Path
import tempfile
import shutil

from vulnguard.pkg.plugins.interface import PluginContext
from vulnguard.pkg.plugins.context import (
    PluginContext as ConcretePluginContext,
    SecureFileSystemProxy,
    SecureExecutionProxy,
    SecurityViolation,
    CAP_FILE_READ,
    CAP_FILE_WRITE,
    CAP_EXEC_CMD
)
from vulnguard.pkg.logging.logger import AuditLogger

class TestPluginSecurity(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock(spec=AuditLogger)
        self.executor = MagicMock()
        self.executor.execute_shell_command_safely.return_value = (0, "ok", "")
        
        self.temp_dir = tempfile.mkdtemp()
        self.allowed_file = os.path.join(self.temp_dir, "allowed.txt")
        self.forbidden_file = os.path.join(self.temp_dir, "forbidden.txt")
        self.output_file = os.path.join(self.temp_dir, "output.txt")
        
        with open(self.allowed_file, "w") as f:
            f.write("Allowed Content")
        with open(self.forbidden_file, "w") as f:
            f.write("Secret Content")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_fs_proxy_read_allowed(self):
        proxy = SecureFileSystemProxy(
            allowed_read_paths=[self.allowed_file],
            allowed_write_paths=[]
        )
        content = proxy.read_text(self.allowed_file)
        self.assertEqual(content, "Allowed Content")

    def test_fs_proxy_read_denied(self):
        proxy = SecureFileSystemProxy(
            allowed_read_paths=[self.allowed_file],
            allowed_write_paths=[]
        )
        with self.assertRaises(SecurityViolation):
            proxy.read_text(self.forbidden_file)

    def test_fs_proxy_write_denied(self):
        proxy = SecureFileSystemProxy(
            allowed_read_paths=[self.allowed_file],
            allowed_write_paths=[] # No write access
        )
        with self.assertRaises(SecurityViolation):
            proxy.write_text(self.allowed_file, "Hacked")

    def test_exec_proxy_allowed(self):
        proxy = SecureExecutionProxy(
            allowed_patterns=[r"^echo .*"],
            command_executor=self.executor
        )
        result = proxy.run("echo hello")
        self.assertEqual(result["exit_code"], 0)
        self.executor.execute_shell_command_safely.assert_called_once()

    def test_exec_proxy_denied(self):
        proxy = SecureExecutionProxy(
            allowed_patterns=[r"^echo .*"],
            command_executor=self.executor
        )
        with self.assertRaises(SecurityViolation):
            proxy.run("rm -rf /") # Not matched by echo .*
        
        self.executor.execute_shell_command_safely.assert_not_called()

    def test_context_integration(self):
        capabilities = {
            CAP_FILE_READ: [self.allowed_file],
            CAP_EXEC_CMD: [r"^ls.*"]
        }
        
        context = ConcretePluginContext(
            config={},
            capabilities=capabilities,
            logger=self.logger,
            command_executor=self.executor
        )
        
        # Should succeed
        context.fs.read_text(self.allowed_file)
        
        # Should fail
        with self.assertRaises(SecurityViolation):
            context.fs.read_text(self.forbidden_file)
            
        # Should fail
        with self.assertRaises(SecurityViolation):
            context.exec.run("cat /etc/passwd")

if __name__ == "__main__":
    unittest.main()

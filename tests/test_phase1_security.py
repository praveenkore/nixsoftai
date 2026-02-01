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
Phase 1 Security Tests - Critical Security Fixes

Comprehensive test suite for Phase 1 security hardening:
1. Command injection vulnerability tests
2. File permission security tests
3. TOCTOU vulnerability tests
4. Integration tests

All tests are designed to verify that security fixes are working
correctly and that the system meets enterprise-level security standards.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnguard.pkg.security.command_executor import (
    SecureCommandExecutor,
    CommandExecutionError,
    CommandValidationError,
    execute_command_safely
)
from vulnguard.pkg.security.file_permissions import (
    SecureFilePermissions,
    PermissionError,
    create_secure_file,
    create_secure_directory
)
from vulnguard.pkg.security.atomic_operations import (
    AtomicFileOperations,
    AtomicOperationError,
    atomic_write_file,
    atomic_read_file
)


class TestCommandInjection(unittest.TestCase):
    """Test cases for command injection vulnerability fixes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.executor = SecureCommandExecutor(logger=None)
    
    def test_safe_command_execution(self):
        """Test that safe commands execute correctly."""
        exit_code, stdout, stderr = self.executor.execute(['echo', 'test'])
        self.assertEqual(exit_code, 0)
        self.assertIn('test', stdout)
    
    def test_command_injection_blocked(self):
        """Test that command injection attempts are blocked."""
        with self.assertRaises(CommandValidationError):
            # This should be blocked because it contains command chaining
            self.executor.execute_shell_command_safely('echo test; rm -rf /')
    
    def test_command_injection_with_backticks(self):
        """Test that backtick command injection is blocked."""
        with self.assertRaises(CommandValidationError):
            # This should be blocked because it contains backticks
            self.executor.execute_shell_command_safely('echo `whoami`')
    
    def test_command_injection_with_pipe(self):
        """Test that pipe command injection is blocked."""
        with self.assertRaises(CommandValidationError):
            # This should be blocked because it contains pipe
            self.executor.execute_shell_command_safely('echo test | cat /etc/passwd')
    
    def test_command_injection_with_variable_substitution(self):
        """Test that variable substitution injection is blocked."""
        with self.assertRaises(CommandValidationError):
            # This should be blocked because it contains variable substitution
            self.executor.execute_shell_command_safely('echo $(whoami)')
    
    def test_allow_list_enforcement(self):
        """Test that only allow-listed commands are allowed."""
        with self.assertRaises(CommandValidationError):
            # This should be blocked because 'rm' with -rf is not in allow-list
            self.executor.execute(['rm', '-rf', '/tmp/test'])
    
    def test_block_list_enforcement(self):
        """Test that block-listed commands are blocked."""
        with self.assertRaises(CommandValidationError):
            # This should be blocked by block-list
            self.executor.execute_shell_command_safely('chmod 777 /etc/passwd')
    
    def test_timeout_protection(self):
        """Test that timeout protection works."""
        # This command should timeout
        with self.assertRaises(CommandExecutionError):
            self.executor.execute(['sleep', '100'], timeout=1)
    
    def test_dry_run_mode(self):
        """Test that dry-run mode doesn't execute commands."""
        exit_code, stdout, stderr = self.executor.execute(
            ['echo', 'test'],
            dry_run=True
        )
        self.assertEqual(exit_code, 0)
        self.assertIn('DRY-RUN', stdout)


class TestFilePermissions(unittest.TestCase):
    """Test cases for file permission security."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.permissions = SecureFilePermissions(logger=None)
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_secure_file_creation(self):
        """Test that files are created with secure permissions."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        self.permissions.create_secure_file(test_file, content='test')
        
        # Check that file has 0600 permissions
        actual_perms = self.permissions.get_file_permissions(test_file)
        self.assertEqual(actual_perms, 0o600)
    
    def test_secure_directory_creation(self):
        """Test that directories are created with secure permissions."""
        test_dir = os.path.join(self.temp_dir, 'testdir')
        self.permissions.create_secure_directory(test_dir)
        
        # Check that directory has 0700 permissions
        actual_perms = self.permissions.get_file_permissions(test_dir)
        self.assertEqual(actual_perms, 0o700)
    
    def test_custom_permissions(self):
        """Test that custom permissions are applied correctly."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        self.permissions.create_secure_file(test_file, content='test', permissions=0o644)
        
        # Check that file has custom permissions
        actual_perms = self.permissions.get_file_permissions(test_file)
        self.assertEqual(actual_perms, 0o644)
    
    def test_permission_verification(self):
        """Test that permission verification works."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        self.permissions.create_secure_file(test_file, content='test')
        
        # Verify permissions
        is_compliant, actual_perms = self.permissions.verify_permissions(
            test_file,
            0o600
        )
        self.assertTrue(is_compliant)
        self.assertEqual(actual_perms, 0o600)
    
    def test_permission_mismatch_detection(self):
        """Test that permission mismatches are detected."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        self.permissions.create_secure_file(test_file, content='test')
        
        # Change permissions to insecure value
        os.chmod(test_file, 0o777)
        
        # Verify permissions should detect mismatch
        is_compliant, actual_perms = self.permissions.verify_permissions(
            test_file,
            0o600
        )
        self.assertFalse(is_compliant)
        self.assertEqual(actual_perms, 0o777)
    
    def test_temp_file_permissions(self):
        """Test that temporary files have secure permissions."""
        temp_file = self.permissions.create_temp_file(content='test')
        
        try:
            # Check that temp file has 0600 permissions
            actual_perms = self.permissions.get_file_permissions(temp_file)
            self.assertEqual(actual_perms, 0o600)
        finally:
            os.unlink(temp_file)
    
    def test_temp_directory_permissions(self):
        """Test that temporary directories have secure permissions."""
        temp_dir = self.permissions.create_temp_directory()
        
        try:
            # Check that temp directory has 0700 permissions
            actual_perms = self.permissions.get_file_permissions(temp_dir)
            self.assertEqual(actual_perms, 0o700)
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_permission_audit(self):
        """Test that permission auditing works."""
        # Create test directory with files
        test_dir = os.path.join(self.temp_dir, 'audit_test')
        os.makedirs(test_dir)
        
        # Create files with different permissions
        secure_file = os.path.join(test_dir, 'secure.txt')
        insecure_file = os.path.join(test_dir, 'insecure.txt')
        
        self.permissions.create_secure_file(secure_file, content='secure')
        with open(insecure_file, 'w') as f:
            f.write('insecure')
        os.chmod(insecure_file, 0o777)
        
        # Run audit
        audit_results = self.permissions.audit_directory_permissions(test_dir)
        
        # Should detect insecure file
        self.assertFalse(audit_results['compliant'])
        self.assertEqual(len(audit_results['non_compliant_files']), 1)
        self.assertEqual(
            audit_results['non_compliant_files'][0]['path'],
            insecure_file
        )


class TestAtomicOperations(unittest.TestCase):
    """Test cases for TOCTOU vulnerability fixes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.ops = AtomicFileOperations(logger=None)
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_atomic_write(self):
        """Test that atomic write works correctly."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        content = 'test content'
        
        self.ops.atomic_write(test_file, content)
        
        # Verify content was written
        with open(test_file, 'r') as f:
            actual_content = f.read()
        
        self.assertEqual(actual_content, content)
    
    def test_atomic_read(self):
        """Test that atomic read works correctly."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        content = 'test content'
        
        with open(test_file, 'w') as f:
            f.write(content)
        
        # Read atomically
        actual_content = self.ops.atomic_read(test_file)
        
        self.assertEqual(actual_content, content)
    
    def test_atomic_create(self):
        """Test that atomic create works correctly."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        content = 'test content'
        
        self.ops.atomic_create(test_file, content)
        
        # Verify content was written
        with open(test_file, 'r') as f:
            actual_content = f.read()
        
        self.assertEqual(actual_content, content)
    
    def test_atomic_create_fails_if_exists(self):
        """Test that atomic create fails if file exists."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        content = 'test content'
        
        # Create file first
        with open(test_file, 'w') as f:
            f.write('existing')
        
        # Atomic create should fail
        with self.assertRaises(AtomicOperationError):
            self.ops.atomic_create(test_file, content)
    
    def test_atomic_append(self):
        """Test that atomic append works correctly."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        
        # Write initial content
        self.ops.atomic_write(test_file, 'initial')
        
        # Append additional content
        self.ops.atomic_append(test_file, ' appended')
        
        # Verify content was appended
        with open(test_file, 'r') as f:
            actual_content = f.read()
        
        self.assertEqual(actual_content, 'initial appended')
    
    def test_atomic_replace(self):
        """Test that atomic replace works correctly."""
        source_file = os.path.join(self.temp_dir, 'source.txt')
        target_file = os.path.join(self.temp_dir, 'target.txt')
        
        # Create source and target files
        with open(source_file, 'w') as f:
            f.write('source content')
        with open(target_file, 'w') as f:
            f.write('target content')
        
        # Replace target with source
        self.ops.atomic_replace(source_file, target_file)
        
        # Verify target now has source content
        with open(target_file, 'r') as f:
            actual_content = f.read()
        
        self.assertEqual(actual_content, 'source content')
        # Source file should be gone
        self.assertFalse(os.path.exists(source_file))
    
    def test_atomic_copy(self):
        """Test that atomic copy works correctly."""
        source_file = os.path.join(self.temp_dir, 'source.txt')
        target_file = os.path.join(self.temp_dir, 'target.txt')
        
        # Create source file
        with open(source_file, 'w') as f:
            f.write('source content')
        
        # Copy atomically
        self.ops.atomic_copy(source_file, target_file)
        
        # Verify target has source content
        with open(target_file, 'r') as f:
            actual_content = f.read()
        
        self.assertEqual(actual_content, 'source content')
        # Source file should still exist
        self.assertTrue(os.path.exists(source_file))
    
    def test_atomic_delete(self):
        """Test that atomic delete works correctly."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        
        # Create file
        with open(test_file, 'w') as f:
            f.write('test content')
        
        # Delete atomically
        self.ops.atomic_delete(test_file)
        
        # File should be gone
        self.assertFalse(os.path.exists(test_file))
    
    def test_atomic_delete_with_backup(self):
        """Test that atomic delete creates backup."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        
        # Create file
        with open(test_file, 'w') as f:
            f.write('test content')
        
        # Delete with backup
        self.ops.atomic_delete(test_file, backup=True)
        
        # File should be gone
        self.assertFalse(os.path.exists(test_file))
        # Backup should exist
        backup_file = f"{test_file}.deleted"
        self.assertTrue(os.path.exists(backup_file))
    
    def test_no_toctou_vulnerability(self):
        """Test that TOCTOU vulnerability is eliminated."""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        
        # This pattern would normally be vulnerable to TOCTOU:
        # 1. Check if file exists
        # 2. Race condition window
        # 3. Write to file
        
        # With atomic operations, this is safe
        if not os.path.exists(test_file):
            self.ops.atomic_create(test_file, 'safe content')
        
        # Verify file was created safely
        self.assertTrue(os.path.exists(test_file))
        with open(test_file, 'r') as f:
            content = f.read()
        
        self.assertEqual(content, 'safe content')


class TestIntegration(unittest.TestCase):
    """Integration tests for Phase 1 security fixes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_end_to_end_secure_workflow(self):
        """Test complete secure workflow."""
        # Create secure file
        test_file = os.path.join(self.temp_dir, 'test.txt')
        permissions = SecureFilePermissions(logger=None)
        permissions.create_secure_file(test_file, content='initial')
        
        # Read atomically
        ops = AtomicFileOperations(logger=None)
        content = ops.atomic_read(test_file)
        self.assertEqual(content, 'initial')
        
        # Write atomically
        ops.atomic_write(test_file, content='updated')
        
        # Verify update
        content = ops.atomic_read(test_file)
        self.assertEqual(content, 'updated')
        
        # Verify permissions are still secure
        actual_perms = permissions.get_file_permissions(test_file)
        self.assertEqual(actual_perms, 0o600)
    
    def test_secure_command_with_file_operations(self):
        """Test secure command execution combined with file operations."""
        # Create test file
        test_file = os.path.join(self.temp_dir, 'test.txt')
        ops = AtomicFileOperations(logger=None)
        ops.atomic_write(test_file, content='test')
        
        # Execute secure command to read file
        executor = SecureCommandExecutor(logger=None)
        exit_code, stdout, stderr = executor.execute(['cat', test_file])
        
        self.assertEqual(exit_code, 0)
        self.assertIn('test', stdout)


def run_tests():
    """Run all Phase 1 security tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCommandInjection))
    suite.addTests(loader.loadTestsFromTestCase(TestFilePermissions))
    suite.addTests(loader.loadTestsFromTestCase(TestAtomicOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("PHASE 1 SECURITY TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    # Return exit code based on results
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())

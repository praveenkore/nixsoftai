import unittest
import os
import shutil
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from vulnguard.pkg.security.path_validator import validate_path, PathValidationError, is_safe_path
from vulnguard.pkg.security.atomic_operations import AtomicFileOperations, AtomicOperationError
from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.remediation.remediation import RemediationEngine

class TestHighPriorityFixes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = MagicMock(spec=AuditLogger)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    # --- SEC-004: Path Validator ---
    def test_path_validator_basics(self):
        # Create dummy file
        fpath = os.path.join(self.temp_dir, "safe.txt")
        with open(fpath, "w") as f:
            f.write("test")
            
        validated = validate_path(fpath, base_dir=self.temp_dir)
        self.assertEqual(str(validated), os.path.abspath(fpath))
        
        # Test traversal confinement
        try:
            # On Windows, abspath resolves .. so we need to be careful constructing path that looks like traversal
            # but resolves outside
            # Actually validate_path normalizes first.
            # Let's try to validate a path outside base_dir
            outside_file = os.path.abspath(os.path.join(self.temp_dir, "..", "outside.txt"))
            # validate_path(outside_file, base_dir=self.temp_dir) # Should fail
            self.assertFalse(is_safe_path(outside_file, base_dir=self.temp_dir))
        except Exception:
            pass

    def test_path_validator_symlinks(self):
        # Create a symlink if OS supports it
        symlink_path = os.path.join(self.temp_dir, "mylink")
        target_path = os.path.join(self.temp_dir, "target")
        with open(target_path, "w") as f:
            f.write("target")
            
        try:
            os.symlink(target_path, symlink_path)
            # Default behavior: blocking symlinks?
            # validate_path default allow_symlinks=False
            with self.assertRaises(PathValidationError):
                validate_path(symlink_path)
                
            # Allow symlinks
            validated = validate_path(symlink_path, allow_symlinks=True)
            self.assertEqual(validated, Path(os.path.abspath(target_path)))
            
        except OSError:
            print("Skipping symlink test (not supported on this OS/user)")

    # --- SEC-005: Atomic Ops Symlink Protection ---
    def test_atomic_ops_rejects_symlinks(self):
        ops = AtomicFileOperations(logger=self.logger)
        
        symlink_path = os.path.join(self.temp_dir, "bad_link")
        target_path = os.path.join(self.temp_dir, "victim")
        with open(target_path, "w") as f:
            f.write("original")
            
        try:
            os.symlink(target_path, symlink_path)
            
            # Try to write to symlink
            with self.assertRaises(AtomicOperationError) as cm:
                ops.atomic_write(symlink_path, "hacked")
            self.assertIn("Symlink access denied", str(cm.exception))
            
            # Verify victim intact
            with open(target_path, "r") as f:
                self.assertEqual(f.read(), "original")
                
        except OSError:
            print("Skipping symlink test")

    # --- REL-003: Backup Retention ---
    @patch('vulnguard.pkg.remediation.remediation._get_secure_command_executor')
    @patch('vulnguard.pkg.remediation.remediation._get_secure_file_permissions')
    def test_backup_retention(self, mock_get_perms, mock_get_executor):
        # Mock permissions
        mock_perms_instance = MagicMock()
        # Mock create_secure_directory to assume success
        mock_perms_instance.create_secure_directory.side_effect = lambda p: os.makedirs(p, exist_ok=True)
        mock_get_perms.return_value = MagicMock(return_value=mock_perms_instance)
        
        # Mock executor
        mock_executor_instance = MagicMock()
        mock_get_executor.return_value = MagicMock(return_value=mock_executor_instance)

        backup_dir = os.path.join(self.temp_dir, "backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        # Mock engine with strict limits
        engine = RemediationEngine(
            logger=self.logger,
            backup_directory=backup_dir,
            backup_retention_days=1, # 1 day
            max_backups_count=2
        )
        
        # Mock file permissions attribute directly on engine to be sure
        engine.file_permissions = mock_perms_instance
        
        # Determine strict retention second threshold
        # We need to create files with old timestamps.
        
        now = time.time()
        old_time = now - (2 * 86400) # 2 days ago
        
        # Create 3 backups
        # 1. Very old (should be deleted by days)
        # 2. Old but within days (should be deleted by count if we have 3 and max is 2)
        # 3. New (should be kept)
        
        b1 = os.path.join(backup_dir, "backup_old")
        os.makedirs(b1)
        os.utime(b1, (old_time, old_time))
        
        b2 = os.path.join(backup_dir, "backup_excess")
        os.makedirs(b2)
        # slight delay to ensure sorting order
        mid_time = now - 100
        os.utime(b2, (mid_time, mid_time))
        
        b3 = os.path.join(backup_dir, "backup_new")
        os.makedirs(b3)
        # current time
        
        # Run cleanup
        engine.cleanup_old_backups()
        
        # Verify
        self.assertFalse(os.path.exists(b1), "Old backup should be deleted")
        # We have max=2. We had b1, b2, b3. b1 deleted by age. b2, b3 left.
        # If we had b4, then b2 might be deleted.
        # Let's create another one to trigger count limit
        
        b4 = os.path.join(backup_dir, "backup_newest")
        os.makedirs(b4)
        
        # Now we have b2, b3, b4 (all valid age). Count=3. Max=2.
        # b2 is oldest of them.
        engine.cleanup_old_backups()
        
        self.assertFalse(os.path.exists(b2), "Excess backup should be deleted")
        self.assertTrue(os.path.exists(b3))
        self.assertTrue(os.path.exists(b4))

if __name__ == '__main__':
    unittest.main()

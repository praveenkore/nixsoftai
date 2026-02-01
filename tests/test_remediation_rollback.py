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
Unit Tests for Remediation Rollback Functionality

Tests the file backup and rollback restoration functionality.
"""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from vulnguard.pkg.remediation.remediation import RemediationEngine, RemediationResult
from vulnguard.pkg.scanner.scanner import ScanResult
from vulnguard.pkg.engine.engine import EvaluationResult
from vulnguard.pkg.logging.logger import AuditLogger


class TestRemediationRollback:
    """Test cases for remediation rollback functionality."""
    
    @pytest.fixture
    def remediation_engine(self):
        """Create a RemediationEngine instance for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = RemediationEngine(
                logger=AuditLogger(),
                backup_directory=temp_dir,
                auto_backup=True,
                rollback_on_failure=True
            )
            yield engine
    
    @pytest.fixture
    def scan_result(self):
        """Create a ScanResult for testing."""
        return ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            title="Test Rule",
            description="Test description",
            rationale="Test rationale",
            check_command="test command",
            expected_state="compliant",
            actual_state="non_compliant",
            check_output="Test output",
            compliant=False,
            severity="medium",
            error=None
        )
    
    @pytest.fixture
    def evaluation_result(self):
        """Create an EvaluationResult for testing."""
        from vulnguard.pkg.engine.engine import EvaluationResult
        return EvaluationResult(
            rule_id="test_rule",
            benchmark="CIS",
            severity="medium",
            risk_level="medium",
            ai_assist_required=True,
            approval_required=False,
            confidence=0.8
        )
    
    def test_backup_files_creates_manifest(self, remediation_engine, scan_result):
        """Test that backup creates a manifest file."""
        files_to_backup = ["/etc/test/config1", "/etc/test/config2"]
        
        backup_path = remediation_engine._backup_files(
            files_to_backup=files_to_backup,
            rule_id=scan_result.rule_id
        )
        
        assert backup_path is not None
        assert os.path.exists(backup_path)
        
        # Check manifest file exists
        manifest_path = Path(backup_path) / ".backup_manifest.json"
        assert manifest_path.exists()
        
        # Verify manifest content
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        assert 'rule_id' in manifest
        assert 'files' in manifest
        assert 'timestamp' in manifest
        assert len(manifest['files']) == 2
    
    def test_backup_files_with_nonexistent_files(self, remediation_engine, scan_result):
        """Test backup with nonexistent files."""
        files_to_backup = ["/etc/nonexistent1", "/etc/nonexistent2"]
        
        backup_path = remediation_engine._backup_files(
            files_to_backup=files_to_backup,
            rule_id=scan_result.rule_id
        )
        
        # Should return None if no files exist
        assert backup_path is None
    
    def test_execute_rollback_with_manifest(self, remediation_engine, scan_result):
        """Test rollback with manifest file."""
        # First create a backup
        files_to_backup = ["/etc/test/config1"]
        backup_path = remediation_engine._backup_files(
            files_to_backup=files_to_backup,
            rule_id=scan_result.rule_id
        )
        
        # Now test rollback
        success, output = remediation_engine._execute_rollback(
            rollback_commands=[],
            backup_path=backup_path,
            dry_run=False
        )
        
        assert success is True
        assert "Restored" in output
    
    def test_execute_rollback_without_backup(self, remediation_engine):
        """Test rollback without backup directory."""
        success, output = remediation_engine._execute_rollback(
            rollback_commands=[],
            backup_path="/nonexistent/backup",
            dry_run=False
        )
        
        assert success is False
        assert "not found" in output.lower()
    
    def test_execute_rollback_dry_run(self, remediation_engine, scan_result):
        """Test rollback in dry-run mode."""
        # First create a backup
        files_to_backup = ["/etc/test/config1"]
        backup_path = remediation_engine._backup_files(
            files_to_backup=files_to_backup,
            rule_id=scan_result.rule_id
        )
        
        # Now test rollback in dry-run mode
        success, output = remediation_engine._execute_rollback(
            rollback_commands=[],
            backup_path=backup_path,
            dry_run=True
        )
        
        assert success is True
        assert "[DRY-RUN]" in output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

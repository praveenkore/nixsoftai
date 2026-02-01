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
Unit Tests for Command Validation Module

Tests the centralized command validation patterns and functions.
"""

import pytest
from vulnguard.pkg.security.command_validation import (
    get_default_command_allowlist,
    get_command_blocklist,
    merge_command_patterns,
    validate_command_list
)


class TestCommandValidation:
    """Test cases for command validation module."""
    
    def test_get_default_command_allowlist(self):
        """Test getting default command allow-list."""
        allowlist = get_default_command_allowlist()
        
        assert isinstance(allowlist, list)
        assert len(allowlist) > 0
        assert any('systemctl' in pattern for pattern in allowlist)
        assert any('sysctl' in pattern for pattern in allowlist)
    
    def test_get_command_blocklist(self):
        """Test getting command block-list."""
        blocklist = get_command_blocklist()
        
        assert isinstance(blocklist, list)
        assert len(blocklist) > 0
        assert any('rm' in pattern for pattern in blocklist)
        assert any('chmod' in pattern for pattern in blocklist)
    
    def test_merge_command_patterns_with_custom_allowlist(self):
        """Test merging custom command patterns."""
        custom_allowlist = [r'^custom\s+command$']
        
        allowlist, blocklist = merge_command_patterns(
            custom_allowlist=custom_allowlist,
            custom_blocklist=None
        )
        
        assert len(allowlist) == len(get_default_command_allowlist()) + 1
        assert any('custom' in pattern for pattern in allowlist)
    
    def test_merge_command_patterns_with_custom_blocklist(self):
        """Test merging custom command patterns."""
        custom_blocklist = [r'^custom\s+dangerous$']
        
        allowlist, blocklist = merge_command_patterns(
            custom_allowlist=None,
            custom_blocklist=custom_blocklist
        )
        
        assert len(blocklist) == len(get_command_blocklist()) + 1
        assert any('custom' in pattern for pattern in blocklist)
    
    def test_merge_command_patterns_with_both_custom(self):
        """Test merging both custom allow-list and block-list."""
        custom_allowlist = [r'^custom\s+command$']
        custom_blocklist = [r'^custom\s+dangerous$']
        
        allowlist, blocklist = merge_command_patterns(
            custom_allowlist=custom_allowlist,
            custom_blocklist=custom_blocklist
        )
        
        assert len(allowlist) == len(get_default_command_allowlist()) + 1
        assert len(blocklist) == len(get_command_blocklist()) + 1
    
    def test_validate_command_list_all_valid(self):
        """Test validating a list of valid commands."""
        commands = [
            'systemctl enable ssh',
            'sysctl -w net.ipv4.ip_forward=0',
            'chmod 644 /etc/ssh/sshd_config',
            'chown root:root /etc/ssh/sshd_config',
            'sed -i "s/^#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config',
            'echo "test" >> /etc/test.conf'
        ]
        
        allowlist, blocklist = merge_command_patterns()
        all_valid, errors = validate_command_list(commands, allowlist, blocklist)
        
        assert all_valid is True
        assert len(errors) == 0
    
    def test_validate_command_list_blocked_command(self):
        """Test validating a list with blocked command."""
        commands = ['rm -rf /']
        
        allowlist, blocklist = merge_command_patterns()
        all_valid, errors = validate_command_list(commands, allowlist, blocklist)
        
        assert all_valid is False
        assert len(errors) == 1
        assert 'blocked' in errors[0]
    
    def test_validate_command_list_not_in_allowlist(self):
        """Test validating a list with command not in allow-list."""
        commands = ['custom_command_not_in_allowlist']
        
        allowlist, blocklist = merge_command_patterns()
        all_valid, errors = validate_command_list(commands, allowlist, blocklist)
        
        assert all_valid is False
        assert len(errors) == 1
        assert 'not in allow-list' in errors[0]
    
    def test_validate_command_list_empty_list(self):
        """Test validating an empty command list."""
        commands = []
        
        allowlist, blocklist = merge_command_patterns()
        all_valid, errors = validate_command_list(commands, allowlist, blocklist)
        
        assert all_valid is True
        assert len(errors) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

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
Security Module - Phase 1 Critical Security Fixes

This module provides secure implementations for:
- Safe command execution (eliminating command injection)
- Secure file and directory permissions
- Atomic file operations (eliminating TOCTOU vulnerabilities)

All implementations follow enterprise-level security standards and are
designed to pass security audits and penetration testing.
"""

# Lazy imports to avoid circular dependencies
def _get_command_executor():
    from vulnguard.pkg.security.command_executor import SecureCommandExecutor
    return SecureCommandExecutor

def _get_file_permissions():
    from vulnguard.pkg.security.file_permissions import SecureFilePermissions
    return SecureFilePermissions

def _get_atomic_operations():
    from vulnguard.pkg.security.atomic_operations import AtomicFileOperations
    return AtomicFileOperations

__all__ = [
    'SecureCommandExecutor',
    'SecureFilePermissions',
    'AtomicFileOperations'
]

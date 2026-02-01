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
Secure File Permissions Module

Provides secure file and directory permission management that:
1. Applies secure default permissions (files: 0600, directories: 0700)
2. Audits all file creation operations
3. Enforces permission standards programmatically
4. Verifies inherited permissions are safe across platforms

This module is designed to pass security audits and penetration testing.
"""

import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnguard.pkg.logging.logger import AuditLogger


class PermissionError(Exception):
    """Raised when permission operation fails."""
    pass


class SecureFilePermissions:
    """
    Secure file and directory permission manager.
    
    Enforces secure default permissions and provides utilities
    for creating files and directories with proper permissions.
    
    Key security features:
    - Default file permissions: 0600 (owner read/write only)
    - Default directory permissions: 0700 (owner read/write/execute only)
    - Automatic permission enforcement on creation
    - Permission verification and auditing
    - Cross-platform compatibility
    
    Usage:
        permissions = SecureFilePermissions(logger=audit_logger)
        permissions.create_secure_file('/path/to/file', content='data')
        permissions.create_secure_directory('/path/to/dir')
    """
    
    # Secure default permissions
    DEFAULT_FILE_PERMISSIONS = 0o600  # rw------- (owner read/write only)
    DEFAULT_DIR_PERMISSIONS = 0o700   # rwx------ (owner read/write/execute only)
    
    # Maximum allowed permissions (for security auditing)
    MAX_FILE_PERMISSIONS = 0o644  # rw-r--r-- (owner read/write, group/others read)
    MAX_DIR_PERMISSIONS = 0o755   # rwxr-xr-x (owner full, group/others read/execute)
    
    # Temporary file permissions
    TEMP_FILE_PERMISSIONS = 0o600
    TEMP_DIR_PERMISSIONS = 0o700
    
    def __init__(
        self,
        logger: Any = None,
        default_file_permissions: int = DEFAULT_FILE_PERMISSIONS,
        default_dir_permissions: int = DEFAULT_DIR_PERMISSIONS,
        enforce_on_create: bool = True
    ):
        """
        Initialize secure file permissions manager.
        
        Args:
            logger: Optional audit logger instance
            default_file_permissions: Default permissions for files (octal)
            default_dir_permissions: Default permissions for directories (octal)
            enforce_on_create: Whether to enforce permissions on file creation
        """
        # Import at runtime to avoid circular dependency
        if logger is None:
            from vulnguard.pkg.logging.logger import AuditLogger as LoggerClass
            self.logger = LoggerClass()
        else:
            self.logger = logger
        self.default_file_permissions = default_file_permissions
        self.default_dir_permissions = default_dir_permissions
        self.enforce_on_create = enforce_on_create
        
        # Get current umask for auditing
        self.current_umask = os.umask(0)
        os.umask(self.current_umask)  # Restore original umask
    
    def _validate_permissions(self, permissions: int) -> None:
        """
        Validate that permissions are within acceptable range.
        
        Args:
            permissions: Permission mode (octal)
            
        Raises:
            PermissionError: If permissions are invalid
        """
        if not isinstance(permissions, int):
            raise PermissionError(
                f"Permissions must be an integer, got {type(permissions)}"
            )
        
        if permissions < 0o000 or permissions > 0o777:
            raise PermissionError(
                f"Permissions must be between 0o000 and 0o777, got {oct(permissions)}"
            )
    
    def get_file_permissions(self, file_path: str) -> int:
        """
        Get the current permissions of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Permission mode (octal)
            
        Raises:
            PermissionError: If file cannot be accessed
        """
        try:
            file_stat = os.stat(file_path)
            return stat.S_IMODE(file_stat.st_mode)
        except OSError as e:
            raise PermissionError(
                f"Failed to get permissions for {file_path}: {str(e)}"
            ) from e
    
    def set_file_permissions(
        self,
        file_path: str,
        permissions: int,
        verify: bool = True
    ) -> None:
        """
        Set permissions on a file or directory.
        
        Args:
            file_path: Path to the file or directory
            permissions: Permission mode (octal)
            verify: Whether to verify permissions were set correctly
            
        Raises:
            PermissionError: If permissions cannot be set
        """
        self._validate_permissions(permissions)
        
        try:
            os.chmod(file_path, permissions)
            
            if verify:
                actual_permissions = self.get_file_permissions(file_path)
                if actual_permissions != permissions:
                    raise PermissionError(
                        f"Failed to set permissions on {file_path}: "
                        f"expected {oct(permissions)}, got {oct(actual_permissions)}"
                    )
            
            self.logger.log_info(
                f"Set permissions on {file_path} to {oct(permissions)}"
            )
            
        except OSError as e:
            raise PermissionError(
                f"Failed to set permissions on {file_path}: {str(e)}"
            ) from e
    
    def verify_permissions(
        self,
        file_path: str,
        expected_permissions: int
    ) -> Tuple[bool, int]:
        """
        Verify that a file has the expected permissions.
        
        Args:
            file_path: Path to the file
            expected_permissions: Expected permission mode (octal)
            
        Returns:
            Tuple of (is_compliant, actual_permissions)
        """
        try:
            actual_permissions = self.get_file_permissions(file_path)
            is_compliant = actual_permissions == expected_permissions
            
            if not is_compliant:
                self.logger.log_warning(
                    f"Permission mismatch on {file_path}: "
                    f"expected {oct(expected_permissions)}, got {oct(actual_permissions)}"
                )
            
            return is_compliant, actual_permissions
            
        except PermissionError as e:
            self.logger.log_error(
                "permission_verification",
                f"Failed to verify permissions on {file_path}: {str(e)}",
                {"file_path": file_path}
            )
            return False, 0
    
    def create_secure_file(
        self,
        file_path: str,
        content: Optional[str] = None,
        permissions: Optional[int] = None,
        encoding: str = 'utf-8'
    ) -> None:
        """
        Create a file with secure permissions.
        
        Args:
            file_path: Path to the file to create
            content: Optional content to write to the file
            permissions: Optional custom permissions (uses default if not specified)
            encoding: File encoding (default: utf-8)
            
        Raises:
            PermissionError: If file cannot be created with secure permissions
        """
        if permissions is None:
            permissions = self.default_file_permissions
        
        self._validate_permissions(permissions)
        
        # Create parent directories if they don't exist
        parent_dir = Path(file_path).parent
        if parent_dir != Path('.') and not parent_dir.exists():
            self.create_secure_directory(str(parent_dir))
        
        try:
            # Create file with restrictive permissions first
            # Use os.open with O_CREAT | O_EXCL to create atomically
            fd = os.open(
                file_path,
                os.O_CREAT | os.O_WRONLY | os.O_EXCL,
                permissions
            )
            
            try:
                if content is not None:
                    os.write(fd, content.encode(encoding))
            finally:
                os.close(fd)
            
            # Verify permissions were set correctly
            if self.enforce_on_create:
                is_compliant, actual_perms = self.verify_permissions(
                    file_path,
                    permissions
                )
                if not is_compliant:
                    # Try to fix permissions
                    self.set_file_permissions(file_path, permissions)
            
            self.logger.log_info(
                f"Created secure file: {file_path} with permissions {oct(permissions)}"
            )
            
        except FileExistsError:
            # File already exists, set permissions
            self.set_file_permissions(file_path, permissions)
            
        except OSError as e:
            raise PermissionError(
                f"Failed to create secure file {file_path}: {str(e)}"
            ) from e
    
    def create_secure_directory(
        self,
        dir_path: str,
        permissions: Optional[int] = None,
        parents: bool = True
    ) -> None:
        """
        Create a directory with secure permissions.
        
        Args:
            dir_path: Path to the directory to create
            permissions: Optional custom permissions (uses default if not specified)
            parents: Whether to create parent directories
            
        Raises:
            PermissionError: If directory cannot be created with secure permissions
        """
        if permissions is None:
            permissions = self.default_dir_permissions
        
        self._validate_permissions(permissions)
        
        try:
            # Create directory with secure permissions
            if parents:
                Path(dir_path).mkdir(parents=True, exist_ok=True, mode=permissions)
            else:
                Path(dir_path).mkdir(mode=permissions, exist_ok=False)
            
            # Verify permissions were set correctly
            if self.enforce_on_create:
                is_compliant, actual_perms = self.verify_permissions(
                    dir_path,
                    permissions
                )
                if not is_compliant:
                    # Try to fix permissions
                    self.set_file_permissions(dir_path, permissions)
            
            self.logger.log_info(
                f"Created secure directory: {dir_path} with permissions {oct(permissions)}"
            )
            
        except OSError as e:
            raise PermissionError(
                f"Failed to create secure directory {dir_path}: {str(e)}"
            ) from e
    
    def create_temp_file(
        self,
        prefix: str = 'vulnguard_',
        suffix: str = '.tmp',
        content: Optional[str] = None,
        encoding: str = 'utf-8'
    ) -> str:
        """
        Create a temporary file with secure permissions.
        
        Args:
            prefix: Prefix for the temporary file name
            suffix: Suffix for the temporary file name
            content: Optional content to write to the file
            encoding: File encoding
            
        Returns:
            Path to the created temporary file
        """
        try:
            # Create temp file with secure permissions
            fd, temp_path = tempfile.mkstemp(
                prefix=prefix,
                suffix=suffix,
                mode=self.TEMP_FILE_PERMISSIONS
            )
            
            try:
                if content is not None:
                    os.write(fd, content.encode(encoding))
            finally:
                os.close(fd)
            
            # Ensure permissions are correct (some systems may override)
            self.set_file_permissions(temp_path, self.TEMP_FILE_PERMISSIONS)
            
            self.logger.log_info(
                f"Created secure temp file: {temp_path}"
            )
            
            return temp_path
            
        except OSError as e:
            raise PermissionError(
                f"Failed to create temporary file: {str(e)}"
            ) from e
    
    def create_temp_directory(
        self,
        prefix: str = 'vulnguard_'
    ) -> str:
        """
        Create a temporary directory with secure permissions.
        
        Args:
            prefix: Prefix for the temporary directory name
            
        Returns:
            Path to the created temporary directory
        """
        try:
            # Create temp directory with secure permissions
            temp_path = tempfile.mkdtemp(
                prefix=prefix,
                mode=self.TEMP_DIR_PERMISSIONS
            )
            
            # Ensure permissions are correct
            self.set_file_permissions(temp_path, self.TEMP_DIR_PERMISSIONS)
            
            self.logger.log_info(
                f"Created secure temp directory: {temp_path}"
            )
            
            return temp_path
            
        except OSError as e:
            raise PermissionError(
                f"Failed to create temporary directory: {str(e)}"
            ) from e
    
    def audit_directory_permissions(
        self,
        directory: str,
        recursive: bool = True,
        max_file_perms: int = MAX_FILE_PERMISSIONS,
        max_dir_perms: int = MAX_DIR_PERMISSIONS
    ) -> dict:
        """
        Audit permissions in a directory.
        
        Args:
            directory: Directory to audit
            recursive: Whether to audit recursively
            max_file_perms: Maximum allowed file permissions
            max_dir_perms: Maximum allowed directory permissions
            
        Returns:
            Dictionary with audit results
        """
        audit_results = {
            'directory': directory,
            'compliant': True,
            'total_files': 0,
            'total_dirs': 0,
            'non_compliant_files': [],
            'non_compliant_dirs': []
        }
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    # Check directories
                    for d in dirs:
                        dir_path = os.path.join(root, d)
                        perms = self.get_file_permissions(dir_path)
                        audit_results['total_dirs'] += 1
                        
                        if perms > max_dir_perms:
                            audit_results['compliant'] = False
                            audit_results['non_compliant_dirs'].append({
                                'path': dir_path,
                                'permissions': oct(perms),
                                'max_allowed': oct(max_dir_perms)
                            })
                    
                    # Check files
                    for f in files:
                        file_path = os.path.join(root, f)
                        perms = self.get_file_permissions(file_path)
                        audit_results['total_files'] += 1
                        
                        if perms > max_file_perms:
                            audit_results['compliant'] = False
                            audit_results['non_compliant_files'].append({
                                'path': file_path,
                                'permissions': oct(perms),
                                'max_allowed': oct(max_file_perms)
                            })
            else:
                # Audit only top-level directory
                perms = self.get_file_permissions(directory)
                audit_results['total_dirs'] += 1
                
                if perms > max_dir_perms:
                    audit_results['compliant'] = False
                    audit_results['non_compliant_dirs'].append({
                        'path': directory,
                        'permissions': oct(perms),
                        'max_allowed': oct(max_dir_perms)
                    })
                
                # Check immediate files
                for item in os.listdir(directory):
                    item_path = os.path.join(directory, item)
                    if os.path.isfile(item_path):
                        perms = self.get_file_permissions(item_path)
                        audit_results['total_files'] += 1
                        
                        if perms > max_file_perms:
                            audit_results['compliant'] = False
                            audit_results['non_compliant_files'].append({
                                'path': item_path,
                                'permissions': oct(perms),
                                'max_allowed': oct(max_file_perms)
                            })
            
            self.logger.log_info(
                f"Permission audit completed for {directory}: "
                f"compliant={audit_results['compliant']}, "
                f"files={audit_results['total_files']}, "
                f"dirs={audit_results['total_dirs']}"
            )
            
        except OSError as e:
            self.logger.log_error(
                "permission_audit",
                f"Failed to audit permissions in {directory}: {str(e)}",
                {"directory": directory}
            )
            audit_results['error'] = str(e)
        
        return audit_results


# Convenience function for backward compatibility
def create_secure_file(
    file_path: str,
    content: Optional[str] = None,
    permissions: int = 0o600,
    logger: Optional["AuditLogger"] = None
) -> None:
    """
    Convenience function to create a file with secure permissions.
    
    Args:
        file_path: Path to the file to create
        content: Optional content to write
        permissions: File permissions (default: 0o600)
        logger: Optional audit logger
    """
    manager = SecureFilePermissions(logger=logger)
    manager.create_secure_file(file_path, content, permissions)


def create_secure_directory(
    dir_path: str,
    permissions: int = 0o700,
    logger: Optional["AuditLogger"] = None
) -> None:
    """
    Convenience function to create a directory with secure permissions.
    
    Args:
        dir_path: Path to the directory to create
        permissions: Directory permissions (default: 0o700)
        logger: Optional audit logger
    """
    manager = SecureFilePermissions(logger=logger)
    manager.create_secure_directory(dir_path, permissions)

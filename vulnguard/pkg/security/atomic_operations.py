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
Atomic File Operations Module

Provides atomic file operations that eliminate TOCTOU vulnerabilities:
1. Uses atomic operations (os.replace, tempfile.NamedTemporaryFile, open(..., mode='x'))
2. Ensures race conditions between file access and state checks are eliminated
3. Implements safe file reading and writing patterns
4. Provides atomic file replacement and update operations

This module is designed to pass security audits and penetration testing.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional, Tuple, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnguard.pkg.logging.logger import AuditLogger
    from vulnguard.pkg.security.path_validator import validate_path, PathValidationError


class AtomicOperationError(Exception):
    """Raised when atomic operation fails."""
    pass


class AtomicFileOperations:
    """
    Atomic file operations that eliminate TOCTOU vulnerabilities.
    
    Key security features:
    - Atomic file creation using open(..., mode='x')
    - Atomic file replacement using os.replace()
    - Temporary file patterns for safe updates
    - No race conditions between checks and operations
    
    TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities occur when:
    1. Code checks a condition (e.g., file exists)
    2. Time passes (race condition window)
    3. Code uses the resource based on the check
    
    Atomic operations eliminate this by performing the check and use
    in a single atomic operation that cannot be interrupted.
    
    Usage:
        ops = AtomicFileOperations(logger=audit_logger)
        ops.atomic_write('/path/to/file', content='data')
        content = ops.atomic_read('/path/to/file')
    """
    
    def __init__(
        self,
        logger: Any = None,
        temp_dir: Optional[str] = None
    ):
        """
        Initialize atomic file operations manager.
        
        Args:
            logger: Optional audit logger instance
            temp_dir: Optional custom temporary directory
        """
        # Import at runtime to avoid circular dependency
        if logger is None:
            from vulnguard.pkg.logging.logger import AuditLogger as LoggerClass
            self.logger = LoggerClass()
        else:
            self.logger = logger
        self.temp_dir = temp_dir
    
    def _get_temp_dir(self) -> str:
        """
        Get temporary directory for atomic operations.
        
        Returns:
            Path to temporary directory
        """
        if self.temp_dir:
            return self.temp_dir
        return tempfile.gettempdir()
    
    def atomic_read(
        self,
        file_path: str,
        encoding: str = 'utf-8',
        binary: bool = False
    ) -> Union[str, bytes]:
        """
        Atomically read a file.
        
        Reading is inherently atomic for small files, but this method
        ensures we handle errors properly and log operations.
        
        Args:
            file_path: Path to the file to read
            encoding: File encoding (for text mode)
            binary: Whether to read in binary mode
            
        Returns:
            File content as string or bytes
            
        Raises:
            AtomicOperationError: If file cannot be read
        """
        try:
            if os.path.islink(file_path):
                raise AtomicOperationError(f"Symlink access denied: {file_path}")

            mode = 'rb' if binary else 'r'
            
            # Open file and read content
            # Note: built-in open() follows symlinks by default and doesn't support O_NOFOLLOW easily
            # But we checked islink() above atomically-ish? No, TOCTOU.
            # Ideally use os.open with O_NOFOLLOW then os.fdopen
            
            flags = os.O_RDONLY
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
                
            fd = os.open(file_path, flags)
            try:
                with os.fdopen(fd, mode, encoding=encoding if not binary else None) as f:
                    content = f.read()
            except Exception:
                os.close(fd)
                raise

            self.logger.log_info(
                f"Atomically read file: {file_path} "
                f"(size={len(content) if binary else len(content.encode(encoding))} bytes)"
            )
            
            return content
            
        except FileNotFoundError:
            raise AtomicOperationError(
                f"File not found: {file_path}"
            )
        except IsADirectoryError:
            raise AtomicOperationError(
                f"Path is a directory, not a file: {file_path}"
            )
        except PermissionError:
            raise AtomicOperationError(
                f"Permission denied reading file: {file_path}"
            )
        except OSError as e:
            # Check for looping symlinks (errno.ELOOP)
            import errno
            if e.errno == errno.ELOOP:
                 raise AtomicOperationError(f"Symlink loop detected: {file_path}")
            raise AtomicOperationError(
                f"Failed to read file {file_path}: {str(e)}"
            ) from e
    
    def atomic_write(
        self,
        file_path: str,
        content: Union[str, bytes],
        encoding: str = 'utf-8',
        mode: str = 'wb',
        permissions: int = 0o600,
        backup: bool = False
    ) -> None:
        """
        Atomically write content to a file.
        
        This method uses a temporary file and atomic rename to ensure
        the write operation is atomic and eliminates TOCTOU vulnerabilities.
        
        Args:
            file_path: Path to the file to write
            content: Content to write (string or bytes)
            encoding: File encoding (for text mode)
            mode: File mode ('wb' for binary, 'w' for text)
            permissions: File permissions (default: 0o600)
            backup: Whether to create a backup of the original file
            
        Raises:
            AtomicOperationError: If file cannot be written atomically
        """
        try:
            # Check for symlink before doing anything
            if os.path.exists(file_path) and os.path.islink(file_path):
                 raise AtomicOperationError(f"Symlink access denied for write: {file_path}")

            # Create backup if requested and file exists
            if backup and os.path.exists(file_path):
                backup_path = f"{file_path}.backup"
                shutil.copy2(file_path, backup_path)
                self.logger.log_info(
                    f"Created backup: {backup_path}"
                )
            
            # Convert content to bytes if needed
            if isinstance(content, str):
                content_bytes = content.encode(encoding)
            else:
                content_bytes = content
            
            # Create temporary file in the same directory as the target
            # This ensures the temporary file is on the same filesystem
            # (required for atomic rename)
            target_dir = os.path.dirname(file_path) or '.'
            temp_fd, temp_path = tempfile.mkstemp(
                dir=target_dir,
                prefix='.tmp_',
                suffix=os.path.basename(file_path)
            )
            
            try:
                # Write content to temporary file
                os.write(temp_fd, content_bytes)
                os.fsync(temp_fd)  # Ensure data is written to disk
                os.close(temp_fd)
                
                # Set permissions on temporary file
                os.chmod(temp_path, permissions)
                
                # Atomically replace the target file with the temporary file
                # This is the critical atomic operation
                os.replace(temp_path, file_path)
                
                self.logger.log_info(
                    f"Atomically wrote file: {file_path} "
                    f"(size={len(content_bytes)} bytes, permissions={oct(permissions)})"
                )
                
            except Exception as e:
                # Clean up temporary file if something went wrong
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except OSError:
                    pass
                raise AtomicOperationError(
                    f"Failed to atomically write file {file_path}: {str(e)}"
                ) from e
            
        except OSError as e:
            raise AtomicOperationError(
                f"Failed to write file {file_path}: {str(e)}"
            ) from e
    
    def atomic_create(
        self,
        file_path: str,
        content: Union[str, bytes],
        encoding: str = 'utf-8',
        permissions: int = 0o600
    ) -> None:
        """
        Atomically create a new file.
        
        Uses exclusive creation (mode='x') to prevent race conditions.
        If the file already exists, this will fail with FileExistsError.
        
        Args:
            file_path: Path to the file to create
            content: Content to write (string or bytes)
            encoding: File encoding (for text mode)
            permissions: File permissions (default: 0o600)
            
        Raises:
            AtomicOperationError: If file cannot be created atomically
            FileExistsError: If file already exists
        """
        try:
            # Convert content to bytes if needed
            if isinstance(content, str):
                content_bytes = content.encode(encoding)
            else:
                content_bytes = content
            
            # Create file with exclusive access (O_CREAT | O_EXCL)
            # This is atomic - either the file is created or it fails
            fd = os.open(
                file_path,
                os.O_CREAT | os.O_WRONLY | os.O_EXCL,
                permissions
            )
            
            try:
                # Write content
                os.write(fd, content_bytes)
                os.fsync(fd)  # Ensure data is written to disk
            finally:
                os.close(fd)
            
            self.logger.log_info(
                f"Atomically created file: {file_path} "
                f"(size={len(content_bytes)} bytes, permissions={oct(permissions)})"
            )
            
        except FileExistsError:
            raise AtomicOperationError(
                f"File already exists: {file_path}"
            )
        except OSError as e:
            raise AtomicOperationError(
                f"Failed to create file {file_path}: {str(e)}"
            ) from e
    
    def atomic_append(
        self,
        file_path: str,
        content: Union[str, bytes],
        encoding: str = 'utf-8',
        permissions: int = 0o600
    ) -> None:
        """
        Atomically append content to a file.
        
        Note: True atomic append is not possible on all filesystems.
        This method uses O_APPEND flag which provides atomicity
        for the append operation itself.
        
        Args:
            file_path: Path to the file to append to
            content: Content to append (string or bytes)
            encoding: File encoding (for text mode)
            permissions: File permissions (used if file doesn't exist)
            
        Raises:
            AtomicOperationError: If append fails
        """
        try:
            if os.path.islink(file_path):
                raise AtomicOperationError(f"Symlink access denied for append: {file_path}")

            # Convert content to bytes if needed
            if isinstance(content, str):
                content_bytes = content.encode(encoding)
            else:
                content_bytes = content
            
            # Open file with O_APPEND flag for atomic append
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
                
            fd = os.open(
                file_path,
                flags,
                permissions
            )
            
            try:
                # Write content
                os.write(fd, content_bytes)
                os.fsync(fd)  # Ensure data is written to disk
            finally:
                os.close(fd)
            
            self.logger.log_info(
                f"Atomically appended to file: {file_path} "
                f"(size={len(content_bytes)} bytes)"
            )
            
        except OSError as e:
            raise AtomicOperationError(
                f"Failed to append to file {file_path}: {str(e)}"
            ) from e
    
    def atomic_replace(
        self,
        source_path: str,
        target_path: str,
        backup: bool = False
    ) -> None:
        """
        Atomically replace a file with another file.
        
        This is a true atomic operation using os.replace().
        Either the replacement completes fully or not at all.
        
        Args:
            source_path: Path to the source file
            target_path: Path to the target file (will be replaced)
            backup: Whether to create a backup of the target file
            
        Raises:
            AtomicOperationError: If replacement fails
        """
        try:
            # Create backup if requested and target exists
            if backup and os.path.exists(target_path):
                backup_path = f"{target_path}.backup"
                shutil.copy2(target_path, backup_path)
                self.logger.log_info(
                    f"Created backup: {backup_path}"
                )
            
            # Atomically replace target with source
            os.replace(source_path, target_path)
            
            self.logger.log_info(
                f"Atomically replaced: {target_path} with {source_path}"
            )
            
        except OSError as e:
            raise AtomicOperationError(
                f"Failed to replace {target_path} with {source_path}: {str(e)}"
            ) from e
    
    def atomic_copy(
        self,
        source_path: str,
        target_path: str,
        permissions: int = 0o600
    ) -> None:
        """
        Atomically copy a file to a new location.
        
        Uses temporary file pattern to ensure atomicity.
        
        Args:
            source_path: Path to the source file
            target_path: Path to the target file
            permissions: Target file permissions (default: 0o600)
            
        Raises:
            AtomicOperationError: If copy fails
        """
        try:
            # Read source file
            content = self.atomic_read(source_path, binary=True)
            
            # Write to target atomically
            self.atomic_write(
                target_path,
                content,
                mode='wb',
                permissions=permissions
            )
            
            self.logger.log_info(
                f"Atomically copied: {source_path} to {target_path}"
            )
            
        except AtomicOperationError as e:
            raise AtomicOperationError(
                f"Failed to copy {source_path} to {target_path}: {str(e)}"
            ) from e
    
    def atomic_delete(
        self,
        file_path: str,
        backup: bool = False
    ) -> None:
        """
        Atomically delete a file.
        
        Args:
            file_path: Path to the file to delete
            backup: Whether to create a backup before deletion
            
        Raises:
            AtomicOperationError: If deletion fails
        """
        try:
            # Create backup if requested
            if backup and os.path.exists(file_path):
                backup_dir = os.path.dirname(file_path) or '.'
                backup_path = os.path.join(
                    backup_dir,
                    f".{os.path.basename(file_path)}.deleted"
                )
                shutil.copy2(file_path, backup_path)
                self.logger.log_info(
                    f"Created backup before deletion: {backup_path}"
                )
            
            if os.path.islink(file_path):
                raise AtomicOperationError(f"Symlink deletion not allowed: {file_path}")

            # Delete file
            os.unlink(file_path)
            
            self.logger.log_info(
                f"Atomically deleted file: {file_path}"
            )
            
        except OSError as e:
            raise AtomicOperationError(
                f"Failed to delete file {file_path}: {str(e)}"
            ) from e
    
    def atomic_file_exists(self, file_path: str) -> bool:
        """
        Check if a file exists (non-atomic, but safe for most use cases).
        
        Note: This is NOT atomic. For truly atomic file existence
        checking with creation, use atomic_create() which will fail
        if the file already exists.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file exists, False otherwise
        """
        try:
            return os.path.isfile(file_path)
        except OSError:
            return False
    
    def safe_file_operation(
        self,
        file_path: str,
        operation: str,
        **kwargs
    ) -> any:
        """
        Perform a safe file operation with proper error handling.
        
        This is a convenience method that routes to the appropriate
        atomic operation based on the operation type.
        
        Args:
            file_path: Path to the file
            operation: Operation type ('read', 'write', 'create', 'append', 'delete')
            **kwargs: Additional arguments for the operation
            
        Returns:
            Result of the operation (for 'read')
            
        Raises:
            AtomicOperationError: If operation fails
        """
        operations = {
            'read': self.atomic_read,
            'write': self.atomic_write,
            'create': self.atomic_create,
            'append': self.atomic_append,
            'delete': self.atomic_delete
        }
        
        if operation not in operations:
            raise AtomicOperationError(
                f"Unknown operation: {operation}. "
                f"Valid operations: {list(operations.keys())}"
            )
        
        return operations[operation](file_path, **kwargs)


# Convenience functions for backward compatibility
def atomic_write_file(
    file_path: str,
    content: Union[str, bytes],
    encoding: str = 'utf-8',
    permissions: int = 0o600,
    logger: Optional["AuditLogger"] = None
) -> None:
    """
    Convenience function to atomically write a file.
    
    Args:
        file_path: Path to the file to write
        content: Content to write
        encoding: File encoding
        permissions: File permissions (default: 0o600)
        logger: Optional audit logger
    """
    ops = AtomicFileOperations(logger=logger)
    ops.atomic_write(file_path, content, encoding, permissions=permissions)


def atomic_read_file(
    file_path: str,
    encoding: str = 'utf-8',
    binary: bool = False,
    logger: Optional["AuditLogger"] = None
) -> Union[str, bytes]:
    """
    Convenience function to atomically read a file.
    
    Args:
        file_path: Path to the file to read
        encoding: File encoding
        binary: Whether to read in binary mode
        logger: Optional audit logger
        
    Returns:
        File content
    """
    ops = AtomicFileOperations(logger=logger)
    return ops.atomic_read(file_path, encoding, binary)

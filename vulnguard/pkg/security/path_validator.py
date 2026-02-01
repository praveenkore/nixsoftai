# VulnGuard - Linux Security Compliance Agent
# Copyright (c) Nixsoft Technologies Pvt. Ltd.

import os
from pathlib import Path
from typing import Optional, List, Union

class PathValidationError(Exception):
    """Raised when path validation fails."""
    pass

def validate_path(
    path: Union[str, Path], 
    base_dir: Optional[Union[str, Path]] = None, 
    must_exist: bool = False,
    allow_symlinks: bool = False
) -> Path:
    """
    Validate a file path for security.
    
    Args:
        path: The path to validate.
        base_dir: Optional base directory to restrict the path to.
        must_exist: If True, the path must exist.
        allow_symlinks: If True, allow the path to be a symlink (not recommended).
        
    Returns:
        The resolved absolute Path object.
        
    Raises:
        PathValidationError: If validation fails.
    """
    try:
        # Convert to Path object
        path_obj = Path(path)
        
        # Check existence if required
        if must_exist and not path_obj.exists():
            raise PathValidationError(f"Path does not exist: {path}")
            
        # Resolve path (handle symlinks and ..)
        # Note: strict=True in resolve() checks existence, preventing resolution of non-existent paths if we wanted that.
        # But for new files, we might want to resolve parent.
        # Here we just use resolve() which might fail on Windows for non-existent paths if strict is default (False in 3.10+?)
        # On Python 3.8+, strict=False is default.
        try:
            abs_path = path_obj.resolve()
        except OSError as e:
            # If path doesn't exist and we didn't require it, we can use abspath fallback
            if not must_exist:
                abs_path = Path(os.path.abspath(str(path_obj)))
            else:
                raise PathValidationError(f"Failed to resolve path: {e}")

        # Check for symlinks if they exist and are not allowed
        if not allow_symlinks and path_obj.exists():
             if path_obj.is_symlink():
                 raise PathValidationError(f"Path is a symlink: {path}")
             # Check if resolved path is different (implicit symlink check in parent components? no resolve handles that)
             # But if the final component is a symlink, resolve() follows it.
             # If we want to ban symlinks, we should check is_symlink() on the original path_obj (if it exists)
             
        # Restrict to base directory
        if base_dir:
            base_path = Path(base_dir).resolve()
            # Use commonpath to check containment
            # We need to ensure string comparison is safe
            try:
                # commonpath works on paths.
                # If abs_path is /var/log/app.log and base is /var/log
                # commonpath should be /var/log
                common = os.path.commonpath([str(base_path), str(abs_path)])
                if str(common) != str(base_path):
                     raise PathValidationError(f"Path traversal detected: {abs_path} is not within {base_path}")
            except ValueError:
                # Can happen on Windows if drives are different
                raise PathValidationError(f"Path traversal detected or different drive: {abs_path} vs {base_path}")

        return abs_path

    except Exception as e:
        if isinstance(e, PathValidationError):
            raise
        raise PathValidationError(f"Unexpected error validating path {path}: {str(e)}")

def is_safe_path(path: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> bool:
    """Check if a path is safe without raising exception."""
    try:
        validate_path(path, base_dir=base_dir)
        return True
    except PathValidationError:
        return False

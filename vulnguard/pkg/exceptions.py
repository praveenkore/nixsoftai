# VulnGuard - Linux Security Compliance Agent
# Copyright (c) Nixsoft Technologies Pvt. Ltd.

"""
Exceptions Module - Custom Exception Hierarchy

Defines the base VulnGuardException and specific subclasses for different
error categories.
"""

class VulnGuardException(Exception):
    """Base class for all VulnGuard exceptions."""
    def __init__(self, message: str, original_exception: Exception = None):
        super().__init__(message)
        self.original_exception = original_exception

class ConfigurationError(VulnGuardException):
    """Raised when there is a configuration error."""
    pass

class RuleLoadError(VulnGuardException):
    """Raised when a rule file cannot be loaded or validated."""
    pass

class ScanError(VulnGuardException):
    """Raised during the scanning process."""
    pass

class RemediationError(VulnGuardException):
    """Raised during the remediation process."""
    pass

class SecurityError(VulnGuardException):
    """Raised when a security violation is detected."""
    pass

class AIAdvisorError(VulnGuardException):
    """Raised during AI advisory generation."""
    pass

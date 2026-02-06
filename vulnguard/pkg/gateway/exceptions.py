
"""
Gateway Exceptions.

Custom exceptions for the VulnGuard Gateway client.
"""

from vulnguard.pkg.exceptions import VulnGuardException

class GatewayError(VulnGuardException):
    """Base class for all Gateway related errors."""
    pass

class GatewayConnectionError(GatewayError):
    """Raised when the client cannot connect to the C2 server."""
    pass

class GatewayAuthenticationError(GatewayError):
    """Raised when authentication with the C2 server fails."""
    pass

class GatewayPayloadError(GatewayError):
    """Raised when the payload is malformed or rejected by the server."""
    pass

class GatewaySecurityError(GatewayError):
    """Raised when a security check fails (e.g., certificate pinning)."""
    pass

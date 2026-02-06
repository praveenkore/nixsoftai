
"""
Gateway Client.

Handles communication with the Centralized C2 Server.
Supports pushing JSON reports securely with TLS certificate pinning.
"""

import hashlib
import json
import logging
import ssl
from typing import Any, Dict, Optional
import httpx
from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.gateway.exceptions import (
    GatewayConnectionError,
    GatewayAuthenticationError,
    GatewayPayloadError,
    GatewaySecurityError
)

class GatewayClient:
    """
    Client for communicating with the VulnGuard C2 Server.
    
    Supports TLS certificate pinning for enhanced security.
    """
    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        logger: Optional[AuditLogger] = None,
        pinned_cert_fingerprint: Optional[str] = None,
        fingerprint_algorithm: str = "sha256"
    ):
        """
        Initialize the Gateway client.
        
        Args:
            server_url: URL of the C2 server
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
            logger: Optional audit logger instance
            pinned_cert_fingerprint: Optional SHA-256 fingerprint of the expected server certificate
            fingerprint_algorithm: Hash algorithm for certificate fingerprint (default: sha256)
        """
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.logger = logger or AuditLogger()
        self.pinned_cert_fingerprint = pinned_cert_fingerprint
        self.fingerprint_algorithm = fingerprint_algorithm
        
        # Create SSL context with certificate pinning if fingerprint provided
        ssl_context = self._create_ssl_context() if verify_ssl else False
        
        # Initialize HTTP client
        self.client = httpx.Client(
            base_url=self.server_url,
            verify=ssl_context if ssl_context else verify_ssl,
            timeout=30.0
        )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context with certificate pinning support.
        
        Returns:
            SSLContext configured with certificate pinning
        """
        context = ssl.create_default_context()
        
        if self.pinned_cert_fingerprint:
            # Wrap the original wrap_socket to add fingerprint verification
            original_wrap_socket = context.wrap_socket
            
            def wrap_socket_with_pinning(*args, **kwargs):
                sock = original_wrap_socket(*args, **kwargs)
                
                # Get the peer certificate in binary form
                cert_binary = sock.getpeercert(binary_form=True)
                if cert_binary:
                    # Calculate fingerprint
                    if self.fingerprint_algorithm.lower() == "sha256":
                        fingerprint = hashlib.sha256(cert_binary).hexdigest()
                    elif self.fingerprint_algorithm.lower() == "sha1":
                        fingerprint = hashlib.sha1(cert_binary).hexdigest()
                    else:
                        fingerprint = hashlib.new(
                            self.fingerprint_algorithm, 
                            cert_binary
                        ).hexdigest()
                    
                    # Verify fingerprint matches expected value
                    expected = self.pinned_cert_fingerprint.lower().replace(':', '').replace(' ', '')
                    actual = fingerprint.lower()
                    
                    if actual != expected:
                        self.logger.log_error(
                            "gateway_security",
                            f"Certificate pinning failed. Expected: {expected}, Got: {actual}"
                        )
                        raise GatewaySecurityError(
                            f"Certificate pinning failed. Expected: {expected}, Got: {actual}"
                        )
                    
                    self.logger.log_info(
                        f"Certificate pinning verification successful for {self.server_url}"
                    )
                
                return sock
            
            context.wrap_socket = wrap_socket_with_pinning
        
        return context
    
    def verify_certificate_pinning(self) -> bool:
        """
        Verify that the server certificate matches the pinned fingerprint.
        
        Returns:
            True if pinning verification succeeds or no pinning is configured
            
        Raises:
            GatewaySecurityError: If certificate pinning verification fails
        """
        if not self.pinned_cert_fingerprint:
            return True
        
        try:
            # Make a test connection to verify the certificate
            test_client = httpx.Client(
                base_url=self.server_url,
                verify=self._create_ssl_context(),
                timeout=10.0
            )
            test_client.get("/")
            test_client.close()
            return True
        except GatewaySecurityError:
            raise
        except Exception as e:
            self.logger.log_error(
                "gateway_security",
                f"Failed to verify certificate pinning: {str(e)}"
            )
            raise GatewaySecurityError(f"Certificate pinning verification failed: {str(e)}")

    def _get_headers(self) -> Dict[str, str]:
        """Generate headers for the request."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnGuard-Agent/1.1.0"
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def send_report(self, report_data: Dict[str, Any]) -> bool:
        """
        Send a JSON compliance report to the C2 server.
        
        Args:
            report_data: Dictionary containing the report
            
        Returns:
            bool: True if successful
            
        Raises:
            GatewayConnectionError: If server is unreachable
            GatewayAuthenticationError: If API key is invalid
            GatewayPayloadError: If server rejects the data
        """
        endpoint = "/api/v1/agent/report"
        headers = self._get_headers()
        
        self.logger.log_info(f"Sending compliance report to {self.server_url}{endpoint}")
        
        try:
            response = self.client.post(
                endpoint,
                json=report_data,
                headers=headers
            )
            
            # Handle specific status codes
            if response.status_code == 201 or response.status_code == 200:
                self.logger.log_info("Successfully pushed report to C2 server.")
                return True
            
            elif response.status_code == 401 or response.status_code == 403:
                error_msg = f"Authentication failed with C2 server: {response.status_code}"
                self.logger.log_error("gateway_auth_error", error_msg)
                raise GatewayAuthenticationError(error_msg)
            
            elif response.status_code >= 400 and response.status_code < 500:
                error_msg = f"C2 server rejected payload: {response.status_code} - {response.text}"
                self.logger.log_error("gateway_payload_error", error_msg)
                raise GatewayPayloadError(error_msg)
            
            else:
                error_msg = f"Unexpected server error: {response.status_code}"
                self.logger.log_error("gateway_server_error", error_msg)
                raise GatewayConnectionError(error_msg)
                
        except httpx.ConnectError as e:
            error_msg = f"Failed to connect to C2 server: {str(e)}"
            self.logger.log_error("gateway_connection_error", error_msg)
            raise GatewayConnectionError(error_msg)
        
        except httpx.HTTPError as e:
            error_msg = f"HTTP error during communication with C2: {str(e)}"
            self.logger.log_error("gateway_http_error", error_msg)
            raise GatewayConnectionError(error_msg)

    def close(self):
        """Close the underlying HTTP client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

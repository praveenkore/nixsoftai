
"""
Gateway Client.

Handles communication with the Centralized C2 Server.
Supports pushing JSON reports securely.
"""

import json
import logging
from typing import Any, Dict, Optional
import httpx
from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.gateway.exceptions import (
    GatewayConnectionError,
    GatewayAuthenticationError,
    GatewayPayloadError
)

class GatewayClient:
    """
    Client for communicating with the VulnGuard C2 Server.
    """
    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        logger: Optional[AuditLogger] = None
    ):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.logger = logger or AuditLogger()
        
        # Initialize HTTP client
        self.client = httpx.Client(
            base_url=self.server_url,
            verify=self.verify_ssl,
            timeout=30.0
        )

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

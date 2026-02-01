
import unittest
from unittest.mock import MagicMock, patch
import json
import httpx
from vulnguard.pkg.gateway.client import GatewayClient
from vulnguard.pkg.gateway.exceptions import (
    GatewayConnectionError,
    GatewayAuthenticationError,
    GatewayPayloadError
)
from vulnguard.pkg.logging.logger import AuditLogger

class TestGatewayClient(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock(spec=AuditLogger)
        self.server_url = "https://c2.test:8443"
        self.api_key = "test-api-key"
        self.client = GatewayClient(
            server_url=self.server_url,
            api_key=self.api_key,
            logger=self.logger
        )

    def test_headers_include_api_key(self):
        headers = self.client._get_headers()
        self.assertEqual(headers["X-API-Key"], self.api_key)
        self.assertEqual(headers["Content-Type"], "application/json")

    @patch("httpx.Client.post")
    def test_send_report_success(self, mock_post):
        # Setup mock response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        report_data = {"test": "data"}
        result = self.client.send_report(report_data)
        
        self.assertTrue(result)
        mock_post.assert_called_once()
        # Verify JSON payload
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"], report_data)

    @patch("httpx.Client.post")
    def test_send_report_auth_failure(self, mock_post):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        with self.assertRaises(GatewayAuthenticationError):
            self.client.send_report({"test": "data"})

    @patch("httpx.Client.post")
    def test_send_report_payload_error(self, mock_post):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 400
        mock_response.text = "Invalid format"
        mock_post.return_value = mock_response

        with self.assertRaises(GatewayPayloadError):
            self.client.send_report({"test": "data"})

    @patch("httpx.Client.post")
    def test_send_report_connection_error(self, mock_post):
        mock_post.side_effect = httpx.ConnectError("Connection refused")

        with self.assertRaises(GatewayConnectionError):
            self.client.send_report({"test": "data"})

if __name__ == "__main__":
    unittest.main()

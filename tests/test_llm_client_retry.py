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
Unit Tests for LLM Client Retry Logic and Rate Limiting

Tests the retry decorator, rate limiter, and connection pooling functionality.
"""

import time
import pytest
from unittest.mock import Mock, patch
from vulnguard.pkg.advisor.llm_client import (
    RateLimiter,
    retry_with_exponential_backoff,
    get_shared_http_client,
    close_http_clients
)


class TestRateLimiter:
    """Test cases for RateLimiter class."""
    
    def test_rate_limiter_initialization(self):
        """Test RateLimiter initialization."""
        limiter = RateLimiter(max_requests=10, time_window=60)
        
        assert limiter.max_requests == 10
        assert limiter.time_window == 60
        assert len(limiter.requests) == 0
    
    def test_rate_limiter_acquire_first_request(self):
        """Test acquiring first request."""
        limiter = RateLimiter(max_requests=10, time_window=60)
        
        assert limiter.acquire() is True
        assert len(limiter.requests) == 1
    
    def test_rate_limiter_acquire_within_limit(self):
        """Test acquiring requests within limit."""
        limiter = RateLimiter(max_requests=10, time_window=60)
        
        for _ in range(10):
            assert limiter.acquire() is True
        
        assert len(limiter.requests) == 10
    
    def test_rate_limiter_acquire_exceeds_limit(self):
        """Test acquiring requests beyond limit."""
        limiter = RateLimiter(max_requests=5, time_window=60)
        
        # Acquire all allowed requests
        for _ in range(5):
            assert limiter.acquire() is True
        
        # Next request should be blocked
        assert limiter.acquire() is False
    
    def test_rate_limiter_wait_time(self):
        """Test wait time calculation."""
        limiter = RateLimiter(max_requests=5, time_window=60)
        
        # Acquire all allowed requests
        for _ in range(5):
            limiter.acquire()
        
        # Check wait time
        wait_time = limiter.wait_time()
        assert wait_time > 0
        assert wait_time <= 60
    
    def test_rate_limiter_old_requests_removed(self):
        """Test old requests are removed from tracking."""
        limiter = RateLimiter(max_requests=5, time_window=60)
        
        # Acquire requests
        for _ in range(5):
            limiter.acquire()
        
        # Wait for window to expire
        time.sleep(0.1)
        
        # Old request should be removed
        assert len(limiter.requests) == 0


class TestRetryWithExponentialBackoff:
    """Test cases for retry decorator."""
    
    def test_retry_success_on_first_attempt(self):
        """Test successful execution on first attempt."""
        @retry_with_exponential_backoff(max_retries=3, base_delay=0.1, max_delay=1.0)
        def always_succeed():
            return "success"
        
        result = always_succeed()
        assert result == "success"
    
    def test_retry_success_on_second_attempt(self):
        """Test successful execution on second attempt."""
        attempt_count = [0]
        
        @retry_with_exponential_backoff(max_retries=3, base_delay=0.1, max_delay=1.0)
        def fail_once():
            attempt_count[0] += 1
            if attempt_count[0] == 1:
                raise ValueError("First attempt fails")
            return "success"
        
        result = fail_once()
        assert result == "success"
        assert attempt_count[0] == 2
    
    def test_retry_all_attempts_fail(self):
        """Test all retry attempts failing."""
        @retry_with_exponential_backoff(max_retries=2, base_delay=0.1, max_delay=1.0)
        def always_fail():
            raise ValueError("Always fails")
        
        with pytest.raises(ValueError, match="Always fails"):
            always_fail()
    
    def test_retry_exponential_backoff_timing(self):
        """Test exponential backoff timing."""
        delays = []
        
        @retry_with_exponential_backoff(max_retries=3, base_delay=0.1, max_delay=1.0)
        def record_delay():
            delays.append(time.time())
            raise ValueError("Fail")
        
        with pytest.raises(ValueError):
            record_delay()
        
        # Check delays follow exponential pattern
        assert len(delays) == 4  # 3 retries + 1 initial call
        # Delays should be: 0.1, 0.2, 0.4, 0.8 (exponential with factor 2)


class TestHTTPClientPool:
    """Test cases for HTTP client connection pooling."""
    
    def test_shared_http_client_initialization(self):
        """Test shared HTTP client initialization."""
        from vulnguard.pkg.advisor.llm_client import _http_client_pool
        
        # Clear pool first
        close_http_clients()
        
        # Get client for new endpoint
        client1 = get_shared_http_client("https://api.example.com/v1/chat")
        client2 = get_shared_http_client("https://api.example.com/v1/chat")
        
        # Should return same client
        assert client1 is client2
    
    def test_shared_http_client_different_endpoints(self):
        """Test shared HTTP client for different endpoints."""
        from vulnguard.pkg.advisor.llm_client import _http_client_pool
        
        # Clear pool first
        close_http_clients()
        
        # Get clients for different endpoints
        client1 = get_shared_http_client("https://api1.example.com/v1/chat")
        client2 = get_shared_http_client("https://api2.example.com/v1/chat")
        
        # Should return different clients
        assert client1 is not client2
    
    def test_close_http_clients(self):
        """Test closing all HTTP clients."""
        from vulnguard.pkg.advisor.llm_client import _http_client_pool
        
        # Create clients
        client1 = get_shared_http_client("https://api1.example.com/v1/chat")
        client2 = get_shared_http_client("https://api2.example.com/v1/chat")
        
        # Close all clients
        close_http_clients()
        
        # Pool should be empty
        assert len(_http_client_pool) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

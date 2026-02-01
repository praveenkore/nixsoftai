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
LLM Client Module - Multi-Provider LLM Integration

Provides a unified interface for connecting to various LLM providers
including OpenAI, Anthropic, OpenRouter, Ollama, and local models.

Features:
- Retry logic with exponential backoff for network operations
- Connection pooling for efficient HTTP requests
- Rate limiting to prevent API quota exhaustion
- Comprehensive error handling and logging
"""

import json
import os
import time
import threading
from abc import ABC, abstractmethod
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple, Type
from typing import TYPE_CHECKING
from vulnguard.pkg.logging.logger import AuditLogger

import httpx

# TYPE_CHECKING constant for optional imports
if TYPE_CHECKING:
    import torch  # type: ignore[import-untyped]
    from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore[import-untyped]

# Global HTTP client pool for connection pooling
_http_client_pool: Dict[str, Any] = {}
_http_client_lock = threading.Lock()


class RateLimiter:
    """
    Rate limiter for API calls using token bucket algorithm.
    
    Prevents API quota exhaustion by limiting the rate of requests.
    """
    
    def __init__(self, max_requests: int = 60, time_window: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self.lock = threading.Lock()
    
    def acquire(self) -> bool:
        """
        Attempt to acquire a request token.
        
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self.lock:
            current_time = time.time()
            
            # Remove requests outside the time window
            self.requests = [
                req_time for req_time in self.requests
                if current_time - req_time < self.time_window
            ]
            
            # Check if we can make a request
            if len(self.requests) < self.max_requests:
                self.requests.append(current_time)
                return True
            
            return False
    
    def wait_time(self) -> float:
        """
        Calculate time to wait before next request.
        
        Returns:
            Time in seconds to wait
        """
        with self.lock:
            if not self.requests:
                return 0.0
            
            current_time = time.time()
            oldest_request = min(self.requests)
            
            # Calculate when the oldest request will be outside the window
            wait_time = (oldest_request + self.time_window) - current_time
            
            return max(0.0, wait_time)


def retry_with_exponential_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    retry_on: Optional[Tuple[Type[Exception], ...]] = None,
):
    """
    Decorator for retrying function calls with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        backoff_factor: Multiplier for delay after each retry
        retry_on: Tuple of exception types to retry on (defaults to network-related exceptions)
    """
    # Default to network-related exceptions for LLM API calls
    if retry_on is None:
        retry_on = (
            httpx.RequestError,
            httpx.TimeoutException,
            ConnectionError,
            json.JSONDecodeError,
        )
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        # Calculate delay with exponential backoff
                        delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                        
                        # Extract logger from args if available
                        logger = None
                        if args and hasattr(args[0], 'logger'):
                            logger = args[0].logger
                        
                        if logger:
                            logger.log_warning(
                                f"Request failed (attempt {attempt + 1}/{max_retries + 1}): {str(e)}. "
                                f"Retrying in {delay:.2f} seconds..."
                            )
                        
                        time.sleep(delay)
                    else:
                        # All retries exhausted
                        if logger:
                            logger.log_error(
                                "llm_client",
                                f"Request failed after {max_retries} retries: {str(e)}"
                            )
                        raise
            
            # This should never be reached, but just in case
            raise last_exception
        
        return wrapper
    return decorator


def get_shared_http_client(
    endpoint: str,
    timeout: int = 30,
    limits: Optional[Dict[str, int]] = None
) -> Any:
    """
    Get or create a shared HTTP client for connection pooling.
    
    Args:
        endpoint: API endpoint URL (used as key for client pool)
        timeout: Request timeout in seconds
        limits: Optional connection limits (max_connections, max_keepalive_connections)
        
    Returns:
        Shared httpx.Client instance
    """
    import httpx
    
    # Normalize endpoint for use as key
    endpoint_key = endpoint.rstrip('/')
    
    with _http_client_lock:
        if endpoint_key not in _http_client_pool:
            # Configure connection limits
            limits = limits or {
                'max_connections': 100,
                'max_keepalive_connections': 20
            }
            
            # Create new HTTP client with connection pooling
            _http_client_pool[endpoint_key] = httpx.Client(
                timeout=timeout,
                limits=httpx.Limits(**limits)
            )
        
        return _http_client_pool[endpoint_key]


def close_http_clients():
    """
    Close all shared HTTP clients.
    
    Should be called when shutting down the application.
    """
    with _http_client_lock:
        for client in _http_client_pool.values():
            try:
                client.close()
            except Exception:
                pass
        _http_client_pool.clear()


class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients.
    
    All LLM provider implementations must inherit from this class
    and implement the generate_response method.
    """
    
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize LLM client.
        
        Args:
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (0.0 - 1.0)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts for failed requests
            rate_limit: Optional rate limit (requests per minute)
        """
        self.logger = logger or AuditLogger()
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Initialize rate limiter if rate_limit is specified
        self.rate_limiter = RateLimiter(max_requests=rate_limit, time_window=60) if rate_limit else None
    
    def _wait_for_rate_limit(self):
        """
        Wait if rate limit would be exceeded.
        """
        if self.rate_limiter:
            wait_time = self.rate_limiter.wait_time()
            if wait_time > 0:
                self.logger.log_info(f"Rate limit reached, waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
    
    @abstractmethod
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a response from LLM.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            
        Returns:
            LLM response as string
        """
        pass
    
    @abstractmethod
    def get_model_name(self) -> str:
        """
        Get the name of the model being used.
        
        Returns:
            Model name string
        """
        pass


class OpenRouterClient(BaseLLMClient):
    """
    OpenRouter API client for accessing multiple LLM providers.
    
    OpenRouter provides unified access to multiple LLM providers including:
    - OpenAI (GPT models)
    - Anthropic (Claude models)
    - Google (Gemini models)
    - Meta (Llama models)
    - And many more
    
    Features:
    - Retry logic with exponential backoff
    - Connection pooling for efficiency
    - Rate limiting to prevent quota exhaustion
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "openai/gpt-4-turbo",
        api_endpoint: str = "https://openrouter.ai/api/v1/chat/completions",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        site_url: str = "https://openrouter.ai",
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize the OpenRouter client.
        
        Args:
            api_key: OpenRouter API key
            model: Model identifier (e.g., "openai/gpt-4-turbo", "anthropic/claude-3-opus")
            api_endpoint: API endpoint URL
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            site_url: OpenRouter site URL for headers
            max_retries: Maximum number of retry attempts
            rate_limit: Optional rate limit (requests per minute)
        """
        super().__init__(logger, max_tokens, temperature, timeout, max_retries, rate_limit)
        self.api_key = api_key
        self.model = model
        self.api_endpoint = api_endpoint
        self.site_url = site_url
        
        # Use shared HTTP client for connection pooling
        self.http_client = get_shared_http_client(api_endpoint, timeout)
    
    def _make_request(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> str:
        """
        Make HTTP request with retry logic.
        
        Args:
            headers: HTTP headers
            payload: Request payload
            
        Returns:
            Response content as string
        """
        # Wait for rate limit if needed
        self._wait_for_rate_limit()
        
        # Make request with retry logic
        @retry_with_exponential_backoff(
            max_retries=self.max_retries,
            base_delay=1.0,
            max_delay=60.0,
            backoff_factor=2.0,
            retry_on=(Exception,)
        )
        def _request():
            response = self.http_client.post(
                self.api_endpoint,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        
        return _request()
    
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a response from OpenRouter.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            
        Returns:
            LLM response as string
        """
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.site_url,
            "X-Title": "VulnGuard Security Compliance Agent"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature
        }
        
        try:
            return self._make_request(headers, payload)
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"OpenRouter API request failed: {str(e)}",
                {"model": self.model, "prompt_length": len(prompt)}
            )
            raise
    
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        return f"OpenRouter:{self.model}"


class OpenAIClient(BaseLLMClient):
    """
    OpenAI API client for GPT models.
    
    Features:
    - Retry logic with exponential backoff
    - Connection pooling for efficiency
    - Rate limiting to prevent quota exhaustion
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo-preview",
        api_endpoint: str = "https://api.openai.com/v1/chat/completions",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize the OpenAI client.
        
        Args:
            api_key: OpenAI API key
            model: Model name
            api_endpoint: API endpoint URL
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            rate_limit: Optional rate limit (requests per minute)
        """
        super().__init__(logger, max_tokens, temperature, timeout, max_retries, rate_limit)
        self.api_key = api_key
        self.model = model
        self.api_endpoint = api_endpoint
        
        # Use shared HTTP client for connection pooling
        self.http_client = get_shared_http_client(api_endpoint, timeout)
    
    def _make_request(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> str:
        """
        Make HTTP request with retry logic.
        
        Args:
            headers: HTTP headers
            payload: Request payload
            
        Returns:
            Response content as string
        """
        # Wait for rate limit if needed
        self._wait_for_rate_limit()
        
        # Make request with retry logic
        @retry_with_exponential_backoff(
            max_retries=self.max_retries,
            base_delay=1.0,
            max_delay=60.0,
            backoff_factor=2.0,
            retry_on=(Exception,)
        )
        def _request():
            response = self.http_client.post(
                self.api_endpoint,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        
        return _request()
    
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a response from OpenAI GPT.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            
        Returns:
            LLM response as string
        """
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature
        }
        
        try:
            return self._make_request(headers, payload)
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"OpenAI API request failed: {str(e)}",
                {"model": self.model, "prompt_length": len(prompt)}
            )
            raise
    
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        return f"OpenAI:{self.model}"


class AnthropicClient(BaseLLMClient):
    """
    Anthropic API client for Claude models.
    
    Features:
    - Retry logic with exponential backoff
    - Connection pooling for efficiency
    - Rate limiting to prevent quota exhaustion
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-opus-20240229",
        api_endpoint: str = "https://api.anthropic.com/v1/messages",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize the Anthropic client.
        
        Args:
            api_key: Anthropic API key
            model: Model name
            api_endpoint: API endpoint URL
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            rate_limit: Optional rate limit (requests per minute)
        """
        super().__init__(logger, max_tokens, temperature, timeout, max_retries, rate_limit)
        self.api_key = api_key
        self.model = model
        self.api_endpoint = api_endpoint
        
        # Use shared HTTP client for connection pooling
        self.http_client = get_shared_http_client(api_endpoint, timeout)
    
    def _make_request(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> str:
        """
        Make HTTP request with retry logic.
        
        Args:
            headers: HTTP headers
            payload: Request payload
            
        Returns:
            Response content as string
        """
        # Wait for rate limit if needed
        self._wait_for_rate_limit()
        
        # Make request with retry logic
        @retry_with_exponential_backoff(
            max_retries=self.max_retries,
            base_delay=1.0,
            max_delay=60.0,
            backoff_factor=2.0,
            retry_on=(Exception,)
        )
        def _request():
            response = self.http_client.post(
                self.api_endpoint,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]
        
        return _request()
    
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a response from Anthropic Claude.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            
        Returns:
            LLM response as string
        """
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            return self._make_request(headers, payload)
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"Anthropic API request failed: {str(e)}",
                {"model": self.model, "prompt_length": len(prompt)}
            )
            raise
    
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        return f"Anthropic:{self.model}"


class OllamaClient(BaseLLMClient):
    """
    Ollama API client for local LLM inference.
    
    Ollama provides a local API for running models like LLaMA, Mistral, etc.
    
    Features:
    - Retry logic with exponential backoff
    - Connection pooling for efficiency
    - Rate limiting to prevent quota exhaustion
    """
    
    def __init__(
        self,
        api_endpoint: str = "http://localhost:11434/api/generate",
        model: str = "llama2",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize the Ollama client.
        
        Args:
            api_endpoint: Ollama API endpoint URL
            model: Model name
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            rate_limit: Optional rate limit (requests per minute)
        """
        super().__init__(logger, max_tokens, temperature, timeout, max_retries, rate_limit)
        self.api_endpoint = api_endpoint
        self.model = model
        
        # Use shared HTTP client for connection pooling
        self.http_client = get_shared_http_client(api_endpoint, timeout)
    
    def _make_request(
        self,
        payload: Dict[str, Any]
    ) -> str:
        """
        Make HTTP request with retry logic.
        
        Args:
            payload: Request payload
            
        Returns:
            Response content as string
        """
        # Wait for rate limit if needed
        self._wait_for_rate_limit()
        
        # Make request with retry logic
        @retry_with_exponential_backoff(
            max_retries=self.max_retries,
            base_delay=1.0,
            max_delay=60.0,
            backoff_factor=2.0,
            retry_on=(Exception,)
        )
        def _request():
            response = self.http_client.post(
                self.api_endpoint,
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return data["response"]
        
        return _request()
    
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a response from Ollama.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            
        Returns:
            LLM response as string
        """
        # Build prompt with system prompt if provided
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        
        # Ollama API payload
        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "num_predict": 128,
                "temperature": self.temperature,
                "top_k": 40,
                "top_p": 0.9
            }
        }
        
        try:
            return self._make_request(payload)
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"Ollama API request failed: {str(e)}",
                {"model": self.model, "prompt_length": len(prompt)}
            )
            raise
    
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        return f"Ollama:{self.model}"


class LocalLLMClient(BaseLLMClient):
    """
    Local LLM client for running models on local hardware.
    
    Supports models like LLaMA, Mistral, Falcon, etc. via transformers.
    """
    
    def __init__(
        self,
        model_path: str,
        model_type: str = "llama",
        device: str = "auto",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize the local LLM client.
        
        Args:
            model_path: Path to local model file
            model_type: Type of model (llama, mistral, falcon, etc.)
            device: Device to run on (cuda, cpu, auto)
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            rate_limit: Optional rate limit (requests per minute)
        """
        super().__init__(logger, max_tokens, temperature, timeout, max_retries, rate_limit)
        self.model_path = model_path
        self.model_type = model_type
        self.device = device
        self.model = None
        self.tokenizer = None
        self._load_model()
    
    def _load_model(self):
        """
        Load the local model and tokenizer.
        
        Note: This requires transformers and torch to be installed.
        """
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore[import-untyped]
            import torch  # type: ignore[import-untyped]
            
            # Determine device
            if self.device == "auto":
                self.device = "cuda" if torch.cuda.is_available() else "cpu"
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_path,
                trust_remote_code=True
            )
            
            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
                device_map=self.device,
                trust_remote_code=True
            )
            
            self.model.eval()
            
            self.logger.log_info(
                f"Loaded local model: {self.model_path} on {self.device}"
            )
            
        except ImportError as e:
            self.logger.log_error(
                "llm_client",
                f"Failed to import transformers/torch: {str(e)}",
                {"model_path": self.model_path}
            )
            raise RuntimeError(
                "Local LLM requires transformers and torch. "
                "Install them with: pip install transformers torch"
            )
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"Failed to load local model: {str(e)}",
                {"model_path": self.model_path}
            )
            raise
    
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a response from the local LLM.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            
        Returns:
            LLM response as string
        """
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("Model not loaded")
        
        # Combine system prompt and user prompt
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        
        try:
            # Tokenize input
            inputs = self.tokenizer(
                full_prompt,
                return_tensors="pt",
                truncation=True,
                max_length=4096
            ).to(self.device)
            
            # Generate response
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=self.max_tokens,
                    temperature=self.temperature,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode response
            response = self.tokenizer.decode(
                outputs[0],
                skip_special_tokens=True
            )
            
            # Remove prompt from response
            if response.startswith(full_prompt):
                response = response[len(full_prompt):].strip()
            
            return response
            
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"Local LLM generation failed: {str(e)}",
                {"model_path": self.model_path, "prompt_length": len(prompt)}
            )
            raise
    
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        return f"Local:{self.model_type}"


class MockLLMClient(BaseLLMClient):
    """
    Mock LLM client for testing purposes.
    
    Returns deterministic responses based on the input prompt.
    """
    
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize the mock LLM client.
        
        Args:
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            rate_limit: Optional rate limit (requests per minute)
        """
        super().__init__(logger, max_tokens, temperature, timeout, max_retries, rate_limit)
    
    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Generate a mock response.
        
        Args:
            prompt: User prompt (ignored)
            system_prompt: Optional system prompt (ignored)
            
        Returns:
            Mock response as JSON string
        """
        # Return a mock JSON response
        mock_response = {
            "rule_id": "mock_rule",
            "compliance_status": "non_compliant",
            "risk_level": "medium",
            "analysis": "This is a mock AI response for testing purposes.",
            "recommended_action": "Apply the recommended remediation.",
            "commands": [],
            "rollback_commands": [],
            "requires_restart": False,
            "requires_reboot": False,
            "confidence": 0.85
        }
        
        return json.dumps(mock_response, indent=2)
    
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        return "Mock:TestClient"


def create_llm_client(
    provider: str,
    config: Dict[str, Any],
    logger: Optional[AuditLogger] = None
) -> BaseLLMClient:
    """
    Factory function to create an LLM client based on provider configuration.
    
    Args:
        provider: Provider name (openai, anthropic, openrouter, local, ollama, mock)
        config: Configuration dictionary for provider
        logger: Optional audit logger instance
        
    Returns:
        BaseLLMClient instance
        
    Raises:
        ValueError: If provider is not supported
    """
    provider_lower = provider.lower()
    
    # Common parameters for all clients
    max_retries = config.get("max_retries", 3)
    rate_limit = config.get("rate_limit")
    
    if provider_lower == "openrouter":
        api_key = config.get("api_key", "")
        if not api_key or api_key.startswith("${"):
            # Try to get from environment variable
            env_var = config.get("api_key", "").strip("${}")
            api_key = os.getenv(env_var, "")
        
        if not api_key:
            raise ValueError(
                "OpenRouter API key not found. Set OPENROUTER_API_KEY environment variable "
                "or provide api_key in config."
            )
        
        return OpenRouterClient(
            api_key=api_key,
            model=config.get("model", "openai/gpt-4-turbo"),
            api_endpoint=config.get("api_endpoint", "https://openrouter.ai/api/v1/chat/completions"),
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30),
            site_url=config.get("site_url", "https://openrouter.ai"),
            max_retries=max_retries,
            rate_limit=rate_limit
        )
    
    elif provider_lower == "openai":
        api_key = config.get("api_key", "")
        if not api_key or api_key.startswith("${"):
            # Try to get from environment variable
            env_var = config.get("api_key", "").strip("${}")
            api_key = os.getenv(env_var, "")
        
        if not api_key:
            raise ValueError(
                "OpenAI API key not found. Set OPENAI_API_KEY environment variable "
                "or provide api_key in config."
            )
        
        return OpenAIClient(
            api_key=api_key,
            model=config.get("model", "gpt-4-turbo-preview"),
            api_endpoint=config.get("api_endpoint", "https://api.openai.com/v1/chat/completions"),
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30),
            max_retries=max_retries,
            rate_limit=rate_limit
        )
    
    elif provider_lower == "anthropic":
        api_key = config.get("api_key", "")
        if not api_key or api_key.startswith("${"):
            # Try to get from environment variable
            env_var = config.get("api_key", "").strip("${}")
            api_key = os.getenv(env_var, "")
        
        if not api_key:
            raise ValueError(
                "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable "
                "or provide api_key in config."
            )
        
        return AnthropicClient(
            api_key=api_key,
            model=config.get("model", "claude-3-opus-20240229"),
            api_endpoint=config.get("api_endpoint", "https://api.anthropic.com/v1/messages"),
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30),
            max_retries=max_retries,
            rate_limit=rate_limit
        )
    
    elif provider_lower == "ollama":
        return OllamaClient(
            api_endpoint=config.get("api_endpoint", "http://localhost:11434/api/generate"),
            model=config.get("model", "llama2"),
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30),
            max_retries=max_retries,
            rate_limit=rate_limit
        )
    
    elif provider_lower == "local":
        model_path = config.get("model_path", "")
        if not model_path:
            raise ValueError("model_path is required for local LLM provider")
        
        return LocalLLMClient(
            model_path=model_path,
            model_type=config.get("model_type", "llama"),
            device=config.get("device", "auto"),
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30),
            max_retries=max_retries,
            rate_limit=rate_limit
        )
    
    elif provider_lower == "mock":
        return MockLLMClient(
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30),
            max_retries=max_retries,
            rate_limit=rate_limit
        )
    
    else:
        raise ValueError(
            f"Unsupported LLM provider: {provider}. "
            "Supported providers: openrouter, openai, anthropic, ollama, local, mock"
        )

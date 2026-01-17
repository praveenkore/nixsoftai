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
"""

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from vulnguard.pkg.logging.logger import AuditLogger


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
        timeout: int = 30
    ):
        """
        Initialize LLM client.
        
        Args:
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (0.0 - 1.0)
            timeout: Request timeout in seconds
        """
        self.logger = logger or AuditLogger()
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
    
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
        site_url: str = "https://openrouter.ai"
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
        """
        super().__init__(logger, max_tokens, temperature, timeout)
        self.api_key = api_key
        self.model = model
        self.api_endpoint = api_endpoint
        self.site_url = site_url
        
        # Import httpx for HTTP requests
        import httpx
        self.http_client = httpx.Client(timeout=timeout)
    
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
            response = self.http_client.post(
                self.api_endpoint,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            
            data = response.json()
            return data["choices"][0]["message"]["content"]
            
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
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo-preview",
        api_endpoint: str = "https://api.openai.com/v1/chat/completions",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30
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
        """
        super().__init__(logger, max_tokens, temperature, timeout)
        self.api_key = api_key
        self.model = model
        self.api_endpoint = api_endpoint
        
        # Import httpx for HTTP requests
        import httpx
        self.http_client = httpx.Client(timeout=timeout)
    
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
            response = self.http_client.post(
                self.api_endpoint,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            
            data = response.json()
            return data["choices"][0]["message"]["content"]
            
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
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-opus-20240229",
        api_endpoint: str = "https://api.anthropic.com/v1/messages",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30
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
        """
        super().__init__(logger, max_tokens, temperature, timeout)
        self.api_key = api_key
        self.model = model
        self.api_endpoint = api_endpoint
        
        # Import httpx for HTTP requests
        import httpx
        self.http_client = httpx.Client(timeout=timeout)
    
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
            response = self.http_client.post(
                self.api_endpoint,
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            
            data = response.json()
            return data["content"][0]["text"]
            
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
    """
    
    def __init__(
        self,
        api_endpoint: str = "http://localhost:11434/api/generate",
        model: str = "llama2",
        logger: Optional[AuditLogger] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: int = 30
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
        """
        super().__init__(logger, max_tokens, temperature, timeout)
        self.api_endpoint = api_endpoint
        self.model = model
        
        # Import httpx for HTTP requests
        import httpx
        self.http_client = httpx.Client(timeout=timeout)
    
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
            response = self.http_client.post(
                self.api_endpoint,
                json=payload
            )
            response.raise_for_status()
            
            data = response.json()
            return data["response"]
            
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
        timeout: int = 30
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
        """
        super().__init__(logger, max_tokens, temperature, timeout)
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
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
            
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
        timeout: int = 30
    ):
        """
        Initialize the mock LLM client.
        
        Args:
            logger: Optional audit logger instance
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
        """
        super().__init__(logger, max_tokens, temperature, timeout)
    
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
            site_url=config.get("site_url", "https://openrouter.ai")
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
            timeout=config.get("timeout", 30)
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
            timeout=config.get("timeout", 30)
        )
    
    elif provider_lower == "ollama":
        return OllamaClient(
            api_endpoint=config.get("api_endpoint", "http://localhost:11434/api/generate"),
            model=config.get("model", "llama2"),
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30)
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
            timeout=config.get("timeout", 30)
        )
    
    elif provider_lower == "mock":
        return MockLLMClient(
            logger=logger,
            max_tokens=config.get("max_tokens", 2000),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 30)
        )
    
    else:
        raise ValueError(
            f"Unsupported LLM provider: {provider}. "
            "Supported providers: openrouter, openai, anthropic, ollama, local, mock"
        )

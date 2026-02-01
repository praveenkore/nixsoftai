
"""
Plugin Interface Definition.

Defines the contract that all VulnGuard plugins must implement.
Plugins operate within a sandboxed context and must request capabilities.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol

class PluginContext(Protocol):
    """
    Protocol defining the sandboxed context provided to plugins.
    Use Protocol to avoid circular imports with the concrete implementation.
    """
    @property
    def config(self) -> Dict[str, Any]:
        """Get plugin-specific configuration."""
        ...

    def log_info(self, message: str) -> None:
        """Log info message."""
        ...

    def log_error(self, message: str) -> None:
        """Log error message."""
        ...
        
    # Proxies will be defined dynamically based on capabilities
    # fs: SecureFileSystemProxy
    # exec: SecureExecutionProxy
    # net: SecureNetworkProxy


class IPlugin(ABC):
    """
    Abstract base class for all VulnGuard plugins.
    """

    @abstractmethod
    def initialize(self, context: PluginContext) -> None:
        """
        Called when the plugin is loaded.
        
        Args:
            context: The sandboxed plugin context.
        """
        pass

    @abstractmethod
    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main execution entry point for the plugin.
        
        Args:
            payload: Input parameters for the execution.
            
        Returns:
            Dictionary containing execution results.
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """
        Called when the plugin is being unloaded or the agent is shutting down.
        Perform cleanup here.
        """
        pass

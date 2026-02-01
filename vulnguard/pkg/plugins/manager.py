
"""
Plugin Manager.

Responsible for discovering, loading, and managing the lifecycle of plugins.
Enforces security checks like signature verification and manifest validation.
"""

import importlib.util
import os
import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.plugins.interface import IPlugin, PluginContext
from vulnguard.pkg.plugins.context import PluginContext as ConcretePluginContext
from vulnguard.pkg.security.command_executor import SecureCommandExecutor

class PluginLoadError(Exception):
    """Raised when a plugin fails to load."""
    pass

class PluginManager:
    """
    Manages the lifecycle of plugins.
    """
    def __init__(
        self,
        plugin_dir: str,
        logger: Optional[AuditLogger] = None,
        command_executor: Optional[SecureCommandExecutor] = None
    ):
        self.plugin_dir = Path(plugin_dir)
        self.logger = logger or AuditLogger()
        self.command_executor = command_executor or SecureCommandExecutor(logger=self.logger)
        self.plugins: Dict[str, IPlugin] = {}
        self.configs: Dict[str, Dict[str, Any]] = {}

    def discover_and_load(self) -> None:
        """
        Discover plugins in the plugin directory and load them.
        """
        if not self.plugin_dir.exists():
            self.logger.log_info(f"Plugin directory {self.plugin_dir} does not exist. No plugins loaded.")
            return

        self.logger.log_info(f"Scanning for plugins in {self.plugin_dir}")

        for item in self.plugin_dir.iterdir():
            if item.is_dir():
                try:
                    self._load_plugin(item)
                except Exception as e:
                    self.logger.log_error(
                        "plugin_load_error",
                        f"Failed to load plugin from {item.name}: {str(e)}",
                        {"plugin_dir": str(item)}
                    )

    def _verify_signature(self, plugin_path: Path) -> bool:
        """
        Verify the digital signature of the plugin.
        TODO: Implement real ECDSA/RSA signature verification.
        For now, checks for presence of signature.sig
        """
        sig_file = plugin_path / "signature.sig"
        if not sig_file.exists():
            self.logger.log_error("plugin_security", f"Missing signature for plugin at {plugin_path}")
            return False
            
        # Real implementation would verify signature against public key
        # verify(plugin_path, sig_file, public_key)
        return True

    def _load_plugin(self, plugin_path: Path) -> None:
        """
        Load a single plugin from a directory.
        """
        manifest_path = plugin_path / "manifest.yaml"
        if not.manifest_path.exists():
            raise PluginLoadError("Missing manifest.yaml")

        # 1. Load Manifest
        with open(manifest_path, "r") as f:
            manifest = yaml.safe_load(f)

        plugin_name = manifest.get("name")
        if not plugin_name:
            raise PluginLoadError("Manifest missing 'name'")

        # 2. Verify Signature (Security Check)
        if not self._verify_signature(plugin_path):
            raise PluginLoadError(f"Signature verification failed for {plugin_name}")

        entry_point = manifest.get("entry_point") # e.g. "plugin.BackupPlugin"
        if not entry_point:
            raise PluginLoadError("Manifest missing 'entry_point'")

        # 3. Load Module
        module_name, class_name = entry_point.split(".")
        module_file = plugin_path / f"{module_name}.py"
        
        if not module_file.exists():
             raise PluginLoadError(f"Module file {module_file} not found")

        spec = importlib.util.spec_from_file_location(f"vulnguard.plugins.{plugin_name}", module_file)
        if not spec or not spec.loader:
            raise PluginLoadError(f"Failed to create module spec for {plugin_name}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[f"vulnguard.plugins.{plugin_name}"] = module
        spec.loader.exec_module(module)

        # 4. Instantiate Plugin
        plugin_class = getattr(module, class_name, None)
        if not plugin_class or not issubclass(plugin_class, IPlugin):
            raise PluginLoadError(f"Class {class_name} must implement IPlugin")

        plugin_instance = plugin_class()

        # 5. Initialize Context (The Sandbox)
        capabilities = {
            cap_name: params 
            for cap_dict in manifest.get("capabilities", []) 
            for cap_name, params in cap_dict.items()
        } if isinstance(manifest.get("capabilities"), list) else {}
        
        # If capabilities is a list of strings "CAP": ["param"], normalize it
        # Actually manifest structure in design was:
        # capabilities:
        #   - "NETWORK_OUTBOUND": ["s3.amazonaws.com"]
        
        # Parse capabilities carefully
        parsed_caps = {}
        raw_caps = manifest.get("capabilities", [])
        for item in raw_caps:
            if isinstance(item, dict):
                parsed_caps.update(item)
            elif isinstance(item, str):
                parsed_caps[item] = [] # Cap with no params

        context = ConcretePluginContext(
            config=manifest.get("config", {}),
            capabilities=parsed_caps,
            logger=self.logger,
            command_executor=self.command_executor
        )

        try:
            plugin_instance.initialize(context)
            self.plugins[plugin_name] = plugin_instance
            self.logger.log_info(f"Loaded plugin: {plugin_name} v{manifest.get('version')}")
        except Exception as e:
            raise PluginLoadError(f"Plugin initialization failed: {str(e)}")

    def get_plugin(self, name: str) -> Optional[IPlugin]:
        return self.plugins.get(name)

    def shutdown_all(self) -> None:
        """Shutdown all plugins."""
        for name, plugin in self.plugins.items():
            try:
                plugin.shutdown()
            except Exception as e:
                self.logger.log_error("plugin_shutdown", f"Error shutting down {name}: {str(e)}")

"""
Plugin registry for discovering and managing OSINT tool plugins.
"""

import importlib
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

from .base import OSINTPlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Registry for managing OSINT tool plugins.
    
    Handles plugin discovery, registration, and retrieval.
    """
    
    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: Dict[str, Type[OSINTPlugin]] = {}
        self._instances: Dict[str, OSINTPlugin] = {}
    
    def register(self, plugin_class: Type[OSINTPlugin]) -> None:
        """
        Register a plugin class.
        
        Args:
            plugin_class: The plugin class to register
        """
        plugin_name = plugin_class.__name__
        self._plugins[plugin_name] = plugin_class
        logger.info(f"Registered plugin: {plugin_name}")
    
    def unregister(self, plugin_name: str) -> None:
        """
        Unregister a plugin.
        
        Args:
            plugin_name: Name of the plugin to unregister
        """
        if plugin_name in self._plugins:
            del self._plugins[plugin_name]
            if plugin_name in self._instances:
                del self._instances[plugin_name]
            logger.info(f"Unregistered plugin: {plugin_name}")
    
    def get_plugin_class(self, plugin_name: str) -> Optional[Type[OSINTPlugin]]:
        """
        Get a registered plugin class.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin class or None if not found
        """
        return self._plugins.get(plugin_name)
    
    def get_plugin_instance(self, plugin_name: str) -> Optional[OSINTPlugin]:
        """
        Get or create a plugin instance.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin instance or None if not found
        """
        if plugin_name not in self._instances:
            plugin_class = self.get_plugin_class(plugin_name)
            if plugin_class:
                self._instances[plugin_name] = plugin_class()
        return self._instances.get(plugin_name)
    
    def list_plugins(self) -> List[str]:
        """
        List all registered plugin names.
        
        Returns:
            List of plugin names
        """
        return list(self._plugins.keys())
    
    def discover_plugins(self, plugin_dir: Optional[Path] = None) -> None:
        """
        Discover and register plugins from a directory.
        
        Args:
            plugin_dir: Directory to search for plugins (default: src/plugins/builtins)
        """
        if plugin_dir is None:
            plugin_dir = Path(__file__).parent / "builtins"
        
        if not plugin_dir.exists():
            logger.warning(f"Plugin directory not found: {plugin_dir}")
            return
        
        # Add plugin directory to Python path
        import sys
        if str(plugin_dir.parent) not in sys.path:
            sys.path.insert(0, str(plugin_dir.parent))
        
        # Import all Python files in the plugin directory
        for module_file in plugin_dir.glob("*.py"):
            if module_file.name.startswith("_"):
                continue
            
            module_name = f"src.plugins.builtins.{module_file.stem}"
            
            try:
                module = importlib.import_module(module_name)
                
                # Find all classes that inherit from OSINTPlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, OSINTPlugin) and 
                        obj is not OSINTPlugin and
                        obj.__module__ == module.__name__):
                        self.register(obj)
                        
            except Exception as e:
                logger.error(f"Failed to load plugin from {module_file}: {e}")
    
    def get_available_plugins(self) -> List[str]:
        """
        Get list of available plugins (those that are available for execution).
        
        Returns:
            List of available plugin names
        """
        available = []
        for plugin_name in self.list_plugins():
            instance = self.get_plugin_instance(plugin_name)
            if instance and instance.is_available():
                available.append(plugin_name)
        return available
    
    def get_plugins_by_artifact_type(self, artifact_type: str) -> List[str]:
        """
        Get plugins that support a specific artifact type.
        
        Args:
            artifact_type: The artifact type (username, email, phone, etc.)
            
        Returns:
            List of plugin names that support this artifact type
        """
        compatible = []
        for plugin_name in self.list_plugins():
            instance = self.get_plugin_instance(plugin_name)
            if instance and instance.is_available():
                if artifact_type in instance.get_supported_artifact_types():
                    compatible.append(plugin_name)
        return compatible


# Global plugin registry instance
_global_registry = PluginRegistry()


def get_global_registry() -> PluginRegistry:
    """
    Get the global plugin registry instance.
    
    Returns:
        Global PluginRegistry instance
    """
    return _global_registry

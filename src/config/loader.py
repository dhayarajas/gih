"""
Configuration loader for Ghost Identity Hunter.

This module handles loading configuration from YAML files and providing
access to plugin and tool settings.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Load and manage configuration from YAML files."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.
        
        Args:
            config_path: Path to configuration file (default: ./config.yaml)
        """
        if config_path is None:
            # Try default locations
            default_paths = [
                "./config/config.yaml",
                "./config/config.yml",
                "./config.yaml",
                "./config.yml",
                str(Path(__file__).parent.parent / "config" / "config.yaml"),
                str(Path(__file__).parent.parent / "config.yaml"),
                os.path.expanduser("~/.ghosthunter/config.yaml"),
            ]
            
            config_path = None
            for path in default_paths:
                if Path(path).exists():
                    config_path = path
                    break
            
            if config_path is None:
                logger.warning("No configuration file found, using defaults")
                config_path = "./config.yaml"
        
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            logger.warning(f"Configuration file not found: {self.config_path}")
            self.config = self._get_default_config()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
            logger.info(f"Configuration loaded from: {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.config = self._get_default_config()
    
    def save_config(self) -> None:
        """Save current configuration to YAML file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            logger.info(f"Configuration saved to: {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation, e.g., "plugins.sherlock.enabled")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin configuration dictionary
        """
        plugin_config = self.get(f"plugins.{plugin_name}", {})
        
        global_settings = self.get("plugin_settings", {})
        
        # The defaults are deliberately not read from plugin_settings: its
        # `parallel_execution` and `rate_limit_seconds` describe how plugins are
        # scheduled, not whether one is enabled or how long it may run, and
        # borrowing them gave an unlisted plugin a 100ms timeout.
        merged_config = {
            "enabled": True,
            "timeout": global_settings.get("default_timeout_seconds", 30),
            "max_retries": global_settings.get("max_retries", 3),
            **plugin_config
        }
        
        return merged_config
    
    def set_plugin_enabled(self, plugin_name: str, enabled: bool) -> None:
        """
        Enable or disable a plugin.
        
        Args:
            plugin_name: Name of the plugin
            enabled: Whether to enable the plugin
        """
        self.set(f"plugins.{plugin_name}.enabled", enabled)
        logger.info(f"Plugin '{plugin_name}' {'enabled' if enabled else 'disabled'}")
    
    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """
        List all plugins and their configuration.
        
        Returns:
            Dictionary of plugin names to their configurations
        """
        plugins = self.get("plugins", {})
        return plugins or {}
    
    def get_enabled_plugins(self) -> list[str]:
        """
        Get list of enabled plugins.
        
        Returns:
            List of enabled plugin names
        """
        plugins = self.list_plugins()
        enabled = []
        
        for plugin_name, config in plugins.items():
            if (config or {}).get("enabled", False):
                enabled.append(plugin_name)
        
        return enabled
    
    def get_disabled_plugins(self) -> list[str]:
        """
        Get list of disabled plugins.
        
        Returns:
            List of disabled plugin names
        """
        plugins = self.list_plugins()
        disabled = []
        
        for plugin_name, config in plugins.items():
            if not (config or {}).get("enabled", False):
                disabled.append(plugin_name)
        
        return disabled
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "plugins": {
                "username_search": {
                    "enabled": True,
                    "priority": 1,
                    "timeout": 30,
                    "max_retries": 3
                },
                "email_breach": {
                    "enabled": True,
                    "priority": 1,
                    "timeout": 30,
                    "max_retries": 3
                },
                "phone_validation": {
                    "enabled": True,
                    "priority": 1,
                    "timeout": 30,
                    "max_retries": 3
                },
                "sherlock": {
                    "enabled": False,
                    "priority": 2,
                    "timeout": 60,
                    "max_retries": 2
                },
                "theharvester": {
                    "enabled": False,
                    "priority": 2,
                    "timeout": 60,
                    "max_retries": 2
                },
                "shodan": {
                    "enabled": False,
                    "priority": 3,
                    "timeout": 30,
                    "max_retries": 2
                },
                "whois": {
                    "enabled": False,
                    "priority": 2,
                    "timeout": 30,
                    "max_retries": 2
                },
                "google_dorks": {
                    "enabled": True,
                    "priority": 2,
                    "timeout": 30,
                    "max_retries": 3
                }
            },
            "plugin_settings": {
                "parallel_execution": True,
                "max_parallel_workers": 5,
                "enable_caching": True,
                "cache_duration_hours": 24,
                "rate_limit_seconds": 1.0,
                "log_plugin_output": False
            },
            "investigation": {
                "max_depth": 2,
                "max_runtime_minutes": 18,
                "max_total_artifacts": 500,
                "max_concurrent_io": 32,
                "check_breaches": True,
                "search_usernames": True,
                "check_images": True,
                "check_external_tools": True,
                "skip_missing_tools": True
            }
        }


# Global configuration instance
_global_config: Optional[ConfigLoader] = None


def get_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Get the global configuration instance.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        ConfigLoader instance
    """
    global _global_config
    
    if _global_config is None:
        _global_config = ConfigLoader(config_path)
    
    return _global_config


def reload_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Reload configuration from file.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        ConfigLoader instance
    """
    global _global_config
    _global_config = ConfigLoader(config_path)
    return _global_config

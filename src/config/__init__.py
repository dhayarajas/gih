"""
Configuration management for Ghost Identity Hunter.

This module handles loading and managing configuration from YAML files.
"""

from .loader import ConfigLoader, get_config

__all__ = [
    'ConfigLoader',
    'get_config',
]

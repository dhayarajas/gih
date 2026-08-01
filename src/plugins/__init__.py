"""
Plugin system for Ghost Identity Hunter OSINT tools.

This module provides a pluggable architecture for integrating OSINT tools
as independent components that can be discovered, loaded, and executed.
"""

from .base import OSINTPlugin, PluginResult, PluginConfig, Artifact
from .manager import PluginManager
from .registry import PluginRegistry

__all__ = [
    'OSINTPlugin',
    'PluginResult', 
    'PluginConfig',
    'Artifact',
    'PluginManager',
    'PluginRegistry',
]

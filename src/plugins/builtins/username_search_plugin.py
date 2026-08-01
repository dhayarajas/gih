"""
Username search plugin for platform presence detection.
"""

import logging
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.modules.username_search import search_username

logger = logging.getLogger(__name__)


class UsernameSearchPlugin(OSINTPlugin):
    """Plugin for searching username presence across social platforms."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the username search plugin."""
        super().__init__(config)
        self.name = "UsernameSearchPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Username Search"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Searches for username presence across multiple social platforms"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["username"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return True  # Built-in, always available
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute username search.
        
        Args:
            artifact: Username artifact to search
            
        Returns:
            PluginResult with discovered platform presences
        """
        try:
            # Use existing username search module
            username_result = search_username(artifact.value)
            
            # Convert platform presences to artifacts
            discovered_artifacts = []
            
            # Handle the UsernameSearchResult object
            if hasattr(username_result, 'platforms'):
                platforms = username_result.platforms
            elif isinstance(username_result, dict):
                platforms = username_result
            else:
                # Fallback to empty dict
                platforms = {}
            
            for platform, url in platforms.items():
                discovered_artifacts.append(Artifact(
                    type="platform_presence",
                    value=url,
                    source=self.name,
                    confidence=0.9,
                    metadata={
                        "platform": platform,
                        "username": artifact.value
                    }
                ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data={"platforms": platforms},
                metadata={
                    "platforms_found": len(platforms),
                    "username": artifact.value
                }
            )
            
        except Exception as e:
            logger.error(f"Username search failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

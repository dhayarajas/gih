"""
Google Dorks plugin for advanced username discovery.
"""

import logging
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.modules.google_dorks import run_google_dorks_search

logger = logging.getLogger(__name__)


class GoogleDorksPlugin(OSINTPlugin):
    """Plugin for Google Dorks advanced username discovery."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the Google Dorks plugin."""
        super().__init__(config)
        self.name = "GoogleDorksPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Google Dorks"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Uses Google Dorks for advanced username discovery across platforms"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["username"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return True  # Uses web scraping/API, always available
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute Google Dorks search.
        
        Args:
            artifact: Username artifact to search
            
        Returns:
            PluginResult with discovered artifacts
        """
        try:
            # Use existing Google Dorks module
            artifacts = run_google_dorks_search(
                username=artifact.value,
                api_key=self.config.api_key,
                cx=self.config.custom_params.get("google_cx"),
                use_api=self.config.custom_params.get("use_google_api", False),
                search_engine=self.config.custom_params.get("search_engine", "auto"),
                max_patterns=self.config.custom_params.get("max_patterns", 3)
            )
            
            # Convert to plugin artifacts
            discovered_artifacts = []
            for artifact_data in artifacts:
                discovered_artifacts.append(Artifact(
                    type=artifact_data.get("type", "unknown"),
                    value=artifact_data.get("value", ""),
                    source=self.name,
                    confidence=artifact_data.get("confidence", 0.7),
                    metadata=artifact_data
                ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data={"artifacts": artifacts},
                metadata={
                    "username": artifact.value,
                    "artifacts_found": len(discovered_artifacts)
                }
            )
            
        except Exception as e:
            logger.error(f"Google Dorks execution failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

"""
Shodan plugin for internet-connected device search.
"""

import logging
import os
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.modules.external_tools import ShodanIntegration

logger = logging.getLogger(__name__)


class ShodanPlugin(OSINTPlugin):
    """Plugin for Shodan internet device search."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the Shodan plugin."""
        super().__init__(config)
        self.name = "ShodanPlugin"
        # Use API key from config or environment
        self.api_key = config.api_key if config and config.api_key else os.environ.get("SHODAN_API_KEY")
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Shodan"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Searches for internet-connected devices and services using Shodan"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["ip", "domain"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return self.api_key is not None
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["shodan"]
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute Shodan search.
        
        Args:
            artifact: IP or domain artifact to search
            
        Returns:
            PluginResult with device information
        """
        try:
            if not self.api_key:
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SKIPPED,
                    error="Shodan API key not configured"
                )
            
            # Use existing Shodan integration
            shodan = ShodanIntegration(api_key=self.api_key)
            
            if artifact.type == "ip":
                result = shodan.search_ip(artifact.value)
            elif artifact.type == "domain":
                result = shodan.search_domain(artifact.value)
            else:
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SKIPPED,
                    error=f"Unsupported artifact type: {artifact.type}"
                )
            
            if not result.success:
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.FAILURE,
                    error=result.error
                )
            
            # Convert to artifacts
            discovered_artifacts = []
            
            if result.artifacts_discovered:
                for artifact_data in result.artifacts_discovered:
                    discovered_artifacts.append(Artifact(
                        type=artifact_data.get("type", "service"),
                        value=artifact_data.get("value", ""),
                        source=self.name,
                        confidence=0.9,
                        metadata=artifact_data
                    ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data=result.raw_data if hasattr(result, 'raw_data') else {},
                metadata={
                    "target": artifact.value,
                    "services_found": len(discovered_artifacts)
                }
            )
            
        except Exception as e:
            logger.error(f"Shodan execution failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

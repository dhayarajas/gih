"""
Sherlock plugin for username search across social platforms.
"""

import logging
import subprocess
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.utils.tool_checker import check_tool_availability

logger = logging.getLogger(__name__)


class SherlockPlugin(OSINTPlugin):
    """Plugin for Sherlock username search tool."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the Sherlock plugin."""
        super().__init__(config)
        self.name = "SherlockPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Sherlock"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Searches for usernames across hundreds of social platforms using Sherlock"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["username"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return check_tool_availability("sherlock")
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["sherlock"]
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute Sherlock username search.
        
        Args:
            artifact: Username artifact to search
            
        Returns:
            PluginResult with discovered platform presences
        """
        try:
            # Run Sherlock command
            cmd = ["sherlock", artifact.value, "--output", "/dev/stdout", "--format", "json"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout
            )
            
            if result.returncode != 0:
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.FAILURE,
                    error=f"Sherlock execution failed: {result.stderr}"
                )
            
            # Parse JSON output
            import json
            sherlock_data = json.loads(result.stdout)
            
            # Convert to artifacts
            discovered_artifacts = []
            for site, data in sherlock_data.items():
                if data.get("status", "unknown") == "found":
                    discovered_artifacts.append(Artifact(
                        type="platform_presence",
                        value=data.get("url", ""),
                        source=self.name,
                        confidence=0.95,
                        metadata={
                            "platform": site,
                            "username": artifact.value,
                            "status": data.get("status")
                        }
                    ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data=sherlock_data,
                metadata={
                    "username": artifact.value,
                    "platforms_found": len(discovered_artifacts)
                }
            )
            
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error="Sherlock execution timed out"
            )
        except Exception as e:
            logger.error(f"Sherlock execution failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

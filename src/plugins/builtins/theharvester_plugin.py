"""
TheHarvester plugin for email and subdomain discovery.
"""

import logging
import subprocess
import json
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.utils.tool_checker import check_tool_availability

logger = logging.getLogger(__name__)


class TheHarvesterPlugin(OSINTPlugin):
    """Plugin for TheHarvester email and subdomain harvesting tool."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the TheHarvester plugin."""
        super().__init__(config)
        self.name = "TheHarvesterPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "TheHarvester"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Harvests emails and subdomains from domains using TheHarvester"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["domain"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return check_tool_availability("theharvester")
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["theharvester"]
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute TheHarvester on a domain.
        
        Args:
            artifact: Domain artifact to harvest
            
        Returns:
            PluginResult with discovered emails and subdomains
        """
        try:
            # Run TheHarvester command
            cmd = [
                "theHarvester",
                "-d", artifact.value,
                "-b", "google",
                "-f", "/dev/stdout",
                "--json"
            ]
            
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
                    error=f"TheHarvester execution failed: {result.stderr}"
                )
            
            # Parse JSON output
            try:
                harvester_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Fallback to text parsing if JSON not available
                harvester_data = {"emails": [], "hosts": []}
                for line in result.stdout.split('\n'):
                    if '@' in line:
                        harvester_data["emails"].append(line.strip())
                    if artifact.value in line:
                        harvester_data["hosts"].append(line.strip())
            
            # Convert to artifacts
            discovered_artifacts = []
            
            # Email artifacts
            for email in harvester_data.get("emails", []):
                discovered_artifacts.append(Artifact(
                    type="email",
                    value=email,
                    source=self.name,
                    confidence=0.8,
                    metadata={
                        "domain": artifact.value
                    }
                ))
            
            # Subdomain artifacts
            for host in harvester_data.get("hosts", []):
                discovered_artifacts.append(Artifact(
                    type="domain",
                    value=host,
                    source=self.name,
                    confidence=0.85,
                    metadata={
                        "parent_domain": artifact.value
                    }
                ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data=harvester_data,
                metadata={
                    "domain": artifact.value,
                    "emails_found": len(harvester_data.get("emails", [])),
                    "hosts_found": len(harvester_data.get("hosts", []))
                }
            )
            
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error="TheHarvester execution timed out"
            )
        except Exception as e:
            logger.error(f"TheHarvester execution failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

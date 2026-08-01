"""
Whois plugin for domain and IP ownership information.
"""

import logging
import subprocess
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.utils.tool_checker import check_tool_availability

logger = logging.getLogger(__name__)


class WhoisPlugin(OSINTPlugin):
    """Plugin for Whois domain/IP ownership information."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the Whois plugin."""
        super().__init__(config)
        self.name = "WhoisPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Whois"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Retrieves domain and IP ownership information using Whois"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["domain", "ip"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return check_tool_availability("whois")
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["whois"]
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute Whois lookup.
        
        Args:
            artifact: Domain or IP artifact to lookup
            
        Returns:
            PluginResult with ownership information
        """
        try:
            # Run whois command
            cmd = ["whois", artifact.value]
            
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
                    error=f"Whois execution failed: {result.stderr}"
                )
            
            # Parse whois output for key information
            whois_output = result.stdout
            discovered_artifacts = []
            
            # Extract registrant name
            if "Registrant Name:" in whois_output:
                for line in whois_output.split('\n'):
                    if "Registrant Name:" in line:
                        name = line.split(":", 1)[1].strip()
                        if name:
                            discovered_artifacts.append(Artifact(
                                type="organization",
                                value=name,
                                source=self.name,
                                confidence=0.8,
                                metadata={"field": "registrant_name"}
                            ))
                        break
            
            # Extract registrant email
            if "Registrant Email:" in whois_output or "Admin Email:" in whois_output:
                for line in whois_output.split('\n'):
                    if "Email:" in line:
                        email = line.split(":", 1)[1].strip()
                        if email and "@" in email:
                            discovered_artifacts.append(Artifact(
                                type="email",
                                value=email,
                                source=self.name,
                                confidence=0.85,
                                metadata={"field": "registrant_email"}
                            ))
                            break
            
            # Extract organization
            if "Organization:" in whois_output:
                for line in whois_output.split('\n'):
                    if "Organization:" in line:
                        org = line.split(":", 1)[1].strip()
                        if org:
                            discovered_artifacts.append(Artifact(
                                type="organization",
                                value=org,
                                source=self.name,
                                confidence=0.8,
                                metadata={"field": "organization"}
                            ))
                        break
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data={"whois_output": whois_output},
                metadata={
                    "target": artifact.value,
                    "fields_found": len(discovered_artifacts)
                }
            )
            
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error="Whois execution timed out"
            )
        except Exception as e:
            logger.error(f"Whois execution failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

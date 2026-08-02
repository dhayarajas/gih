"""
Dig plugin for DNS lookup and information gathering.
"""

import logging
import subprocess
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.utils.tool_checker import check_tool_availability

logger = logging.getLogger(__name__)


class DigPlugin(OSINTPlugin):
    """Plugin for DNS lookup using dig command."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the Dig plugin."""
        super().__init__(config)
        self.name = "DigPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Dig"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Performs DNS lookups and retrieves DNS information using dig"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["domain"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return check_tool_availability("dig")
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["dig"]
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute DNS lookup using dig.
        
        Args:
            artifact: Domain artifact to lookup
            
        Returns:
            PluginResult with DNS information
        """
        try:
            discovered_artifacts = []
            dns_records = {}
            
            # Perform various DNS record lookups
            record_types = ["A", "MX", "NS", "TXT", "CNAME"]
            
            for record_type in record_types:
                cmd = ["dig", artifact.value, record_type, "+short"]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
                    dns_records[record_type] = records
                    
                    # Create artifacts from DNS records
                    for record in records:
                        if record_type == "A":
                            discovered_artifacts.append(Artifact(
                                type="ip_address",
                                value=record,
                                source=self.name,
                                confidence=0.9,
                                metadata={
                                    "record_type": record_type,
                                    "domain": artifact.value
                                }
                            ))
                        elif record_type == "MX":
                            discovered_artifacts.append(Artifact(
                                type="mail_server",
                                value=record,
                                source=self.name,
                                confidence=0.85,
                                metadata={
                                    "record_type": record_type,
                                    "domain": artifact.value
                                }
                            ))
                        elif record_type == "NS":
                            discovered_artifacts.append(Artifact(
                                type="nameserver",
                                value=record,
                                source=self.name,
                                confidence=0.85,
                                metadata={
                                    "record_type": record_type,
                                    "domain": artifact.value
                                }
                            ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data=dns_records,
                metadata={
                    "domain": artifact.value,
                    "record_types_found": len(dns_records),
                    "total_records": len(discovered_artifacts)
                }
            )
            
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error="Dig execution timed out"
            )
        except Exception as e:
            logger.error(f"Dig execution failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

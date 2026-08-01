"""
Email breach checking plugin using HaveIBeenPwned.
"""

import logging
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.modules.email_osint import analyze_email

logger = logging.getLogger(__name__)


class EmailBreachPlugin(OSINTPlugin):
    """Plugin for checking email breaches using HaveIBeenPwned."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the email breach plugin."""
        super().__init__(config)
        self.name = "EmailBreachPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Email Breach Check"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Checks email addresses against HaveIBeenPwned breach database"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["email"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return True  # Uses API, always available
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute email breach check.
        
        Args:
            artifact: Email artifact to check
            
        Returns:
            PluginResult with breach information
        """
        try:
            # Use existing email analysis module
            email_analysis = analyze_email(artifact.value)
            
            # Create artifacts from breach data
            discovered_artifacts = []
            
            # Check if breach data exists in analysis
            if hasattr(email_analysis, 'breaches') and email_analysis.breaches:
                for breach in email_analysis.breaches:
                    discovered_artifacts.append(Artifact(
                        type="breach",
                        value=breach.get("Name", "Unknown"),
                        source=self.name,
                        confidence=1.0,
                        metadata={
                            "breach_date": breach.get("BreachDate"),
                            "data_classes": breach.get("DataClasses", []),
                            "description": breach.get("Description", ""),
                            "email": artifact.value
                        }
                    ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data={"breaches": email_analysis.breaches if hasattr(email_analysis, 'breaches') else []},
                metadata={
                    "email": artifact.value,
                    "breached": len(discovered_artifacts) > 0,
                    "breach_count": len(discovered_artifacts)
                }
            )
            
        except Exception as e:
            logger.error(f"Email breach check failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

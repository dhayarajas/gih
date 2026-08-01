"""
Phone validation plugin for phone number analysis.
"""

import logging
from typing import List

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from src.modules.phone_osint import analyze_phone

logger = logging.getLogger(__name__)


class PhoneValidationPlugin(OSINTPlugin):
    """Plugin for validating and analyzing phone numbers."""
    
    def __init__(self, config: PluginConfig = None):
        """Initialize the phone validation plugin."""
        super().__init__(config)
        self.name = "PhoneValidationPlugin"
    
    def get_name(self) -> str:
        """Get plugin name."""
        return "Phone Validation"
    
    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Get plugin description."""
        return "Validates phone numbers and extracts carrier/location information"
    
    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["phone"]
    
    def is_available(self) -> bool:
        """Check if plugin is available."""
        return True  # Built-in, always available
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute phone validation.
        
        Args:
            artifact: Phone artifact to validate
            
        Returns:
            PluginResult with phone validation data
        """
        try:
            # Use existing phone validation module
            phone_analysis = analyze_phone(artifact.value)
            
            # Create artifacts from phone data
            discovered_artifacts = []
            
            if phone_analysis.valid:
                # Add location artifact
                if phone_analysis.country:
                    discovered_artifacts.append(Artifact(
                        type="location",
                        value=phone_analysis.country,
                        source=self.name,
                        confidence=0.8,
                        metadata={
                            "country_code": phone_analysis.country_code,
                            "phone": artifact.value
                        }
                    ))
                
                # Add carrier artifact
                if phone_analysis.carrier_name:
                    discovered_artifacts.append(Artifact(
                        type="carrier",
                        value=phone_analysis.carrier_name,
                        source=self.name,
                        confidence=0.7,
                        metadata={
                            "phone": artifact.value
                        }
                    ))
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered_artifacts,
                raw_data=phone_analysis.to_json() if hasattr(phone_analysis, 'to_json') else {},
                metadata={
                    "phone": artifact.value,
                    "valid": phone_analysis.valid,
                    "type": phone_analysis.line_type if hasattr(phone_analysis, 'line_type') else "unknown"
                }
            )
            
        except Exception as e:
            logger.error(f"Phone validation failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

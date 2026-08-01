"""
Ghost Identity Hunter - Image Match Plugin

PURPOSE:
--------
Plugin for image search and face matching based on full name.
Integrates with the image_match module to provide identity verification
through image analysis.

FUNCTIONALITY:
--------------
- Searches for images by full name across multiple platforms
- Extracts face encodings from images
- Matches faces with probability scoring
- Returns high-confidence matches as artifacts

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project
"""

import logging
from typing import Optional

from src.modules.image_match import search_and_match_identity, get_discovered_artifacts
from src.plugins.base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus

logger = logging.getLogger(__name__)


class ImageMatchPlugin(OSINTPlugin):
    """Plugin for image search and face matching."""
    
    name = "image_match"
    version = "1.0.0"
    description = "Search for images and match faces by full name"
    
    def __init__(self, config: Optional[PluginConfig] = None):
        super().__init__(config)
        self.supported_artifact_types = ["fullname"]
    
    def get_name(self) -> str:
        """Get the plugin name."""
        return self.name
    
    def get_version(self) -> str:
        """Get the plugin version."""
        return self.version
    
    def get_description(self) -> str:
        """Get the plugin description."""
        return self.description
    
    def get_supported_artifact_types(self) -> list[str]:
        """Get the artifact types this plugin can process."""
        return self.supported_artifact_types
    
    def is_available(self) -> bool:
        """Check if the plugin is available for execution."""
        try:
            import face_recognition
            return True
        except ImportError:
            logger.warning("face_recognition module not available, image match plugin disabled")
            return False
    
    def validate_artifact(self, artifact: Artifact) -> bool:
        """Check if artifact type is supported."""
        return artifact.type in self.supported_artifact_types
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """Execute image search and face matching."""
        try:
            logger.info("Starting image match for: %s", artifact.value)
            
            # Search and match identity
            match_result = search_and_match_identity(
                full_name=artifact.value,
                max_results=self.config.custom_params.get("max_results", 20)
            )
            
            # Extract artifacts from results
            discovered = []
            for art in get_discovered_artifacts(match_result):
                discovered.append(Artifact(
                    type=art["type"],
                    value=art["value"],
                    source=art["source"],
                    confidence=art["confidence"],
                    metadata=art.get("metadata")
                ))
            
            # Add overall probability as metadata
            result_metadata = {
                "overall_probability": match_result.overall_probability,
                "image_count": len(match_result.images),
                "face_match_count": len(match_result.face_matches),
                "confidence_sources": match_result.confidence_sources
            }
            
            logger.info(
                "Image match complete: %d images, %d face matches, probability=%.2f",
                len(match_result.images),
                len(match_result.face_matches),
                match_result.overall_probability
            )
            
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                artifacts=discovered,
                metadata=result_metadata
            )
        
        except Exception as e:
            logger.error("Image match failed: %s", e)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=str(e)
            )

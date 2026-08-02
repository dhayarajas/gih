"""
ExifTool plugin for image metadata extraction.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class ExifToolPlugin(IntegrationPlugin):
    """Plugin wrapping the exiftool integration."""

    tool_name = "exiftool"
    analysis_type = "metadata_extract"
    artifact_types: ClassVar[list[str]] = ['image']
    description = "Extracts GPS, camera and timestamp metadata from local images using ExifTool"

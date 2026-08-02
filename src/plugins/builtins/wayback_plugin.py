"""
Wayback Machine plugin for historical URL discovery.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class WaybackMachinePlugin(IntegrationPlugin):
    """Plugin wrapping the wayback_machine integration."""

    tool_name = "wayback_machine"
    analysis_type = "historical_urls"
    artifact_types: ClassVar[list[str]] = ['domain']
    description = "Retrieves historical URLs for a domain from the Wayback Machine CDX API"
    # Reached over HTTP; there is no local executable to detect.
    requires_executable = False

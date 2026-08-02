"""
Nmap plugin for host port and service scanning.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class NmapPlugin(IntegrationPlugin):
    """Plugin wrapping the nmap integration."""

    tool_name = "nmap"
    analysis_type = "host_scan"
    artifact_types: ClassVar[list[str]] = ['ip_address']
    description = "Scans a host for open ports and service versions using Nmap"

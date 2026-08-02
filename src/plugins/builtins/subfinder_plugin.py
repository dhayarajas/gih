"""
Subfinder plugin for passive subdomain enumeration.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class SubfinderPlugin(IntegrationPlugin):
    """Plugin wrapping the subfinder integration."""

    tool_name = "subfinder"
    analysis_type = "subdomain_enum"
    artifact_types: ClassVar[list[str]] = ['domain']
    description = "Enumerates subdomains passively using Subfinder"

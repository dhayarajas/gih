"""
Sublist3r plugin for search-engine subdomain enumeration.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class Sublist3rPlugin(IntegrationPlugin):
    """Plugin wrapping the sublist3r integration."""

    tool_name = "sublist3r"
    analysis_type = "subdomain_enum"
    artifact_types: ClassVar[list[str]] = ['domain']
    description = "Enumerates subdomains from search engines using Sublist3r"

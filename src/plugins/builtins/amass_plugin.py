"""
Amass plugin for passive subdomain enumeration.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class AmassPlugin(IntegrationPlugin):
    """Plugin wrapping the amass integration."""

    tool_name = "amass"
    analysis_type = "subdomain_enum"
    artifact_types: ClassVar[list[str]] = ['domain']
    description = "Enumerates subdomains passively using OWASP Amass"

"""
Whois plugin for domain and IP ownership information.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class WhoisPlugin(IntegrationPlugin):
    """Plugin wrapping the whois integration."""

    tool_name = "whois"
    analysis_type = "domain_lookup"
    artifact_types: ClassVar[list[str]] = ["domain"]
    description = "Retrieves domain registration and ownership detail using Whois"

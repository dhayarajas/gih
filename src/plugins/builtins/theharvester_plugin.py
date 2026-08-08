"""
theHarvester plugin for email and subdomain harvesting.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class TheHarvesterPlugin(IntegrationPlugin):
    """Plugin wrapping the theHarvester integration."""

    tool_name = "theharvester"
    analysis_type = "email_harvest"
    additional_analysis_types: ClassVar[list[str]] = ["subdomain_harvest"]
    artifact_types: ClassVar[list[str]] = ["domain"]
    description = "Harvests emails, subdomains and hosts for a domain using theHarvester"

"""
Holehe plugin for email account discovery.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class HolehePlugin(IntegrationPlugin):
    """Plugin wrapping the holehe integration."""

    tool_name = "holehe"
    analysis_type = "email_check"
    artifact_types: ClassVar[list[str]] = ['email']
    description = "Checks which sites an email address is registered on using Holehe"

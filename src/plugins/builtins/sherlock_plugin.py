"""
Sherlock plugin for username enumeration across social networks.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class SherlockPlugin(IntegrationPlugin):
    """Plugin wrapping the sherlock integration."""

    tool_name = "sherlock"
    analysis_type = "username_search"
    artifact_types: ClassVar[list[str]] = ["username"]
    description = "Searches a username across social networks with Sherlock"

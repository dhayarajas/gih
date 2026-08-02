"""
Maigret plugin for wide username enumeration.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class MaigretPlugin(IntegrationPlugin):
    """Plugin wrapping the maigret integration."""

    tool_name = "maigret"
    analysis_type = "username_search"
    artifact_types: ClassVar[list[str]] = ['username']
    description = "Searches usernames across 2500+ sites with Maigret and records found accounts"

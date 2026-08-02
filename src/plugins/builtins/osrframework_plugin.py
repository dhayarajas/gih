"""
OSRFramework plugin for username checks via usufy.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class OsrframeworkPlugin(IntegrationPlugin):
    """Plugin wrapping the osrframework integration."""

    tool_name = "osrframework"
    analysis_type = "username_search"
    artifact_types: ClassVar[list[str]] = ["username"]
    description = "Checks a username across the OSRFramework platform list using usufy"

    def get_required_dependencies(self) -> list[str]:
        return ["usufy"]

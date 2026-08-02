"""
WhatWeb plugin for web technology fingerprinting.
"""

from typing import ClassVar

from ..integration_plugin import IntegrationPlugin


class WhatWebPlugin(IntegrationPlugin):
    """Plugin wrapping the whatweb integration."""

    tool_name = "whatweb"
    analysis_type = "tech_fingerprint"
    artifact_types: ClassVar[list[str]] = ['domain', 'subdomain']
    description = "Fingerprints web technologies and resolves addresses using WhatWeb"

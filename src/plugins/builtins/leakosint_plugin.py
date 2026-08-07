"""
LeakOSINT plugin: breach-database records for an identity selector.
"""

import logging
from typing import List

from src.modules import leakosint

from ..base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus

logger = logging.getLogger(__name__)


class LeakosintPlugin(OSINTPlugin):
    """Plugin for LeakOSINT breach-data search."""

    def __init__(self, config: PluginConfig = None):
        """Initialize the LeakOSINT plugin."""
        super().__init__(config)
        self.name = "LeakosintPlugin"

    def get_name(self) -> str:
        """Get plugin name."""
        return "LeakOSINT"

    def get_version(self) -> str:
        """Get plugin version."""
        return "1.0.0"

    def get_description(self) -> str:
        """Get plugin description."""
        return "Searches leaked databases for records matching an email, phone, username or name"

    def get_supported_artifact_types(self) -> List[str]:
        """Get supported artifact types."""
        return ["email", "phone", "username", "fullname"]

    def is_available(self) -> bool:
        """The API is only reachable with a token, so the key gates the plugin."""
        return leakosint.get_settings()["enabled"] and self._token() is not None

    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["requests"]

    def _token(self):
        if self.config and self.config.api_key:
            return str(self.config.api_key).strip() or None
        return leakosint.get_api_token()

    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Query LeakOSINT for the artifact's value.

        Args:
            artifact: Email, phone, username or full-name artifact

        Returns:
            PluginResult with one artifact per leaked record
        """
        if not self.is_available():
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SKIPPED,
                error="LeakOSINT API token not configured",
            )

        settings = leakosint.get_settings()
        params = (self.config.custom_params if self.config else None) or {}
        result = leakosint.search(
            artifact.value,
            limit=int(params.get("limit") or settings["limit"]),
            lang=str(params.get("lang") or settings["lang"]),
            timeout=settings["timeout"],
        )

        if not result.success:
            # A quota error or an outage must not fail the investigation. The
            # tool then reports as silent, so the reason is logged to keep an
            # outage distinguishable from a genuine no-match.
            logger.warning(
                "LeakOSINT returned no records for %s (%s): %s",
                artifact.value,
                artifact.type,
                result.error,
            )
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=result.error,
                metadata={"target": artifact.value},
            )

        artifacts = [
            Artifact(
                type="leak_record",
                value=f"{record.database}: {record.summary}" if record.summary else record.database,
                source=self.name,
                confidence=0.9,
                metadata={
                    "database": record.database,
                    "info": record.info,
                    "query": result.query,
                    "query_type": artifact.type,
                    "fields": record.fields,
                },
            )
            for record in result.records
        ]

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.SUCCESS,
            artifacts=artifacts,
            metadata={
                "target": artifact.value,
                "databases": result.databases,
                "records_found": len(artifacts),
            },
        )

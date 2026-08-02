"""
Plugin adapter over the external-tool integrations.

`src.modules.external_tools` already owns the subprocess invocation, timeout
handling, availability guard and output parser for every integrated tool. A
plugin for such a tool therefore only has to say *which* tool and analysis to
run and *which* artifact types it accepts -- the work of turning raw output
into artifacts must not be duplicated here, or the two copies drift.
"""

import logging
from typing import Any, ClassVar

from src.modules.external_tools import ANALYSIS_METHODS, run_tool_analysis
from src.utils.tool_checker import check_tool_availability

from .base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus

logger = logging.getLogger(__name__)

# Keys the integrations use for the artifact itself; anything else a parser
# emits (platform, service, record_type, ...) is preserved as metadata.
_ARTIFACT_KEYS = frozenset({"type", "value", "source", "confidence"})


class IntegrationPlugin(OSINTPlugin):
    """Base class for plugins backed by an `external_tools` integration.

    Subclasses set `tool_name`, `analysis_type`, `artifact_types` and
    `description`; everything else is handled here.
    """

    tool_name: str = ""
    analysis_type: str = ""
    artifact_types: ClassVar[list[str]] = []
    description: str = ""
    version: str = "1.0.0"
    # Set for tools reached over HTTP rather than a local executable.
    requires_executable: bool = True

    def __init__(self, config: PluginConfig = None):
        super().__init__(config)
        self.name = self.__class__.__name__

    def get_name(self) -> str:
        return self.tool_name

    def get_version(self) -> str:
        return self.version

    def get_description(self) -> str:
        return self.description

    def get_supported_artifact_types(self) -> list[str]:
        return list(self.artifact_types)

    def get_required_dependencies(self) -> list[str]:
        return [self.tool_name] if self.requires_executable else []

    def is_available(self) -> bool:
        if not self.requires_executable:
            return True
        return check_tool_availability(self.tool_name)

    def execute(self, artifact: Artifact) -> PluginResult:
        result = run_tool_analysis(self.tool_name, self.analysis_type, artifact.value)

        if not result.success:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILURE,
                error=result.error_message or f"{self.tool_name} failed",
                metadata={"target": artifact.value},
            )

        artifacts = [self._to_artifact(found) for found in result.artifacts_discovered]

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.SUCCESS,
            artifacts=artifacts,
            raw_data=result.parsed_data,
            execution_time=result.execution_time,
            metadata={"target": artifact.value, "artifacts_found": len(artifacts)},
        )

    def _to_artifact(self, found: dict[str, Any]) -> Artifact:
        return Artifact(
            type=found["type"],
            value=found["value"],
            source=found.get("source", self.tool_name),
            confidence=found.get("confidence", 0.8),
            metadata={k: v for k, v in found.items() if k not in _ARTIFACT_KEYS},
        )

    @classmethod
    def check_wiring(cls) -> None:
        """Fail loudly if a subclass names an analysis the integration lacks."""
        available = ANALYSIS_METHODS.get(cls.tool_name, {})
        if cls.analysis_type not in available:
            raise ValueError(
                f"{cls.__name__} requests {cls.tool_name}/{cls.analysis_type}, "
                f"but the integration only offers {sorted(available)}"
            )

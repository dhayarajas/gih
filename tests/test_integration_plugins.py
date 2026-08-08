"""Tests for the plugins backed by external-tool integrations."""

import json
from pathlib import Path
from typing import ClassVar

import pytest

from src.modules.external_tools import (
    ANALYSIS_METHODS,
    TOOL_ARTIFACT_TYPES,
    ToolResult,
    get_tool_integrations,
)
from src.modules.tool_parsers import parse_usufy_profiles
from src.plugins.base import Artifact, PluginStatus
from src.plugins.builtins import (
    AmassPlugin,
    ExifToolPlugin,
    HolehePlugin,
    MaigretPlugin,
    NmapPlugin,
    OsrframeworkPlugin,
    SherlockPlugin,
    SubfinderPlugin,
    Sublist3rPlugin,
    TheHarvesterPlugin,
    WaybackMachinePlugin,
    WhatWebPlugin,
    WhoisPlugin,
)
from src.plugins.integration_plugin import IntegrationPlugin
from src.plugins.registry import PluginRegistry

INTEGRATION_PLUGINS = [
    MaigretPlugin,
    HolehePlugin,
    SubfinderPlugin,
    Sublist3rPlugin,
    AmassPlugin,
    WhatWebPlugin,
    NmapPlugin,
    ExifToolPlugin,
    WaybackMachinePlugin,
    OsrframeworkPlugin,
    SherlockPlugin,
    WhoisPlugin,
    TheHarvesterPlugin,
]


@pytest.mark.parametrize("plugin_class", INTEGRATION_PLUGINS, ids=lambda c: c.__name__)
class TestPluginWiring:
    """Each plugin must name a tool and analysis the integration layer offers."""

    def test_analysis_exists(self, plugin_class):
        plugin_class.check_wiring()

    def test_tool_is_integrated(self, plugin_class):
        assert plugin_class.tool_name in get_tool_integrations()

    def test_declares_artifact_types(self, plugin_class):
        plugin = plugin_class()
        assert plugin.get_supported_artifact_types()
        assert plugin.get_description()
        assert plugin.get_name() == plugin_class.tool_name


class TestRegistryDiscovery:
    """The plugins must be discoverable, and the base must not be."""

    def test_all_plugins_registered(self):
        registry = PluginRegistry()
        registry.discover_plugins()
        registered = set(registry.list_plugins())

        for plugin_class in INTEGRATION_PLUGINS:
            assert plugin_class.__name__ in registered

    def test_base_class_not_registered(self):
        registry = PluginRegistry()
        registry.discover_plugins()
        assert "IntegrationPlugin" not in registry.list_plugins()


class TestExecution:
    """Execution delegates to the integration and converts its artifacts."""

    def test_artifacts_converted_with_metadata(self, monkeypatch):
        def fake_analysis(tool_name, analysis_type, target):
            assert (tool_name, analysis_type, target) == ("nmap", "host_scan", "1.2.3.4")
            return ToolResult(
                tool_name="nmap",
                success=True,
                output="",
                artifacts_discovered=[{
                    "type": "open_port",
                    "value": "1.2.3.4:22",
                    "protocol": "tcp",
                    "service": "ssh",
                    "source": "nmap",
                    "confidence": 0.9,
                }],
            )

        monkeypatch.setattr(
            "src.plugins.integration_plugin.run_tool_analysis", fake_analysis
        )

        result = NmapPlugin().execute(Artifact(type="ip_address", value="1.2.3.4", source="seed"))

        assert result.status == PluginStatus.SUCCESS
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.type == "open_port"
        assert artifact.value == "1.2.3.4:22"
        assert artifact.confidence == 0.9
        # Parser keys that are not part of the artifact itself survive as metadata.
        assert artifact.metadata == {"protocol": "tcp", "service": "ssh"}

    def test_both_harvester_analyses_run(self, monkeypatch):
        """theHarvester harvests emails and subdomains as separate runs; a
        plugin doing only one silently halves what the tool found."""
        seen = []

        def fake_analysis(tool_name, analysis_type, target):
            seen.append(analysis_type)
            return ToolResult(
                tool_name=tool_name,
                success=True,
                output="",
                artifacts_discovered=[{
                    "type": "email" if analysis_type == "email_harvest" else "subdomain",
                    "value": f"{analysis_type}@example.com",
                    "source": "theharvester",
                }],
            )

        monkeypatch.setattr(
            "src.plugins.integration_plugin.run_tool_analysis", fake_analysis
        )

        result = TheHarvesterPlugin().execute(
            Artifact(type="domain", value="example.com", source="seed")
        )

        assert seen == ["email_harvest", "subdomain_harvest"]
        assert {a.type for a in result.artifacts} == {"email", "subdomain"}

    def test_one_failed_analysis_keeps_the_other(self, monkeypatch):
        def fake_analysis(tool_name, analysis_type, target):
            if analysis_type == "email_harvest":
                return ToolResult(tool_name=tool_name, success=False, output="",
                                  error_message="no emails")
            return ToolResult(
                tool_name=tool_name, success=True, output="",
                artifacts_discovered=[{
                    "type": "subdomain", "value": "www.example.com",
                    "source": "theharvester",
                }],
            )

        monkeypatch.setattr(
            "src.plugins.integration_plugin.run_tool_analysis", fake_analysis
        )

        result = TheHarvesterPlugin().execute(
            Artifact(type="domain", value="example.com", source="seed")
        )

        assert result.status == PluginStatus.SUCCESS
        assert [a.value for a in result.artifacts] == ["www.example.com"]

    def test_failure_is_reported(self, monkeypatch):
        monkeypatch.setattr(
            "src.plugins.integration_plugin.run_tool_analysis",
            lambda *_: ToolResult(
                tool_name="maigret",
                success=False,
                output="",
                error_message="boom",
            ),
        )

        result = MaigretPlugin().execute(Artifact(type="username", value="x", source="seed"))

        assert result.status == PluginStatus.FAILURE
        assert result.error == "boom"
        assert result.artifacts == []

    def test_produces_the_declared_artifact_types(self, monkeypatch):
        """A plugin's output types must match what the coverage matrix claims."""
        monkeypatch.setattr(
            "src.plugins.integration_plugin.run_tool_analysis",
            lambda *_: ToolResult(
                tool_name="subfinder",
                success=True,
                output="",
                artifacts_discovered=[
                    {"type": "subdomain", "value": "a.example.com", "source": "subfinder"}
                ],
            ),
        )

        result = SubfinderPlugin().execute(
            Artifact(type="domain", value="example.com", source="seed")
        )

        assert [a.type for a in result.artifacts] == TOOL_ARTIFACT_TYPES["subfinder"]


class TestAvailability:
    """Availability follows the executable, except for HTTP-only tools."""

    def test_executable_backed_plugin_checks_the_tool(self, monkeypatch):
        monkeypatch.setattr(
            "src.plugins.integration_plugin.check_tool_availability",
            lambda tool: tool == "nmap",
        )
        assert NmapPlugin().is_available() is True
        assert MaigretPlugin().is_available() is False

    def test_wayback_needs_no_executable(self, monkeypatch):
        monkeypatch.setattr(
            "src.plugins.integration_plugin.check_tool_availability", lambda tool: False
        )
        assert WaybackMachinePlugin().is_available() is True
        assert WaybackMachinePlugin().get_required_dependencies() == []

    def test_osrframework_depends_on_usufy(self):
        # The framework has no "osrframework" command of its own.
        assert OsrframeworkPlugin().get_required_dependencies() == ["usufy"]


class TestWiringGuard:
    """check_wiring is the guard against silently dead plugins."""

    def test_unknown_analysis_raises(self):
        class BrokenPlugin(IntegrationPlugin):
            tool_name = "nmap"
            analysis_type = "does_not_exist"
            artifact_types: ClassVar[list[str]] = ["ip_address"]

        with pytest.raises(ValueError, match="does_not_exist"):
            BrokenPlugin.check_wiring()

    def test_no_plugin_runs_an_integrated_tool_itself(self):
        """A plugin that spawns its own subprocess for a tool the integration
        layer already owns runs a *different* command with a different parser,
        and the two copies drift: that is how the sherlock plugin came to pass
        a flag sherlock does not have, and the whois plugin to report a
        registrar's abuse mailbox as the registrant's address."""
        integrated = set(get_tool_integrations())
        offenders = []

        builtins_dir = Path(__file__).resolve().parents[1] / "src/plugins/builtins"
        for path in builtins_dir.glob("*_plugin.py"):
            source = path.read_text()
            if "subprocess" not in source:
                continue
            if any(f'"{tool}"' in source or f"'{tool}'" in source
                   for tool in integrated):
                offenders.append(path.name)

        assert not offenders, (
            f"these plugins run an integrated tool themselves: {offenders}"
        )


class TestConfigIsActuallyApplied:
    """The registry names plugins by class, config.yaml by tool. A lookup that
    misses means every `plugins.<tool>` setting -- enabled, timeout, retries --
    is silently replaced by a default."""

    def test_every_plugin_resolves_to_a_config_entry(self):
        from src.plugins.manager import PluginManager

        manager = PluginManager()
        manager.registry.discover_plugins()
        unmatched = [
            name for name in manager.registry.list_plugins()
            if manager._config_key(name) == name
        ]

        assert not unmatched, f"no plugins: entry found for {unmatched}"

    def test_a_disabled_tool_is_not_run(self, monkeypatch):
        """The switch has to hold on the integration path too, because a tool
        is dispatched both by the orchestrator and by the plugin manager."""
        from src.modules import external_tools

        monkeypatch.setattr(
            external_tools, "get_config",
            lambda: type("C", (), {"get": staticmethod(
                lambda key, default=None: {"osrframework": {"enabled": False}}
                if key == "plugins" else default
            )})(),
        )
        monkeypatch.setattr(
            external_tools, "get_tool_integrations",
            lambda: pytest.fail("a disabled tool must not be reached"),
        )

        result = external_tools.run_tool_analysis(
            "osrframework", "username_search", "someone-not-cached"
        )

        assert result.success is False
        assert "disabled" in result.error_message


class TestUsufyParser:
    """usufy reports attributes as tagged entities rather than named fields."""

    PROFILES = json.loads("""
    [
      {
        "attributes": [
          {"type": "com.i3visio.URI", "value": "https://github.com/torvalds"},
          {"type": "com.i3visio.Alias", "value": "torvalds"},
          {"type": "com.i3visio.Platform", "value": "Github"}
        ],
        "type": "com.i3visio.Profile",
        "value": "Github - torvalds"
      },
      {
        "attributes": [
          {"type": "com.i3visio.URI", "value": "https://github.com/torvalds"},
          {"type": "com.i3visio.Platform", "value": "Github"}
        ],
        "type": "com.i3visio.Profile",
        "value": "duplicate"
      },
      {
        "attributes": [
          {"type": "com.i3visio.Platform", "value": "NoUri"}
        ],
        "type": "com.i3visio.Profile",
        "value": "unusable"
      }
    ]
    """)

    def test_parses_profiles(self):
        artifacts = parse_usufy_profiles(self.PROFILES, "torvalds")

        assert len(artifacts) == 1
        assert artifacts[0] == {
            "type": "username_presence",
            "value": "https://github.com/torvalds",
            "platform": "Github",
            "username": "torvalds",
            "source": "osrframework",
            "confidence": 0.7,
        }

    def test_tolerates_unexpected_shapes(self):
        assert parse_usufy_profiles({}, "torvalds") == []
        assert parse_usufy_profiles([], "torvalds") == []
        assert parse_usufy_profiles(["not-a-dict"], "torvalds") == []


class TestOsrframeworkIntegration:
    """The integration is registered like any other tool."""

    def test_registered_with_analysis_and_types(self):
        assert "osrframework" in get_tool_integrations()
        assert ANALYSIS_METHODS["osrframework"] == {"username_search": "search_username"}
        assert TOOL_ARTIFACT_TYPES["osrframework"] == ["username_presence"]

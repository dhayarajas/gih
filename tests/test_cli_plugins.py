"""Tests for the `plugins` CLI subcommands.

These commands used to call a registry method that does not exist, so every
invocation ended in an AttributeError. They are therefore exercised through
Click itself rather than through their helpers.
"""

import pytest
from click.testing import CliRunner

from src.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestPluginsList:
    def test_list_prints_every_registered_plugin(self, runner):
        result = runner.invoke(cli, ["plugins", "list"])

        assert result.exit_code == 0, result.output
        assert "Registered Plugins" in result.output
        # A built-in (no external binary) and a tool-backed plugin.
        assert "UsernameSearchPlugin" in result.output
        assert "SherlockPlugin" in result.output

    def test_list_reports_config_state_and_artifact_types(self, runner):
        result = runner.invoke(cli, ["plugins", "list"])

        assert result.exit_code == 0, result.output
        assert "Enabled in config:" in result.output
        assert "Artifact types: username" in result.output

    def test_verbose_adds_version_and_dependencies(self, runner):
        result = runner.invoke(cli, ["plugins", "list", "--verbose"])

        assert result.exit_code == 0, result.output
        assert "Version:" in result.output
        assert "Requires:" in result.output


class TestPluginsInfo:
    def test_info_by_class_name(self, runner):
        result = runner.invoke(cli, ["plugins", "info", "SherlockPlugin"])

        assert result.exit_code == 0, result.output
        assert "Plugin: SherlockPlugin" in result.output
        assert "Tool name: sherlock" in result.output
        assert "Artifact types: username" in result.output

    def test_info_by_config_name(self, runner):
        result = runner.invoke(cli, ["plugins", "info", "username_search"])

        assert result.exit_code == 0, result.output
        assert "Plugin: UsernameSearchPlugin" in result.output
        assert "Enabled in config:" in result.output

    def test_unknown_plugin_exits_non_zero(self, runner):
        result = runner.invoke(cli, ["plugins", "info", "not_a_plugin"])

        assert result.exit_code == 1
        assert "not found" in result.output


class TestPluginsToggle:
    def test_disable_points_at_the_config_key(self, runner):
        result = runner.invoke(cli, ["plugins", "disable", "sherlock"])

        assert result.exit_code == 0, result.output
        assert "plugins.sherlock.enabled: false" in result.output

    def test_unknown_plugin_lists_the_known_ones(self, runner):
        result = runner.invoke(cli, ["plugins", "enable", "not_a_plugin"])

        assert result.exit_code == 1
        assert "Known plugins:" in result.output
        assert "sherlock" in result.output

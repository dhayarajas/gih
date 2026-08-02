"""Tests for how CLI options are turned into investigation seeds."""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

import src.cli as cli_module
from src.cli import cli
from src.orchestrator import InvestigationResult


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def captured_seeds(monkeypatch):
    """Stop before any network work and record the seeds the CLI built."""
    seeds: list[list[dict]] = []

    def _fake_run_investigation(conn, seed_list, config, title=None, **kwargs):
        seeds.append(seed_list)
        return InvestigationResult(investigation_id="INV-test", seed_artifacts=seed_list)

    monkeypatch.setattr(cli_module, "run_investigation", _fake_run_investigation)
    monkeypatch.setattr(cli_module, "generate_html_report", lambda *a, **k: "")
    return seeds


def _invoke(runner, *args):
    db_path = Path(tempfile.mktemp(suffix=".db"))
    return runner.invoke(cli, ["--db", str(db_path), "investigate", *args])


class TestSeedConstruction:
    def test_fullname_becomes_a_fullname_seed(self, runner, captured_seeds):
        result = _invoke(runner, "-n", "Linus Torvalds", "--no-external-tools")

        assert result.exit_code == 0, result.output
        assert captured_seeds[0] == [{"type": "fullname", "value": "Linus Torvalds"}]

    def test_ip_becomes_an_ip_address_seed(self, runner, captured_seeds):
        result = _invoke(runner, "--ip", "45.33.32.156", "--no-external-tools")

        assert result.exit_code == 0, result.output
        assert captured_seeds[0] == [{"type": "ip_address", "value": "45.33.32.156"}]

    def test_fullname_alone_satisfies_the_seed_requirement(self, runner, captured_seeds):
        """Without --fullname in the guard, this exits 1 as 'no seed given'."""
        result = _invoke(runner, "--fullname", "Ada Lovelace", "--no-external-tools")

        assert result.exit_code == 0, result.output

    def test_no_seed_options_is_an_error(self, runner, captured_seeds):
        result = _invoke(runner)

        assert result.exit_code == 1
        assert "At least one seed artifact required" in result.output
        assert captured_seeds == []

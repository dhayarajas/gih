"""Tests for how CLI options are turned into investigation seeds."""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

import src.cli as cli_module
from src.cli import _json_output_path, cli
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
    def test_ip_becomes_an_ip_address_seed(self, runner, captured_seeds):
        result = _invoke(runner, "--ip", "45.33.32.156", "--no-external-tools")

        assert result.exit_code == 0, result.output
        assert captured_seeds[0] == [{"type": "ip_address", "value": "45.33.32.156"}]

    def test_no_seed_options_is_an_error(self, runner, captured_seeds):
        result = _invoke(runner)

        assert result.exit_code == 1
        assert "At least one seed artifact required" in result.output
        assert captured_seeds == []


class TestReportOutputPaths:
    """--report-format both must not write the JSON over the HTML."""

    def test_both_formats_get_distinct_paths(self):
        assert _json_output_path("/tmp/r.html", "both") == "/tmp/r.json"

    def test_json_named_output_is_not_clobbered(self):
        assert _json_output_path("/tmp/r.json", "both") == "/tmp/r_data.json"

    def test_single_format_keeps_the_requested_path(self):
        assert _json_output_path("/tmp/r.html", "json") == "/tmp/r.html"
        assert _json_output_path(None, "both") is None


class TestShareableCopy:
    """A masked twin is a second file; a toggle could only unmask the first."""

    @staticmethod
    def _report(monkeypatch, tmp_path):
        """Record every report generated, writing each to disk."""
        written: list[tuple[str, bool]] = []

        def fake_generate(conn, investigation_id, output_path=None, **kwargs):
            path = Path(output_path or tmp_path / "report.html")
            path.write_text("report")
            written.append((path.name, bool(kwargs.get("redact"))))
            return str(path)

        monkeypatch.setattr(cli_module, "generate_html_report", fake_generate)
        return written

    def test_a_masked_twin_is_written_beside_the_report(self, monkeypatch, tmp_path):
        written = self._report(monkeypatch, tmp_path)
        path = cli_module._shareable_copy(
            None, "INV-test", str(tmp_path / "INV-test_report.html"),
            "standard", None,
        )
        assert Path(path).name == "INV-test_report_redacted.html"
        assert written == [("INV-test_report_redacted.html", True)]

    def test_a_failed_copy_does_not_cost_the_report(self, monkeypatch, tmp_path):
        def explode(*args, **kwargs):
            raise OSError("read-only file system")

        monkeypatch.setattr(cli_module, "generate_html_report", explode)
        assert cli_module._shareable_copy(
            None, "INV-test", str(tmp_path / "r.html"), "standard", None,
        ) is None

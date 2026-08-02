"""Tests for the --full-name seed option on the investigate command."""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from src.cli import cli


def _fake_result():
    result = MagicMock()
    result.investigation_id = "INV-test"
    result.total_artifacts = 0
    result.total_links = 0
    result.total_platforms = 0
    result.risk_indicators = []
    return result


def test_full_name_seeds_fullname_artifact():
    runner = CliRunner()
    with patch("src.cli.get_connection", return_value=MagicMock()), \
            patch("src.cli.run_investigation", return_value=_fake_result()) as run:
        res = runner.invoke(
            cli,
            ["investigate", "--full-name", "Jane Doe", "--report-format", "json"],
        )

    assert res.exit_code == 0, res.output
    seeds = run.call_args.args[1]
    assert {"type": "fullname", "value": "Jane Doe"} in seeds


def test_short_flag_and_multiple_names():
    runner = CliRunner()
    with patch("src.cli.get_connection", return_value=MagicMock()), \
            patch("src.cli.run_investigation", return_value=_fake_result()) as run:
        res = runner.invoke(
            cli,
            ["investigate", "-n", "Jane Doe", "-n", "John Roe"],
        )

    assert res.exit_code == 0, res.output
    seeds = run.call_args.args[1]
    names = [s["value"] for s in seeds if s["type"] == "fullname"]
    assert names == ["Jane Doe", "John Roe"]


def test_no_seed_still_errors_without_full_name():
    runner = CliRunner()
    res = runner.invoke(cli, ["investigate"])
    assert res.exit_code != 0
    assert "--full-name" in res.output

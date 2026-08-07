"""Tests for finishing the run whatever a tool or a module does.

An investigation is long and expensive: nothing a single tool prints, fails at
or hangs on may cost the operator the whole run or its report.
"""

import subprocess
import sys
import time

import pytest
from click.testing import CliRunner

from src.modules import external_tools
from src.modules.external_tools import ExternalToolsIntegration


@pytest.fixture
def integration():
    return ExternalToolsIntegration()


def _python(script: str) -> list[str]:
    return [sys.executable, "-c", script]


class TestASlowTool:

    def test_a_tool_that_never_returns_is_stopped(self, integration):
        """The deadline is enforced, and the run continues without it."""
        started = time.monotonic()
        result = integration.run_tool(
            "sleeper",
            _python("import time; time.sleep(60)"),
            timeout=2,
        )

        assert not result.success
        assert "timed out" in result.error_message
        assert time.monotonic() - started < 30

    def test_a_forking_tool_does_not_hang_the_run(self, integration):
        """A child holding the pipe open used to block the cleanup forever."""
        started = time.monotonic()
        result = integration.run_tool(
            "forker",
            _python(
                "import subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                "print('started', flush=True); time.sleep(60)"
            ),
            timeout=3,
        )

        assert not result.success
        assert time.monotonic() - started < 30
        # What it printed before the deadline is still evidence.
        assert "started" in result.output

    def test_the_children_are_stopped_too(self, integration):
        """A killed tool must not leave its scanners running."""
        marker = "gih-resilience-grandchild"
        integration.run_tool(
            "forker",
            _python(
                "import subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)  # {marker}']); "
                "time.sleep(60)"
            ),
            timeout=3,
        )

        time.sleep(1)
        running = subprocess.run(
            ["pgrep", "-f", marker], capture_output=True, text=True
        )
        assert running.stdout.strip() == ""


class TestUnreadableOutput:

    def test_bytes_that_are_not_text_do_not_lose_the_run(self, integration):
        """Tools print filenames in whatever encoding they were given."""
        result = integration.run_tool(
            "noisy",
            _python(
                "import sys; sys.stdout.buffer.write(b'found \\xff\\xfe here\\n')"
            ),
        )

        assert result.success
        assert "found" in result.output and "here" in result.output

    def test_an_endless_talker_is_cut_off(self, integration, monkeypatch):
        """Output is kept in memory, so it cannot be unbounded."""
        monkeypatch.setattr(external_tools, "MAX_TOOL_OUTPUT_BYTES", 1024)

        result = integration.run_tool(
            "shouter",
            _python("print('x' * 200000)"),
        )

        assert result.success
        assert len(result.output) == 1024

    def test_a_missing_tool_is_reported_not_raised(self, integration):
        result = integration.run_tool("ghost", ["gih-no-such-tool-anywhere"])

        assert not result.success
        assert "not found" in result.error_message


class TestCorrelationFailure:

    def test_the_run_survives_an_analysis_it_cannot_do(self, monkeypatch):
        """Everything is already stored; the metrics are not worth the run."""
        from src.modules import correlation
        from src import orchestrator

        monkeypatch.setattr(
            correlation, "analyze_correlation",
            lambda artifacts, links: (_ for _ in ()).throw(ValueError("bad graph")),
        )

        analysis = orchestrator._safe_correlation([{"a": 1}], [{"b": 2}])

        assert analysis.artifacts_analyzed == 1
        assert analysis.links_found == 1


class TestAnAbortedRun:

    def test_what_was_found_is_still_reported(self, tmp_path, monkeypatch):
        """A run that stops partway keeps its findings and its report."""
        from src import cli as cli_module
        from src.storage import database as db

        db_path = tmp_path / "gih.db"

        def stop_after_the_seed(conn, seeds, config=None, title=None, started=None):
            inv_id = db.create_investigation(conn, title=title)
            started["id"] = inv_id
            db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed")
            raise RuntimeError("a tool took the run down")

        monkeypatch.setattr(
            "src.orchestrator._run_investigation", stop_after_the_seed
        )

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "--db", str(db_path),
                "investigate", "--username", "ghostuser",
                "--report-output", str(tmp_path / "r.html"),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "stopped early" in result.output.lower()
        assert "a tool took the run down" in result.output
        assert (tmp_path / "r.html").exists()
        assert "ghostuser" in (tmp_path / "r.html").read_text()

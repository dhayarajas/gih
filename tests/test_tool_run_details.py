"""Tool Run Status: what each tool ran, how long it waited, what it printed."""

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.reporting.html_report import generate_html_report
from src.reporting.report_data import SECRET_MASK, enrich_tool_status, mask_secrets
from src.storage import database as db
from src.storage import evidence as evidence_store


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def only_whois_installed(monkeypatch):
    """Pin host availability so the rows do not depend on this machine."""
    from src.utils import tool_checker

    monkeypatch.setattr(
        tool_checker, "get_tool_checker",
        lambda: SimpleNamespace(is_available=lambda tool: tool == "whois"),
    )


def capture_file(tmp_path: Path, body: str, name: str = "capture.txt") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def run_row(tmp_path: Path, tool: str = "whois", **overrides) -> dict:
    row = {
        "tool": tool,
        "operation": "lookup",
        "target": "example.com",
        "command": f"{tool} example.com",
        "captured_at": "2026-01-01T09:00:00+00:00",
        "duration_seconds": 4.25,
        "exit_status": "exit 0",
        "sha256": "a" * 64,
        "byte_size": 24,
        "stored_path": str(capture_file(tmp_path, "Registrant: Example Ltd\n")),
        "truncated": 0,
    }
    row.update(overrides)
    return row


def statuses(tool_metrics, **kwargs) -> dict:
    metrics = enrich_tool_status(tool_metrics, **kwargs)
    return {row["tool"]: row for row in metrics["tool_status"]}


class TestRunDetail:
    def test_a_productive_tool_shows_its_command_wait_and_log(
        self, tmp_path, only_whois_installed
    ):
        rows = statuses(
            {"tools": [{"tool": "whois", "kind": "tool"}], "silent_tools": []},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path)],
        )
        run = rows["whois"]["runs"][0]
        assert rows["whois"]["state"] == "produced_output"
        assert run["command"] == "whois example.com"
        assert run["duration_seconds"] == 4.25
        assert run["timeout_seconds"] == 30
        assert run["exit_status"] == "exit 0"
        assert run["captured_at"].startswith("2026-01-01")
        assert "Registrant: Example Ltd" in run["log"]

    def test_a_silent_tool_still_shows_the_run_behind_its_silence(
        self, tmp_path, only_whois_installed
    ):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path, command="whois ghost.example")],
        )
        assert rows["whois"]["state"] == "silent_or_not_dispatched"
        assert rows["whois"]["runs"][0]["command"] == "whois ghost.example"

    def test_a_tool_that_never_ran_has_no_panel_to_fill(self, only_whois_installed):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "username"}],
            evidence_runs=[],
        )
        assert rows["whois"]["runs"] == []
        assert rows["whois"]["reason"].startswith("not dispatched")

    def test_a_disabled_tool_says_so_rather_than_showing_an_empty_panel(
        self, monkeypatch, only_whois_installed, tmp_path
    ):
        from src.modules import external_tools
        from src.reporting import report_data

        monkeypatch.setattr(external_tools, "tool_enabled", lambda tool: False)
        monkeypatch.setattr(report_data, "tool_enabled", lambda tool: False)
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[],
        )
        assert rows["whois"]["runs"] == []
        assert rows["whois"]["reason"] == "not dispatched — disabled in configuration"

    def test_a_timeout_keeps_its_status_against_the_budget(
        self, tmp_path, only_whois_installed
    ):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path, exit_status="timeout", duration_seconds=30.0)],
        )
        run = rows["whois"]["runs"][0]
        assert run["exit_status"] == "timeout"
        assert (run["duration_seconds"], run["timeout_seconds"]) == (30.0, 30)

    def test_a_non_zero_exit_is_reported_as_it_happened(
        self, tmp_path, only_whois_installed
    ):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path, exit_status="exit 2")],
        )
        assert rows["whois"]["runs"][0]["exit_status"] == "exit 2"

    def test_a_capped_capture_is_flagged_with_its_size_and_digest(
        self, tmp_path, only_whois_installed
    ):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path, truncated=1, byte_size=2097152)],
        )
        run = rows["whois"]["runs"][0]
        assert run["truncated"] is True
        assert (run["byte_size"], run["sha256"]) == (2097152, "a" * 64)

    def test_a_capture_longer_than_the_report_allows_is_clipped(
        self, tmp_path, only_whois_installed
    ):
        body = "x" * (evidence_store.REPORT_EXCERPT_BYTES + 500)
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(
                tmp_path,
                stored_path=str(capture_file(tmp_path, body, name="big.txt")),
            )],
        )
        run = rows["whois"]["runs"][0]
        assert run["log_clipped"] is True
        assert len(run["log"]) == evidence_store.REPORT_EXCERPT_BYTES

    def test_a_missing_capture_file_says_so(self, tmp_path, only_whois_installed):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path, stored_path=str(tmp_path / "gone.txt"))],
        )
        run = rows["whois"]["runs"][0]
        assert run["log"] is None
        assert run["log_note"] == "capture file is no longer readable"

    def test_the_redacted_copy_carries_no_command_target_or_log(
        self, tmp_path, only_whois_installed
    ):
        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(tmp_path)],
            redact=True,
        )
        run = rows["whois"]["runs"][0]
        assert (run["command"], run["target"], run["log"]) == (None, None, None)
        assert run["exit_status"] == "exit 0"
        assert run["duration_seconds"] == 4.25


class TestSecretMasking:
    def test_a_configured_key_never_reaches_the_report(self, tmp_path, only_whois_installed):
        from src.config import loader

        loader._global_config = None
        secret = (loader.get_config().get("plugins", {})
                  .get("leakosint", {}).get("api_key"))
        assert secret, "config must ship a leakosint key for this test to mean anything"

        rows = statuses(
            {"tools": [], "silent_tools": ["whois"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[run_row(
                tmp_path,
                command=f"POST https://leakosintapi.com/ token={secret}",
                stored_path=str(capture_file(
                    tmp_path, f"queried with {secret}\n", name="keyed.txt")),
            )],
        )
        run = rows["whois"]["runs"][0]
        assert secret not in run["command"]
        assert secret not in run["log"]
        assert SECRET_MASK in run["command"]

    def test_a_key_passed_as_an_option_or_a_query_parameter_is_masked(self):
        assert mask_secrets("shodan host --api-key sekret-value 1.2.3.4") == (
            f"shodan host --api-key {SECRET_MASK} 1.2.3.4"
        )
        assert mask_secrets("GET https://api.example.com/s?q=x&key=abcdef123456&n=1") == (
            f"GET https://api.example.com/s?q=x&key={SECRET_MASK}&n=1"
        )

    def test_an_ordinary_command_is_left_alone(self):
        assert mask_secrets("nmap -F 93.184.216.34") == "nmap -F 93.184.216.34"

    def test_a_placeholder_credential_does_not_censor_the_word_it_spells(self):
        from src.config import loader
        from src.reporting.report_data import _configured_secrets

        loader._global_config = None
        assert "password" not in _configured_secrets()
        assert mask_secrets("holehe found a password reset form") == (
            "holehe found a password reset form"
        )

    def test_a_shipped_placeholder_is_not_taken_for_a_credential(self):
        from src.reporting.report_data import _looks_like_credential

        assert not _looks_like_credential("password")
        assert not _looks_like_credential("changeme")
        assert not _looks_like_credential("secret")
        assert _looks_like_credential("8810459628:BDW8tFR3")
        assert _looks_like_credential("0000000000000000")


class TestRenderedPanel:
    def test_the_panel_reaches_the_report_collapsed(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Run detail")
        db.add_artifact(conn, inv_id, "domain", "example.com",
                        source="whois", confidence=0.7, depth=1)
        db.add_evidence(conn, evidence_store.EvidenceCapture(
            investigation_id=inv_id, tool="whois", operation="lookup",
            target="example.com", command="whois example.com",
            tool_version="5.5.14", captured_at="2026-01-01T09:00:00+00:00",
            duration_seconds=4.25, exit_status="exit 0", sha256="b" * 64,
            byte_size=24, stored_path=str(capture_file(tmp_path, "Registrant: Example Ltd\n")),
        ))
        html = Path(generate_html_report(
            conn, inv_id, str(tmp_path / "report.html")
        )).read_text()

        assert '<details class="tool-detail">' in html
        assert '<details class="tool-detail" open>' not in html
        assert "whois example.com" in html
        assert "4.2 s of a 30 s budget" in html
        assert "Registrant: Example Ltd" in html

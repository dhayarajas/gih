"""Tests for preservation and verification of raw tool output."""

import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.reporting.report_data import build_preserved_evidence
from src.storage import database as db
from src.storage import evidence


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def capturing(tmp_path, conn):
    """An investigation with capture active against a temporary store."""
    inv_id = db.create_investigation(conn, title="Evidence")
    with patch.object(evidence, "evidence_root", return_value=tmp_path):
        evidence.begin(inv_id)
        yield inv_id
    evidence.end()


class TestCapture:
    def test_output_is_stored_under_its_own_digest(self, conn, capturing, tmp_path):
        capture = evidence.record("whois", "Domain Name: example.com\n",
                                  command="whois example.com", exit_status="exit 0")

        expected = hashlib.sha256(b"Domain Name: example.com\n").hexdigest()
        assert capture.sha256 == expected
        assert Path(capture.stored_path) == tmp_path / capturing / f"{expected}.txt"
        assert Path(capture.stored_path).read_text() == "Domain Name: example.com\n"

    def test_identical_output_is_stored_once_and_recorded_twice(self, conn, capturing):
        first = evidence.record("whois", "same", command="whois a")
        second = evidence.record("whois", "same", command="whois b")

        assert first.sha256 == second.sha256
        assert first.stored_path == second.stored_path
        assert evidence.flush(conn) == 2
        assert len(db.get_evidence(conn, capturing)) == 2

    def test_oversized_output_is_truncated_and_marked(self, conn, capturing):
        capture = evidence.record("sherlock", "x" * (evidence.MAX_CAPTURE_BYTES + 500))

        assert capture.truncated is True
        assert capture.byte_size <= evidence.MAX_CAPTURE_BYTES + len(evidence.TRUNCATION_NOTICE) + 16
        assert "capture truncated" in Path(capture.stored_path).read_text()

    def test_capture_outside_an_investigation_is_a_no_op(self):
        evidence.end()
        assert evidence.record("whois", "output") is None

    def test_the_analysing_scope_labels_captures(self, conn, capturing):
        with evidence.analysing("domain_lookup", "example.com"):
            capture = evidence.record("whois", "output")

        assert capture.operation == "domain_lookup"
        assert capture.target == "example.com"

    def test_disabled_by_config(self, tmp_path, conn):
        inv_id = db.create_investigation(conn, title="Disabled")
        with patch.object(evidence, "is_enabled", return_value=False), \
                patch.object(evidence, "evidence_root", return_value=tmp_path):
            evidence.begin(inv_id)
            assert evidence.record("whois", "output") is None
        evidence.end()


class TestVerification:
    def test_untouched_capture_verifies(self, conn, capturing):
        evidence.record("whois", "output", command="whois example.com")
        evidence.flush(conn)

        summary = build_preserved_evidence(conn, capturing)
        assert summary["intact"] is True
        assert summary["verified"] == 1
        assert summary["items"][0]["status"] == "verified"

    def test_edited_capture_is_reported_as_modified(self, conn, capturing):
        capture = evidence.record("whois", "output")
        evidence.flush(conn)
        Path(capture.stored_path).write_text("tampered")

        summary = build_preserved_evidence(conn, capturing)
        assert summary["intact"] is False
        assert summary["modified"] == 1
        assert summary["items"][0]["status"] == "modified"

    def test_deleted_capture_is_reported_as_missing(self, conn, capturing):
        capture = evidence.record("whois", "output")
        evidence.flush(conn)
        Path(capture.stored_path).unlink()

        summary = build_preserved_evidence(conn, capturing)
        assert summary["missing"] == 1
        assert summary["items"][0]["status"] == "missing"

    def test_redaction_withholds_the_command_and_target(self, conn, capturing):
        evidence.record("holehe", "output", command="holehe ghost@example.com",
                        target="ghost@example.com")
        evidence.flush(conn)

        summary = build_preserved_evidence(conn, capturing, redact=True)
        item = summary["items"][0]
        assert item["command"] is None
        assert item["target"] is None
        assert item["sha256"]

    def test_investigation_without_captures(self, conn):
        inv_id = db.create_investigation(conn, title="None")
        summary = build_preserved_evidence(conn, inv_id)
        assert summary["enabled"] is False
        assert summary["items"] == []


class TestToolIntegration:
    def test_run_tool_preserves_subprocess_output(self, conn, capturing):
        from src.modules.external_tools import ExternalToolsIntegration

        result = ExternalToolsIntegration().run_tool(
            "echo_test", ["echo", "hello evidence"], timeout=10
        )
        assert "hello evidence" in result.output

        evidence.flush(conn)
        rows = db.get_evidence(conn, capturing)
        assert len(rows) == 1
        assert rows[0]["tool"] == "echo_test"
        assert rows[0]["command"] == "echo hello evidence"
        assert rows[0]["exit_status"] == "exit 0"
        assert Path(rows[0]["stored_path"]).read_text() == result.output

    def test_a_failed_tool_run_is_preserved_too(self, conn, capturing):
        from src.modules.external_tools import ExternalToolsIntegration

        ExternalToolsIntegration().run_tool("missing_test", ["gih-no-such-binary"], timeout=5)

        evidence.flush(conn)
        rows = db.get_evidence(conn, capturing)
        assert rows[0]["exit_status"] == "not_found"

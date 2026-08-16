"""A tool that emits binary garbage must not reach the database, report or log.

A stubbed whatweb answering `--version` normally and then printing raw bytes
persisted four `web_technology` artifacts made of control characters, put 2068
control bytes into the HTML, and left the Tool Run Status row claiming the tool
"found nothing" while the artifact chart credited it with four findings.
"""

import logging
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import orchestrator
from src.modules import external_tools
from src.modules.external_tools import STATUS_UNPARSABLE, ToolResult
from src.orchestrator import ArtifactProcessResult, InvestigationConfig, run_investigation
from src.reporting.html_report import _generate_tool_metrics
from src.reporting.report_data import enrich_tool_status
from src.storage import database as db
from src.storage.evidence import EvidenceCapture
from src.utils.text import ControlSafeFormatter, has_control_characters, is_textual

# What a lenient decode makes of a binary stream: control bytes plus the
# replacement character where a byte was not valid UTF-8.
BINARY_OUTPUT = "1[\xd8\ufffd\x0f\x8a\ufffd\x16J\x00\x01\x02\ufffd\x1b\x7f" * 8

# whatweb reporting a real page whose title came back in an unexpected
# encoding: mostly readable, a couple of bytes that did not survive decoding.
MESSY_OUTPUT = (
    "http://example.com [200 OK] Country[UNITED STATES][US], "
    "HTTPServer[nginx/1.18.0], Title[Caf\ufffd\ufffd de Paris], "
    "IP[93.184.216.34], nginx[1.18.0]\n"
)


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


def capture(exit_status: str = "exit 0") -> EvidenceCapture:
    return EvidenceCapture(
        investigation_id="INV-test",
        tool="whatweb",
        operation="tech_fingerprint",
        target="example.com",
        command="whatweb example.com",
        tool_version="0.5.5",
        captured_at="2026-01-01T09:00:00+00:00",
        duration_seconds=0.4,
        exit_status=exit_status,
        sha256="a" * 64,
        byte_size=len(BINARY_OUTPUT),
        stored_path="/nonexistent/capture.txt",
    )


def fake_whatweb(monkeypatch, output: str, findings: list[dict],
                 exit_status: str = "exit 0") -> ToolResult:
    """Dispatch whatweb through a fake integration returning a fixed capture."""
    result = ToolResult(
        tool_name="whatweb",
        success=True,
        output=output,
        parsed_data={"technologies": [f["value"] for f in findings]},
        artifacts_discovered=findings,
        capture=capture(exit_status),
    )
    monkeypatch.setattr(
        external_tools, "get_tool_integrations",
        lambda: {"whatweb": SimpleNamespace(fingerprint=lambda target: result)},
    )
    external_tools.clear_tool_analysis_cache()
    return external_tools.run_tool_analysis("whatweb", "tech_fingerprint", "example.com")


class TestBinaryCapture:
    """A capture that is not text is an outcome, not a set of findings."""

    def test_binary_output_yields_no_artifacts_and_its_own_status(self, monkeypatch):
        result = fake_whatweb(
            monkeypatch,
            BINARY_OUTPUT,
            [{"type": "web_technology", "value": "1[\xd8\ufffd\x0f\x16J",
              "source": "whatweb", "confidence": 0.8}],
        )

        assert result.artifacts_discovered == []
        assert result.parsed_data == {}
        assert not result.success
        assert result.capture.exit_status == STATUS_UNPARSABLE

    def test_the_report_names_the_outcome(self, monkeypatch):
        result = fake_whatweb(
            monkeypatch, BINARY_OUTPUT,
            [{"type": "web_technology", "value": "\x01\x02\x03", "source": "whatweb"}],
        )
        monkeypatch.setattr(
            "src.utils.tool_checker.get_tool_checker",
            lambda: SimpleNamespace(is_available=lambda tool: tool == "whatweb"),
        )

        metrics = enrich_tool_status(
            {"tools": [], "silent_tools": ["whatweb"]},
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[{"tool": "whatweb",
                            "exit_status": result.capture.exit_status}],
            include_logs=False,
        )
        row = next(r for r in metrics["tool_status"] if r["tool"] == "whatweb")

        assert row["reason"] == "ran but returned unparsable output"

    def test_a_control_character_value_is_dropped_from_a_readable_run(self, monkeypatch):
        result = fake_whatweb(
            monkeypatch, MESSY_OUTPUT,
            [
                {"type": "web_technology", "value": "nginx[1.18.0]", "source": "whatweb"},
                {"type": "web_technology", "value": "Title[\x00\x01\x02]", "source": "whatweb"},
            ],
        )

        assert [a["value"] for a in result.artifacts_discovered] == ["nginx[1.18.0]"]
        assert result.success
        assert result.capture.exit_status == "exit 0"

    def test_a_partly_messy_capture_is_still_parsed(self, monkeypatch):
        findings = [
            {"type": "ip_address", "value": "93.184.216.34", "source": "whatweb"},
            {"type": "web_technology", "value": "HTTPServer[nginx/1.18.0]",
             "source": "whatweb"},
        ]
        result = fake_whatweb(monkeypatch, MESSY_OUTPUT, findings)

        assert result.artifacts_discovered == findings
        assert result.success
        assert result.capture.exit_status == "exit 0"
        assert is_textual(MESSY_OUTPUT)

    def test_a_timeout_keeps_the_better_explanation_it_already_has(self, monkeypatch):
        result = fake_whatweb(
            monkeypatch, BINARY_OUTPUT,
            [{"type": "web_technology", "value": "\x01\x02", "source": "whatweb"}],
            exit_status="timeout",
        )

        assert result.artifacts_discovered == []
        assert result.capture.exit_status == "timeout"


class TestArtifactBoundary:
    """The backstop protecting every tool, integration and plugin alike."""

    def test_a_binary_value_is_never_persisted(self, conn, monkeypatch):
        discovered = [
            {"type": "web_technology", "value": "1[\xd8\x0f\x16J",
             "source": "plugin:WhatWebPlugin", "confidence": 0.8},
            {"type": "subdomain", "value": "www.example.com",
             "source": "plugin:WhatWebPlugin", "confidence": 0.8},
        ]

        def _fake(inv_id, artifact, config, plugin_manager=None):
            res = ArtifactProcessResult(artifact=artifact)
            if artifact["depth"] == 0:
                res.discovered = list(discovered)
            return res

        monkeypatch.setattr(orchestrator, "_process_artifact", _fake)
        result = run_investigation(
            conn,
            seeds=[{"type": "domain", "value": "example.com"}],
            config=InvestigationConfig(
                max_depth=1,
                check_breaches=False,
                search_usernames=False,
                check_external_tools=False,
            ),
        )

        values = [a["value"] for a in db.get_artifacts(conn, result.investigation_id)]
        assert "www.example.com" in values
        assert not any(has_control_characters(value) for value in values)


class TestStatusAgreesWithTheChart:
    """A tool credited with artifacts cannot also be reported as silent."""

    @pytest.fixture
    def whatweb_installed(self, monkeypatch):
        monkeypatch.setattr(
            "src.utils.tool_checker.get_tool_checker",
            lambda: SimpleNamespace(is_available=lambda tool: tool == "whatweb"),
        )

    def test_a_plugin_sourced_tool_is_not_called_silent(self, whatweb_installed):
        artifacts = [
            {"artifact_type": "web_technology", "value": f"nginx[{i}]",
             "source": "plugin:WhatWebPlugin", "confidence": 0.8}
            for i in range(4)
        ]
        tool_metrics = _generate_tool_metrics(
            artifacts, SimpleNamespace(identities=[])
        )
        metrics = enrich_tool_status(
            tool_metrics,
            artifacts=artifacts,
            evidence_runs=[{"tool": "whatweb", "exit_status": "exit 0"}],
            include_logs=False,
        )

        credited = {t["tool"]: t["count"] for t in tool_metrics["tools"]
                    if t["kind"] == "tool"}
        silent = {row["tool"] for row in metrics["tool_status"]
                  if row["state"] == "silent_or_not_dispatched"}

        assert credited == {"whatweb": 4}
        assert not credited.keys() & silent
        assert "whatweb" not in metrics["silent_installed"]

    def test_a_tool_reported_unparsable_is_credited_with_nothing(self, whatweb_installed):
        tool_metrics = _generate_tool_metrics([], SimpleNamespace(identities=[]))
        metrics = enrich_tool_status(
            tool_metrics,
            artifacts=[{"artifact_type": "domain"}],
            evidence_runs=[{"tool": "whatweb", "exit_status": STATUS_UNPARSABLE}],
            include_logs=False,
        )
        row = next(r for r in metrics["tool_status"] if r["tool"] == "whatweb")

        assert row["reason"] == "ran but returned unparsable output"
        assert not [t for t in tool_metrics["tools"] if t["tool"] == "whatweb"]


class TestLogFile:
    """A log holding raw bytes is a binary file: grep and reviewers lose it."""

    def test_control_bytes_are_escaped_out_of_a_record(self):
        record = logging.LogRecord(
            name="src.modules.external_tools", level=logging.WARNING,
            pathname=__file__, lineno=1,
            msg="whatweb returned %s", args=(BINARY_OUTPUT,), exc_info=None,
        )
        formatted = ControlSafeFormatter("%(message)s").format(record)

        assert not has_control_characters(formatted)
        assert "\\x0f" in formatted

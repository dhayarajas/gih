"""Tests for per-finding source citations."""

import json
import tempfile
from pathlib import Path

import pytest

from src.reporting.html_report import generate_html_report, generate_json_report
from src.reporting.report_data import build_source_citations
from src.storage import database as db
from src.storage import evidence as evidence_store


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


def _capture(inv_id, tool, *, target, command, captured_at, version="1.2.3",
             duration=1.5, status="exit 0"):
    return evidence_store.EvidenceCapture(
        investigation_id=inv_id, tool=tool, operation="scan", target=target,
        command=command, tool_version=version, captured_at=captured_at,
        duration_seconds=duration, exit_status=status,
        sha256="a" * 64, byte_size=120, stored_path="/tmp/a.txt",
    )


@pytest.fixture
def investigation(conn):
    inv_id = db.create_investigation(conn, title="Citations")
    db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed")
    db.add_artifact(
        conn, inv_id, "email", "ghost@example.com", source="holehe", confidence=0.8,
        depth=1, metadata=json.dumps({"profile_url": "https://example.com/u/ghostuser"}),
    )
    db.add_evidence(conn, _capture(
        inv_id, "holehe", target="ghostuser", command="holehe ghost@example.com",
        captured_at="2026-01-01T10:00:00+00:00",
    ))
    return inv_id


class TestCitations:
    def test_a_finding_cites_the_run_that_produced_it(self, conn, investigation):
        artifacts = db.get_artifacts(conn, investigation)
        email = next(a for a in artifacts if a["artifact_type"] == "email")

        citation = build_source_citations(conn, investigation, artifacts)[email["artifact_id"]][0]
        assert citation["tool"] == "holehe"
        assert citation["tool_version"] == "1.2.3"
        assert citation["command"] == "holehe ghost@example.com"
        assert citation["duration_seconds"] == 1.5
        assert citation["exit_status"] == "exit 0"
        assert citation["sha256"] == "a" * 64

    def test_a_version_banner_repeating_the_tool_name_is_shortened(self, conn):
        inv_id = db.create_investigation(conn, title="Banner")
        db.add_artifact(conn, inv_id, "domain", "example.com", source="whois", depth=1)
        db.add_evidence(conn, _capture(
            inv_id, "whois", target="example.com", command="whois example.com",
            captured_at="2026-01-01T09:00:00+00:00", version="whois 5.5.14"))

        artifacts = db.get_artifacts(conn, inv_id)
        citation = build_source_citations(conn, inv_id, artifacts)[
            artifacts[0]["artifact_id"]][0]
        assert citation["tool_version"] == "5.5.14"

    def test_a_banner_whose_next_word_starts_with_v_is_left_intact(self, conn):
        inv_id = db.create_investigation(conn, title="Banner")
        db.add_artifact(conn, inv_id, "ip_address", "93.184.216.34", source="nmap", depth=1)
        db.add_evidence(conn, _capture(
            inv_id, "nmap", target="93.184.216.34", command="nmap 93.184.216.34",
            captured_at="2026-01-01T09:00:00+00:00", version="Nmap version 7.94"))

        artifacts = db.get_artifacts(conn, inv_id)
        citation = build_source_citations(conn, inv_id, artifacts)[
            artifacts[0]["artifact_id"]][0]
        assert citation["tool_version"] == "version 7.94"

    def test_a_url_recorded_on_the_artifact_is_cited_too(self, conn, investigation):
        artifacts = db.get_artifacts(conn, investigation)
        email = next(a for a in artifacts if a["artifact_type"] == "email")

        urls = [c for c in build_source_citations(conn, investigation, artifacts)[
            email["artifact_id"]] if c["kind"] == "url"]
        assert urls == [{"kind": "url", "field": "profile_url",
                         "url": "https://example.com/u/ghostuser"}]

    def test_an_artifact_with_no_matching_run_is_left_uncited(self, conn, investigation):
        artifacts = db.get_artifacts(conn, investigation)
        seed = next(a for a in artifacts if a["source"] == "seed")

        assert seed["artifact_id"] not in build_source_citations(conn, investigation, artifacts)

    def test_the_run_targeting_this_artifact_wins_over_the_earlier_one(self, conn):
        inv_id = db.create_investigation(conn, title="Two runs")
        db.add_artifact(conn, inv_id, "domain", "example.com", source="whois", depth=1)
        db.add_evidence(conn, _capture(
            inv_id, "whois", target="other.com", command="whois other.com",
            captured_at="2026-01-01T09:00:00+00:00"))
        db.add_evidence(conn, _capture(
            inv_id, "whois", target="example.com", command="whois example.com",
            captured_at="2026-01-01T09:30:00+00:00"))

        artifacts = db.get_artifacts(conn, inv_id)
        citation = build_source_citations(conn, inv_id, artifacts)[
            artifacts[0]["artifact_id"]][0]
        assert citation["command"] == "whois example.com"

    def test_a_run_after_the_finding_cannot_be_its_source(self, conn):
        inv_id = db.create_investigation(conn, title="Later run")
        db.add_artifact(conn, inv_id, "domain", "example.com", source="whois", depth=1)
        db.add_evidence(conn, _capture(
            inv_id, "whois", target="unrelated.com", command="whois unrelated.com",
            captured_at="2099-01-01T00:00:00+00:00"))

        artifacts = db.get_artifacts(conn, inv_id)
        assert build_source_citations(conn, inv_id, artifacts) == {}

    def test_a_later_run_targeting_the_value_did_not_produce_it(self, conn):
        inv_id = db.create_investigation(conn, title="Expansion")
        db.add_artifact(conn, inv_id, "domain", "sub.example.com",
                        source="subfinder", depth=1)
        db.add_evidence(conn, _capture(
            inv_id, "subfinder", target="example.com",
            command="subfinder -d example.com",
            captured_at="2020-01-01T09:00:00+00:00"))
        # The next depth feeds the finding back in as a target; that run
        # consumed the artifact rather than reporting it.
        db.add_evidence(conn, _capture(
            inv_id, "subfinder", target="sub.example.com",
            command="subfinder -d sub.example.com",
            captured_at="2099-01-01T09:00:00+00:00"))

        artifacts = db.get_artifacts(conn, inv_id)
        citation = build_source_citations(conn, inv_id, artifacts)[
            artifacts[0]["artifact_id"]][0]
        assert citation["command"] == "subfinder -d example.com"

    def test_redaction_drops_the_seed_bearing_fields_only(self, conn, investigation):
        artifacts = db.get_artifacts(conn, investigation)
        email = next(a for a in artifacts if a["artifact_type"] == "email")

        cited = build_source_citations(conn, investigation, artifacts, redact=True)[
            email["artifact_id"]]
        assert len(cited) == 1  # the URL citation is gone
        assert cited[0]["command"] is None
        assert cited[0]["target"] is None
        assert cited[0]["tool_version"] == "1.2.3"
        assert cited[0]["sha256"] == "a" * 64


class TestToolVersionCapture:
    def test_a_capture_records_the_version_of_the_tool(self, monkeypatch, tmp_path):
        monkeypatch.setattr(evidence_store, "tool_version", lambda tool: "whois 5.5.14")
        monkeypatch.setattr(evidence_store, "evidence_root", lambda: tmp_path)
        evidence_store.begin("INV-version")
        try:
            capture = evidence_store.record("whois", "raw output", command="whois example.com")
        finally:
            evidence_store.end()

        assert capture.tool_version == "whois 5.5.14"

    def test_an_unknown_tool_reports_no_version_rather_than_failing(self):
        assert evidence_store.tool_version("not-a-real-tool") is None


class TestRendering:
    def test_the_report_shows_the_command_version_and_timing(
        self, conn, investigation, tmp_path
    ):
        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / "r.html"))).read_text()

        assert "Source Citation" in html
        assert "holehe ghost@example.com" in html
        assert "1.2.3" in html
        assert "1.50s" in html

    def test_a_redacted_report_cites_without_the_command(
        self, conn, investigation, tmp_path
    ):
        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / "r.html"), redact=True)).read_text()

        citation_block = html.split("Source Citation", 1)[1].split("</table>", 1)[0]
        assert "holehe" in citation_block
        assert "holehe ghost@example.com" not in citation_block
        assert "https://example.com/u/ghostuser" not in citation_block

    def test_a_redacted_report_still_cites_the_run_that_found_the_artifact(
        self, conn, investigation, tmp_path
    ):
        # The run naming this artifact must win over a later unrelated run of
        # the same tool, which it cannot if masking has changed the value the
        # target is compared against.
        db.add_evidence(conn, _capture(
            investigation, "holehe", target="ghost@example.com",
            command="holehe --check ghost@example.com",
            captured_at="2026-01-01T10:30:00+00:00", duration=2.75))
        db.add_evidence(conn, _capture(
            investigation, "holehe", target="someone@else.test",
            command="holehe someone@else.test",
            captured_at="2026-01-01T11:00:00+00:00", duration=9.25))

        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / "r.html"), redact=True)).read_text()

        citation_block = html.split("Source Citation", 1)[1].split("</table>", 1)[0]
        assert "2.75s" in citation_block
        assert "9.25s" not in citation_block

    def test_the_json_report_carries_the_citations(self, conn, investigation, tmp_path):
        payload = json.loads(Path(generate_json_report(
            conn, investigation, str(tmp_path / "r.json"))).read_text())

        assert any(c["kind"] == "tool" for cites in payload["source_citations"].values()
                   for c in cites)


class TestSchemaMigration:
    def test_a_database_without_the_version_column_gains_it(self, tmp_path):
        path = tmp_path / "old.db"
        first = db.get_connection(path)
        first.execute("ALTER TABLE evidence DROP COLUMN tool_version")
        first.commit()
        first.close()

        second = db.get_connection(path)
        columns = {row["name"] for row in second.execute("PRAGMA table_info(evidence)")}
        second.close()
        assert "tool_version" in columns

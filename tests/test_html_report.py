"""Tests for HTML/JSON report generation and artifact drill-downs."""

import json
import tempfile
from types import SimpleNamespace
from pathlib import Path

import pytest

from src.reporting.html_report import (
    EXECUTIVE_TEMPLATE,
    HTML_TEMPLATE,
    LEGAL_TEMPLATE,
    TECHNICAL_TEMPLATE,
    _generate_tool_metrics,
    _normalize_tool_source,
    _select_template,
    generate_html_report,
    generate_json_report,
)
from src.storage import database as db

SEED_METADATA = {"platform": "github", "notes": "seed <b>value</b>"}


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def investigation(conn):
    """An investigation covering valid, malformed, null and empty metadata."""
    inv_id = db.create_investigation(conn, title="Report Test")
    username = db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed",
                               confidence=0.95, metadata=json.dumps(SEED_METADATA))
    email = db.add_artifact(conn, inv_id, "email", "ghostuser@example.com", source="holehe",
                            confidence=0.8, metadata="{not valid json", depth=1)
    db.add_artifact(conn, inv_id, "phone", "+14155550123", source="phone_osint",
                    confidence=0.6, metadata=None, depth=1)
    db.add_artifact(conn, inv_id, "domain", "example.com", source="amass",
                    confidence=0.4, metadata="", depth=2)
    db.add_link(conn, inv_id, username, email, "discovered_from", 0.9, "username to email pivot")
    db.add_platform_presence(conn, inv_id, platform_name="GitHub",
                             profile_url="https://github.com/ghostuser", username="ghostuser",
                             display_name="Ghost User", bio="Security researcher",
                             follower_count=42, profile_image_url="https://example.com/a.png",
                             artifact_id=username)
    db.add_platform_presence(conn, inv_id, platform_name="Reddit")
    return inv_id


def render(conn, investigation_id, tmp_path, template_type="standard") -> str:
    path = generate_html_report(conn, investigation_id,
                                str(tmp_path / "report.html"), template_type=template_type)
    return Path(path).read_text()


class TestTemplateSelection:
    def test_standard_and_html_map_to_default_template(self):
        assert _select_template("standard") is HTML_TEMPLATE
        assert _select_template("html") is HTML_TEMPLATE

    def test_named_templates(self):
        assert _select_template("executive") is EXECUTIVE_TEMPLATE
        assert _select_template("technical") is TECHNICAL_TEMPLATE
        assert _select_template("legal") is LEGAL_TEMPLATE

    def test_unknown_falls_back_to_default(self):
        assert _select_template("nonexistent") is HTML_TEMPLATE


class TestDrillDowns:
    def test_artifact_drilldown_shows_metadata_and_links(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Connected Artifacts" in html
        assert "discovered_from" in html
        assert "username to email pivot" in html
        assert "github" in html

    def test_metadata_values_are_escaped(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "&lt;b&gt;value&lt;/b&gt;" in html
        assert "seed <b>value</b>" not in html

    def test_malformed_and_missing_metadata_do_not_break_rendering(self, conn, investigation,
                                                                   tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "{not valid json" in html
        assert "No metadata recorded" in html

    def test_platform_presence_drilldown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Account created" in html
        assert "Ghost User" in html
        assert "https://example.com/a.png" in html

    def test_identity_evidence_drilldown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Complete Evidence Basis" in html

    def test_expand_collapse_controls(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert 'id="expand-all"' in html
        assert 'id="collapse-all"' in html


class TestEmptyInvestigation:
    def test_renders_without_artifacts_or_presences(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Empty")
        html = render(conn, inv_id, tmp_path)
        assert "No artifacts were discovered" in html
        assert "No platform presence recorded" in html


class TestToolMetrics:
    """The infographic groups artifacts by the tool that produced them."""

    @staticmethod
    def _correlation(*identities):
        return SimpleNamespace(identities=list(identities))

    @staticmethod
    def _artifact(artifact_type, source, confidence=0.8):
        return {"artifact_type": artifact_type, "source": source, "confidence": confidence}

    def test_source_normalization_folds_the_three_source_formats(self):
        assert _normalize_tool_source("nmap") == "nmap"
        assert _normalize_tool_source("plugin:MaigretPlugin") == "maigret"
        assert _normalize_tool_source("username_search_github") == "username_search"
        assert _normalize_tool_source("profile_image_steam") == "profile_image"

    def test_seeds_are_not_counted_as_a_tool(self):
        assert _normalize_tool_source("seed") is None
        assert _normalize_tool_source(None) is None

        metrics = _generate_tool_metrics(
            [self._artifact("username", "seed"), self._artifact("subdomain", "amass")],
            self._correlation(),
        )
        assert metrics["attributed"] == 1
        assert metrics["unattributed"] == 1
        assert [t["tool"] for t in metrics["tools"]] == ["amass"]

    def test_tools_ranked_by_yield_with_type_breakdown(self):
        artifacts = [
            self._artifact("username_presence", "sherlock", 0.9),
            self._artifact("username_presence", "sherlock", 0.7),
            self._artifact("username_presence", "plugin:MaigretPlugin"),
            self._artifact("open_port", "nmap"),
            self._artifact("domain_info", "whois"),
        ]
        metrics = _generate_tool_metrics(artifacts, self._correlation())

        assert [t["tool"] for t in metrics["tools"]] == ["sherlock", "maigret", "nmap", "whois"]
        sherlock = metrics["tools"][0]
        assert sherlock["count"] == 2
        assert sherlock["share"] == 40.0
        assert sherlock["avg_confidence"] == 0.8
        assert sherlock["types"] == [{"type": "username_presence", "count": 2}]
        assert metrics["max_count"] == 2
        assert metrics["top_tool"] == "sherlock"

    def test_type_mix_shares_and_colors(self):
        artifacts = [self._artifact("username_presence", "sherlock") for _ in range(3)]
        artifacts.append(self._artifact("open_port", "nmap"))
        metrics = _generate_tool_metrics(artifacts, self._correlation())

        assert [(t["type"], t["share"]) for t in metrics["types"]] == [
            ("username_presence", 75.0),
            ("open_port", 25.0),
        ]
        assert all(t["color"].startswith("#") for t in metrics["types"])

    def test_identities_reached_counts_distinct_profiles(self):
        identities = (
            SimpleNamespace(profile_id="IDENTITY-001",
                            tool_findings=[{"source": "sherlock"}, {"source": "nmap"}]),
            SimpleNamespace(profile_id="IDENTITY-002", tool_findings=[{"source": "sherlock"}]),
        )
        metrics = _generate_tool_metrics(
            [self._artifact("username_presence", "sherlock"), self._artifact("open_port", "nmap")],
            self._correlation(*identities),
        )
        by_tool = {t["tool"]: t for t in metrics["tools"]}
        assert by_tool["sherlock"]["identities"] == 2
        assert by_tool["nmap"]["identities"] == 1

    def test_integrated_tools_without_output_are_reported_as_silent(self):
        metrics = _generate_tool_metrics(
            [self._artifact("open_port", "nmap")], self._correlation()
        )
        assert "nmap" not in metrics["silent_tools"]
        assert "sherlock" in metrics["silent_tools"]
        assert metrics["integrated_count"] >= len(metrics["silent_tools"])

    def test_seed_only_investigation_renders_the_empty_note(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Seeds only")
        db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed", confidence=0.95)
        html = render(conn, inv_id, tmp_path)
        assert "No tool-derived artifacts" in html

    def test_section_renders_bars_and_breakdown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Tool Metrics" in html
        assert "Artifacts per Tool" in html
        assert "tool-chart-bar" in html
        assert "holehe" in html and "amass" in html

    def test_technical_template_includes_the_breakdown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path, template_type="technical")
        assert "Tool Metrics" in html
        assert "Identities reached" in html

    def test_json_report_carries_the_same_metrics(self, conn, investigation, tmp_path):
        path = generate_json_report(conn, investigation, str(tmp_path / "report.json"))
        metrics = json.loads(Path(path).read_text())["tool_metrics"]
        assert {t["tool"] for t in metrics["tools"]} == {"holehe", "phone_osint", "amass"}


class TestJsonReport:
    def test_metadata_stays_raw_and_serializable(self, conn, investigation, tmp_path):
        generate_html_report(conn, investigation, str(tmp_path / "report.html"))
        path = generate_json_report(conn, investigation, str(tmp_path / "report.json"))
        data = json.loads(Path(path).read_text())
        metadata = [a["metadata"] for a in data["artifacts"]]
        assert metadata == [json.dumps(SEED_METADATA), "{not valid json", None, ""]
        assert all("metadata_parsed" not in a for a in data["artifacts"])

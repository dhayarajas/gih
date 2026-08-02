"""Tests for HTML/JSON report generation and artifact drill-downs."""

import json
import tempfile
from pathlib import Path

import pytest

from src.reporting.html_report import (
    EXECUTIVE_TEMPLATE,
    HTML_TEMPLATE,
    LEGAL_TEMPLATE,
    TECHNICAL_TEMPLATE,
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

    def test_validation_status_is_surfaced_per_presence(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Validation")
        db.add_platform_presence(conn, inv_id, platform_name="Steam",
                                 username="ghostuser", is_verified=True)
        db.add_platform_presence(conn, inv_id, platform_name="Pinterest",
                                 username="ghostuser")
        html = render(conn, inv_id, tmp_path)
        assert "Content-validated" in html
        assert "Unvalidated (status only)" in html
        assert "1 of 2 platform presences are content-validated" in html

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


class TestJsonReport:
    def test_metadata_stays_raw_and_serializable(self, conn, investigation, tmp_path):
        generate_html_report(conn, investigation, str(tmp_path / "report.html"))
        path = generate_json_report(conn, investigation, str(tmp_path / "report.json"))
        data = json.loads(Path(path).read_text())
        metadata = [a["metadata"] for a in data["artifacts"]]
        assert metadata == [json.dumps(SEED_METADATA), "{not valid json", None, ""]
        assert all("metadata_parsed" not in a for a in data["artifacts"])

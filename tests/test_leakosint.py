"""Tests for the LeakOSINT integration: client, plugin and report placement."""

import json
import tempfile
from pathlib import Path

import pytest

from src.modules import leakosint
from src.plugins.base import Artifact, PluginConfig, PluginStatus
from src.plugins.builtins.leakosint_plugin import LeakosintPlugin
from src.reporting.html_report import generate_html_report, generate_json_report
from src.reporting.report_data import build_leak_findings
from src.storage import database as db

API_PAYLOAD = {
    "List": {
        "Facebook 2019": {
            "InfoLeak": "533 million accounts, scraped 2019",
            "Data": [
                {"Email": "ghost@example.com", "Phone": "14155550123", "FullName": "Ghost User"},
            ],
        },
        "Collection#1": {
            "InfoLeak": "Credential stuffing corpus",
            "Data": [
                {"Email": "ghost@example.com", "Password": "hunter2"},
                {"Email": "ghost@example.com", "Password": "letmein"},
            ],
        },
        "No results found": {"Data": []},
    }
}


class _Response:
    def __init__(self, payload, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setattr(leakosint, "_plugin_config", dict)
    monkeypatch.setenv("LEAKOSINT_API_TOKEN", "test-token")
    # The client throttles to one request per second; tests must not pay for it.
    monkeypatch.setattr(leakosint, "MIN_REQUEST_INTERVAL", 0.0)


def _stub_post(monkeypatch, response, captured=None):
    def post(url, json=None, timeout=None):
        if captured is not None:
            captured.update({"url": url, "payload": json, "timeout": timeout})
        return response

    monkeypatch.setattr(
        "src.utils.http_client.get_http_session",
        lambda: type("S", (), {"post": staticmethod(post)})(),
    )


class TestClient:
    def test_records_are_flattened_per_database(self, monkeypatch):
        captured: dict = {}
        _stub_post(monkeypatch, _Response(API_PAYLOAD), captured)

        result = leakosint.search("ghost@example.com", limit=50, lang="en")

        assert result.success
        assert captured["payload"]["token"] == "test-token"
        assert captured["payload"]["request"] == "ghost@example.com"
        assert captured["payload"]["limit"] == 50
        # "No results found" is the API's miss marker, not a database.
        assert result.databases == ["Collection#1", "Facebook 2019"]
        assert len(result.records) == 3
        # Rows sharing an email stay distinguishable, so none is deduplicated away.
        assert {r.summary for r in result.records} == {
            "ghost@example.com / 14155550123 / Ghost User",
            "ghost@example.com / hunter2",
            "ghost@example.com / letmein",
        }

    def test_missing_token_is_not_an_error(self, monkeypatch):
        monkeypatch.delenv("LEAKOSINT_API_TOKEN", raising=False)
        result = leakosint.search("ghost@example.com")
        assert result.success is False
        assert "not configured" in result.error
        assert leakosint.is_configured() is False

    @pytest.mark.parametrize(
        "response",
        [
            _Response({"Error code": "Invalid token"}),
            _Response({"error": "502"}),
            _Response({"List": {}}, status_code=500),
            _Response(None, status_code=200, text="<html>"),
        ],
    )
    def test_api_failures_degrade_quietly(self, monkeypatch, response):
        _stub_post(monkeypatch, response)
        result = leakosint.search("ghost@example.com")
        assert result.success is False
        assert result.records == []
        assert result.error

    def test_transport_failure_degrades_quietly(self, monkeypatch):
        def boom():
            raise RuntimeError("connection reset")

        monkeypatch.setattr("src.utils.http_client.get_http_session", boom)
        result = leakosint.search("ghost@example.com")
        assert result.success is False
        assert "connection reset" in result.error


class TestPlugin:
    def test_records_become_artifacts(self, monkeypatch):
        _stub_post(monkeypatch, _Response(API_PAYLOAD))
        plugin = LeakosintPlugin(PluginConfig())

        result = plugin.execute(Artifact(type="email", value="ghost@example.com", source="seed"))

        assert result.status == PluginStatus.SUCCESS
        assert len(result.artifacts) == 3
        assert {a.type for a in result.artifacts} == {"leak_record"}
        assert len({a.value for a in result.artifacts}) == 3
        facebook = next(a for a in result.artifacts if a.metadata["database"] == "Facebook 2019")
        assert facebook.value.startswith("Facebook 2019: ghost@example.com")
        assert facebook.metadata["fields"]["FullName"] == "Ghost User"
        assert result.metadata["records_found"] == 3

    def test_unavailable_without_a_token(self, monkeypatch):
        monkeypatch.delenv("LEAKOSINT_API_TOKEN", raising=False)
        plugin = LeakosintPlugin(PluginConfig())
        assert plugin.is_available() is False
        assert plugin.execute(
            Artifact(type="email", value="ghost@example.com", source="seed")
        ).status == PluginStatus.SKIPPED

    def test_api_error_fails_without_raising(self, monkeypatch):
        _stub_post(monkeypatch, _Response({"Error code": "Not enough money"}))
        result = LeakosintPlugin(PluginConfig()).execute(
            Artifact(type="email", value="ghost@example.com", source="seed")
        )
        assert result.status == PluginStatus.FAILURE
        assert result.artifacts == []

    def test_supported_selectors(self):
        assert set(LeakosintPlugin().get_supported_artifact_types()) == {
            "email", "phone", "username", "fullname",
        }


class TestReport:
    @pytest.fixture
    def conn(self):
        c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
        yield c
        c.close()

    @pytest.fixture
    def investigation(self, conn):
        inv_id = db.create_investigation(conn, title="Leak Test")
        db.add_artifact(conn, inv_id, "email", "ghost@example.com", source="seed", confidence=0.95)
        for database, fields in (
            ("Collection#1", {"Email": "ghost@example.com", "Password": "hunter2"}),
            ("Collection#1", {"Email": "ghost@example.com", "Password": "letmein"}),
            ("Facebook 2019", {"Email": "ghost@example.com", "FullName": "Ghost User"}),
        ):
            db.add_artifact(
                conn, inv_id, "leak_record",
                f"{database}: {' / '.join(str(v) for v in fields.values())}",
                source="plugin:LeakosintPlugin", confidence=0.9, depth=1,
                metadata=json.dumps({
                    "database": database,
                    "info": "Credential corpus",
                    "query": "ghost@example.com",
                    "query_type": "email",
                    "fields": fields,
                }),
            )
        return inv_id

    def test_findings_group_by_database(self, conn, investigation):
        artifacts = db.get_artifacts(conn, investigation)
        findings = build_leak_findings(artifacts)
        assert findings["record_count"] == 3
        assert findings["database_count"] == 2
        # Largest database first, and identity fields ahead of the rest.
        assert findings["databases"][0]["database"] == "Collection#1"
        assert [f["key"] for f in findings["databases"][0]["records"][0]["fields"]] == ["Email", "Password"]
        assert findings["queries"] == ["ghost@example.com"]

    def test_redaction_masks_record_fields(self, conn, investigation):
        artifacts = db.get_artifacts(conn, investigation)
        findings = build_leak_findings(artifacts, redact=True)
        values = {f["value"] for g in findings["databases"] for r in g["records"] for f in r["fields"]}
        assert values == {"[REDACTED]"}

    def test_redacted_report_hides_leaked_values_everywhere(self, conn, investigation, tmp_path):
        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / "r.html"), redact=True
        )).read_text()
        # Not in the section, the artifact table or the metadata drill-down.
        assert "hunter2" not in html
        assert "letmein" not in html
        assert "Collection#1: [REDACTED]" in html

    def test_standard_report_leads_with_breach_records(self, conn, investigation, tmp_path):
        path = generate_html_report(conn, investigation, str(tmp_path / "r.html"))
        html = Path(path).read_text()
        assert "1. Breach Records (3)" in html
        assert "hunter2" in html
        # Ahead of every other numbered section.
        assert html.index("Breach Records") < html.index("Identity Profiles")

    def test_section_is_absent_without_records(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="No leaks")
        db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed", confidence=0.9)
        html = Path(generate_html_report(conn, inv_id, str(tmp_path / "r.html"))).read_text()
        assert "Breach Records" not in html

    @pytest.mark.parametrize("template", ["executive", "technical", "legal"])
    def test_other_templates_report_the_records(self, conn, investigation, tmp_path, template):
        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / f"{template}.html"), template_type=template
        )).read_text()
        assert "Breach Records" in html

    def test_json_report_carries_the_findings(self, conn, investigation, tmp_path):
        data = json.loads(Path(
            generate_json_report(conn, investigation, str(tmp_path / "r.json"))
        ).read_text())
        assert data["summary"]["leak_record_count"] == 3
        assert data["leak_findings"]["database_count"] == 2

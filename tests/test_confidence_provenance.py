"""Tests for the signals reported behind confidence and risk scores."""

import json
import tempfile
from pathlib import Path

import networkx as nx
import pytest

from src.correlation.linker import (
    _compute_confidence,
    correlate_identities,
    explain_confidence,
)
from src.correlation.scorer import (
    compute_identity_risk_score,
    explain_identity_risk_score,
)
from src.reporting.html_report import generate_html_report, generate_json_report
from src.storage import database as db


def _linked_component() -> tuple[nx.Graph, set]:
    G = nx.Graph()
    G.add_node("a", artifact_type="username")
    G.add_node("b", artifact_type="email")
    G.add_node("c", artifact_type="phone")
    G.add_edge("a", "b", confidence=0.9)
    G.add_edge("b", "c", confidence=0.7)
    return G, {"a", "b", "c"}


class TestIdentityConfidenceProvenance:
    def test_the_explanation_reproduces_the_score(self):
        G, component = _linked_component()
        explanation = explain_confidence(G, component)

        assert explanation["score"] == _compute_confidence(G, component)
        total = sum(s["contribution"] for s in explanation["signals"])
        assert round(total, 3) == explanation["score"]

    def test_each_signal_reports_its_measurement_and_weight(self):
        G, component = _linked_component()
        signals = {s["name"]: s for s in explain_confidence(G, component)["signals"]}

        assert signals["Artifact type diversity"]["value"] == 0.75   # 3 of 4 types
        assert signals["Artifact type diversity"]["weight"] == 0.4
        assert signals["Cross-type links"]["value"] == 1.0           # both edges cross
        assert signals["Mean link confidence"]["value"] == 0.8       # (0.9 + 0.7) / 2
        assert "3 of 4 identity types" in signals["Artifact type diversity"]["detail"]

    def test_a_lone_artifact_is_explained_rather_than_scored(self):
        G = nx.Graph()
        G.add_node("a", artifact_type="username")
        explanation = explain_confidence(G, {"a"})

        assert explanation["score"] == 0.3
        assert explanation["signals"] == []
        assert "single unlinked artifact" in explanation["note"]


class TestRiskProvenance:
    def test_the_breakdown_reproduces_the_score(self):
        indicators = ["voip_number", "disposable_email_domain"]

        explanation = explain_identity_risk_score(indicators)
        assert explanation["score"] == compute_identity_risk_score(indicators)
        assert sum(s["weight"] for s in explanation["signals"]) == explanation["raw_total"]

    def test_dynamic_breach_indicators_report_how_they_scale(self):
        explanation = explain_identity_risk_score(["found_in_4_breaches"])
        signal = explanation["signals"][0]

        assert signal["weight"] == 0.2  # 4 × 0.05
        assert "4 breach(es)" in signal["detail"]

    def test_an_unknown_indicator_is_named_as_using_the_default_weight(self):
        signal = explain_identity_risk_score(["something_new"])["signals"][0]

        assert signal["weight"] == 0.1
        assert "unrecognised" in signal["detail"]

    def test_the_cap_is_reported_instead_of_silently_swallowing_evidence(self):
        explanation = explain_identity_risk_score([
            "disposable_number_service", "disposable_email_domain",
            "possible_stock_photo", "voip_number", "invalid_number",
        ])

        assert explanation["score"] == 1.0
        assert explanation["capped"] is True
        assert explanation["raw_total"] > 1.0

    def test_no_indicators_yields_no_signals(self):
        assert explain_identity_risk_score([]) == {
            "score": 0.0, "signals": [], "capped": False
        }


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def investigation(conn):
    inv_id = db.create_investigation(conn, title="Provenance")
    username = db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed",
                               confidence=0.95)
    email = db.add_artifact(conn, inv_id, "email", "ghost@mailinator.com", source="holehe",
                            confidence=0.8, depth=1,
                            metadata=json.dumps({"risk_indicators": ["disposable_email_domain"]}))
    db.add_link(conn, inv_id, username, email, "exact_match", 0.95, "same local part")
    return inv_id


class TestReportRendering:
    def test_the_identity_score_is_shown_with_its_signals(self, conn, investigation, tmp_path):
        html = Path(generate_html_report(conn, investigation, str(tmp_path / "r.html"))).read_text()

        assert "Why this score?" in html
        assert "Artifact type diversity" in html
        assert "Mean link confidence" in html

    def test_each_artifact_states_where_its_number_came_from(
        self, conn, investigation, tmp_path
    ):
        html = Path(generate_html_report(conn, investigation, str(tmp_path / "r.html"))).read_text()

        assert "Confidence Basis" in html
        assert "Assigned at discovery" in html
        assert "reported by holehe" in html
        assert "base weight 1.0 for this link type" in html  # exact_match

    def test_the_signals_survive_into_the_json_report(self, conn, investigation, tmp_path):
        payload = json.loads(
            Path(generate_json_report(conn, investigation, str(tmp_path / "r.json"))).read_text()
        )

        identity = payload["identities"][0]
        assert identity["confidence_signals"]
        assert {"name", "weight", "value", "contribution", "detail"} <= set(
            identity["confidence_signals"][0]
        )

    def test_correlation_attaches_the_signals_to_each_profile(self, conn, investigation):
        result = correlate_identities(conn, investigation)

        identity = result.identities[0]
        assert identity.confidence_signals
        assert round(
            sum(s["contribution"] for s in identity.confidence_signals), 3
        ) == identity.confidence

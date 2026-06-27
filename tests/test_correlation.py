"""Tests for identity correlation and confidence scoring."""

import tempfile
from pathlib import Path

import pytest

from src.correlation.linker import build_identity_graph, correlate_identities
from src.correlation.scorer import (
    compute_link_confidence,
    compute_identity_risk_score,
    classify_risk_level,
)
from src.storage import database as db


@pytest.fixture
def conn():
    """Create a test database."""
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


class TestConfidenceScoring:
    """Test link confidence scoring."""

    def test_exact_match_highest(self):
        score = compute_link_confidence("exact_match")
        assert score == 1.0

    def test_registered_with_high(self):
        score = compute_link_confidence("registered_with")
        assert score == 0.9

    def test_unknown_link_type_low(self):
        score = compute_link_confidence("some_unknown_type")
        assert score == 0.3

    def test_old_data_decay(self):
        fresh = compute_link_confidence("exact_match", data_age_days=30)
        old = compute_link_confidence("exact_match", data_age_days=800)
        assert old < fresh

    def test_source_reliability_multiplier(self):
        high_rel = compute_link_confidence("discovered_from", source_reliability=1.0)
        low_rel = compute_link_confidence("discovered_from", source_reliability=0.5)
        assert low_rel < high_rel


class TestRiskScoring:
    """Test identity risk scoring."""

    def test_no_indicators_zero_risk(self):
        score = compute_identity_risk_score([])
        assert score == 0.0

    def test_disposable_email_medium_risk(self):
        score = compute_identity_risk_score(["disposable_email_domain"])
        assert 0.2 <= score <= 0.5

    def test_multiple_indicators_higher_risk(self):
        single = compute_identity_risk_score(["voip_number"])
        multiple = compute_identity_risk_score(["voip_number", "disposable_email_domain", "disposable_number_service"])
        assert multiple > single

    def test_risk_capped_at_one(self):
        # Many indicators should still cap at 1.0
        indicators = ["disposable_email_domain", "voip_number", "disposable_number_service",
                      "privacy_email_provider", "possible_stock_photo"]
        score = compute_identity_risk_score(indicators)
        assert score <= 1.0

    def test_breach_indicator_parsing(self):
        score = compute_identity_risk_score(["found_in_5_breaches"])
        assert score > 0.0


class TestRiskLevelClassification:
    """Test risk level classification."""

    def test_critical(self):
        assert classify_risk_level(0.9) == "critical"

    def test_high(self):
        assert classify_risk_level(0.7) == "high"

    def test_medium(self):
        assert classify_risk_level(0.5) == "medium"

    def test_low(self):
        assert classify_risk_level(0.3) == "low"

    def test_minimal(self):
        assert classify_risk_level(0.1) == "minimal"


class TestIdentityCorrelation:
    """Test graph-based identity correlation."""

    def test_empty_investigation(self, conn):
        inv_id = db.create_investigation(conn)
        result = correlate_identities(conn, inv_id)
        assert result.graph_nodes == 0
        assert len(result.identities) == 0

    def test_single_artifact_one_identity(self, conn):
        inv_id = db.create_investigation(conn)
        db.add_artifact(conn, inv_id, "email", "test@example.com")
        result = correlate_identities(conn, inv_id)
        assert len(result.identities) == 1
        assert result.identities[0].emails == ["test@example.com"]

    def test_linked_artifacts_same_identity(self, conn):
        inv_id = db.create_investigation(conn)
        art1 = db.add_artifact(conn, inv_id, "email", "test@example.com")
        art2 = db.add_artifact(conn, inv_id, "username", "testuser")
        db.add_link(conn, inv_id, art1, art2, "discovered_from")
        result = correlate_identities(conn, inv_id)
        assert len(result.identities) == 1
        assert "test@example.com" in result.identities[0].emails
        assert "testuser" in result.identities[0].usernames

    def test_unlinked_artifacts_separate_identities(self, conn):
        inv_id = db.create_investigation(conn)
        db.add_artifact(conn, inv_id, "email", "a@example.com")
        db.add_artifact(conn, inv_id, "email", "b@example.com")
        result = correlate_identities(conn, inv_id)
        assert len(result.identities) == 2

    def test_confidence_increases_with_cross_type_links(self, conn):
        inv_id = db.create_investigation(conn)
        art1 = db.add_artifact(conn, inv_id, "email", "test@example.com")
        art2 = db.add_artifact(conn, inv_id, "username", "testuser")
        art3 = db.add_artifact(conn, inv_id, "phone", "+15551234567")
        db.add_link(conn, inv_id, art1, art2, "discovered_from", confidence=0.9)
        db.add_link(conn, inv_id, art1, art3, "registered_with", confidence=0.8)
        result = correlate_identities(conn, inv_id)
        assert len(result.identities) == 1
        assert result.identities[0].confidence > 0.3

    def test_build_identity_graph(self, conn):
        inv_id = db.create_investigation(conn)
        art1 = db.add_artifact(conn, inv_id, "email", "test@example.com")
        art2 = db.add_artifact(conn, inv_id, "username", "testuser")
        db.add_link(conn, inv_id, art1, art2, "discovered_from")
        G = build_identity_graph(conn, inv_id)
        assert G.number_of_nodes() == 2
        assert G.number_of_edges() == 1

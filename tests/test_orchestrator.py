"""Tests for investigation orchestrator."""

import tempfile
from pathlib import Path

import pytest

from src.orchestrator import run_investigation, InvestigationConfig
from src.storage import database as db


@pytest.fixture
def conn():
    """Create a test database."""
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


class TestInvestigationOrchestrator:
    """Test the BFS investigation pipeline."""

    def test_phone_investigation(self, conn):
        """Phone seed should create investigation with artifacts."""
        config = InvestigationConfig(
            max_depth=0,
            check_breaches=False,
            search_usernames=False,
        )
        result = run_investigation(
            conn,
            seeds=[{"type": "phone", "value": "+14155552671"}],
            config=config,
        )
        assert result.investigation_id.startswith("INV-")
        assert result.total_artifacts >= 1

    def test_email_investigation_no_network(self, conn):
        """Email investigation with network calls disabled."""
        config = InvestigationConfig(
            max_depth=0,
            check_breaches=False,
            search_usernames=False,
        )
        result = run_investigation(
            conn,
            seeds=[{"type": "email", "value": "test@mailinator.com"}],
            config=config,
        )
        assert result.investigation_id.startswith("INV-")
        assert result.total_artifacts >= 1

    def test_multiple_seeds(self, conn):
        """Multiple seed artifacts should all be processed."""
        config = InvestigationConfig(
            max_depth=0,
            check_breaches=False,
            search_usernames=False,
        )
        result = run_investigation(
            conn,
            seeds=[
                {"type": "phone", "value": "+14155552671"},
                {"type": "email", "value": "test@example.com"},
            ],
            config=config,
        )
        assert result.total_artifacts >= 2

    def test_depth_limit_respected(self, conn):
        """Investigation should not exceed max_depth."""
        config = InvestigationConfig(
            max_depth=1,
            check_breaches=False,
            search_usernames=False,
        )
        result = run_investigation(
            conn,
            seeds=[{"type": "email", "value": "test@mailinator.com"}],
            config=config,
        )
        # Verify all artifacts are within depth limit
        artifacts = db.get_artifacts(conn, result.investigation_id)
        for art in artifacts:
            assert art["depth"] <= 1

    def test_investigation_marked_completed(self, conn):
        """Investigation status should be 'completed' after run."""
        config = InvestigationConfig(max_depth=0, check_breaches=False, search_usernames=False)
        result = run_investigation(
            conn,
            seeds=[{"type": "phone", "value": "+14155552671"}],
            config=config,
        )
        inv = db.get_investigation(conn, result.investigation_id)
        assert inv["status"] == "completed"

    def test_duplicate_seeds_handled(self, conn):
        """Duplicate seed values should not create duplicate artifacts."""
        config = InvestigationConfig(max_depth=0, check_breaches=False, search_usernames=False)
        result = run_investigation(
            conn,
            seeds=[
                {"type": "email", "value": "same@example.com"},
                {"type": "email", "value": "same@example.com"},
            ],
            config=config,
        )
        artifacts = db.get_artifacts(conn, result.investigation_id)
        email_artifacts = [a for a in artifacts if a["artifact_type"] == "email"]
        assert len(email_artifacts) == 1

    def test_custom_title(self, conn):
        """Custom investigation title should be stored."""
        config = InvestigationConfig(max_depth=0, check_breaches=False, search_usernames=False)
        result = run_investigation(
            conn,
            seeds=[{"type": "phone", "value": "+14155552671"}],
            config=config,
            title="My Custom Investigation",
        )
        inv = db.get_investigation(conn, result.investigation_id)
        assert inv["title"] == "My Custom Investigation"

"""Tests for SQLite storage layer."""

import tempfile
from pathlib import Path

import pytest

from src.storage import database as db


@pytest.fixture
def conn():
    """Create an in-memory database connection for testing."""
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


class TestInvestigations:
    """Test investigation CRUD operations."""

    def test_create_investigation(self, conn):
        inv_id = db.create_investigation(conn, title="Test Investigation")
        assert inv_id.startswith("INV-")

    def test_get_investigation(self, conn):
        inv_id = db.create_investigation(conn, title="Test", description="A test")
        inv = db.get_investigation(conn, inv_id)
        assert inv is not None
        assert inv["title"] == "Test"
        assert inv["description"] == "A test"
        assert inv["status"] == "in_progress"

    def test_complete_investigation(self, conn):
        inv_id = db.create_investigation(conn)
        db.complete_investigation(conn, inv_id)
        inv = db.get_investigation(conn, inv_id)
        assert inv["status"] == "completed"

    def test_list_investigations(self, conn):
        db.create_investigation(conn, title="First")
        db.create_investigation(conn, title="Second")
        investigations = db.list_investigations(conn)
        assert len(investigations) == 2

    def test_nonexistent_investigation(self, conn):
        inv = db.get_investigation(conn, "INV-nonexist")
        assert inv is None


class TestArtifacts:
    """Test artifact operations."""

    def test_add_artifact(self, conn):
        inv_id = db.create_investigation(conn)
        art_id = db.add_artifact(conn, inv_id, "email", "test@example.com", source="seed")
        assert art_id.startswith("ART-")

    def test_get_artifacts(self, conn):
        inv_id = db.create_investigation(conn)
        db.add_artifact(conn, inv_id, "phone", "+15551234567")
        db.add_artifact(conn, inv_id, "email", "test@example.com")
        artifacts = db.get_artifacts(conn, inv_id)
        assert len(artifacts) == 2

    def test_duplicate_artifact_returns_existing(self, conn):
        inv_id = db.create_investigation(conn)
        id1 = db.add_artifact(conn, inv_id, "email", "same@example.com")
        id2 = db.add_artifact(conn, inv_id, "email", "same@example.com")
        assert id1 == id2

    def test_artifact_with_metadata(self, conn):
        inv_id = db.create_investigation(conn)
        db.add_artifact(
            conn, inv_id, "phone", "+15551234567",
            metadata='{"carrier": "AT&T"}',
            confidence=0.9,
        )
        artifacts = db.get_artifacts(conn, inv_id)
        assert artifacts[0]["metadata"] == '{"carrier": "AT&T"}'
        assert artifacts[0]["confidence"] == 0.9


class TestLinks:
    """Test link operations."""

    def test_add_link(self, conn):
        inv_id = db.create_investigation(conn)
        art1 = db.add_artifact(conn, inv_id, "email", "a@b.com")
        art2 = db.add_artifact(conn, inv_id, "username", "user_a")
        link_id = db.add_link(conn, inv_id, art1, art2, "discovered_from")
        assert link_id.startswith("LNK-")

    def test_get_links(self, conn):
        inv_id = db.create_investigation(conn)
        art1 = db.add_artifact(conn, inv_id, "email", "a@b.com")
        art2 = db.add_artifact(conn, inv_id, "username", "user_a")
        db.add_link(conn, inv_id, art1, art2, "discovered_from")
        links = db.get_links(conn, inv_id)
        assert len(links) == 1
        assert links[0]["link_type"] == "discovered_from"

    def test_duplicate_link_returns_existing(self, conn):
        inv_id = db.create_investigation(conn)
        art1 = db.add_artifact(conn, inv_id, "email", "a@b.com")
        art2 = db.add_artifact(conn, inv_id, "username", "user_a")
        id1 = db.add_link(conn, inv_id, art1, art2, "discovered_from")
        id2 = db.add_link(conn, inv_id, art1, art2, "discovered_from")
        assert id1 == id2


class TestPlatformPresence:
    """Test platform presence operations."""

    def test_add_presence(self, conn):
        inv_id = db.create_investigation(conn)
        prs_id = db.add_platform_presence(
            conn, inv_id, "GitHub",
            username="testuser",
            profile_url="https://github.com/testuser",
        )
        assert prs_id.startswith("PRS-")

    def test_get_presences(self, conn):
        inv_id = db.create_investigation(conn)
        db.add_platform_presence(conn, inv_id, "GitHub", username="user1")
        db.add_platform_presence(conn, inv_id, "Reddit", username="user1")
        presences = db.get_platform_presences(conn, inv_id)
        assert len(presences) == 2

"""Tests for investigation orchestrator."""

import tempfile
from pathlib import Path

import pytest

import src.orchestrator as orchestrator
from src.orchestrator import (
    EXPANDABLE_ARTIFACT_TYPES,
    TOOL_ONLY_ARTIFACT_TYPES,
    ArtifactProcessResult,
    InvestigationConfig,
    run_investigation,
)
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


class TestBoundedProcessing:
    """Tests for the artifact budget, re-queue restriction, and dedup."""

    @staticmethod
    def _stub_processor(discovered_per_artifact):
        """Build a _process_artifact stub returning fixed discoveries."""
        def _fake(inv_id, artifact, config, plugin_manager=None):
            res = ArtifactProcessResult(artifact=artifact)
            if artifact["depth"] == 0:
                res.discovered = list(discovered_per_artifact)
            return res
        return _fake

    def test_artifact_budget_caps_total(self, conn, monkeypatch):
        """max_total_artifacts should cap the number of enqueued artifacts."""
        discovered = [
            {"type": "username", "value": f"user{i}", "source": "test"}
            for i in range(50)
        ]
        monkeypatch.setattr(orchestrator, "_process_artifact", self._stub_processor(discovered))

        config = InvestigationConfig(
            max_depth=3,
            check_breaches=False,
            search_usernames=False,
            check_external_tools=False,
            max_total_artifacts=10,
        )
        result = run_investigation(
            conn,
            seeds=[{"type": "username", "value": "seed"}],
            config=config,
        )
        # seed counts toward the budget, so total never exceeds the cap.
        assert result.total_artifacts <= 10

    def test_only_expandable_types_requeued(self, conn, monkeypatch):
        """Leaf artifact types are stored but never re-queued for expansion."""
        # A leaf type (risk_indicator) plus an expandable type (username).
        discovered = [
            {"type": "risk_indicator", "value": "spam", "source": "test"},
            {"type": "username", "value": "child", "source": "test"},
        ]
        calls = []

        def _fake(inv_id, artifact, config, plugin_manager=None):
            calls.append((artifact["type"], artifact["value"]))
            res = ArtifactProcessResult(artifact=artifact)
            if artifact["depth"] == 0:
                res.discovered = list(discovered)
            return res

        monkeypatch.setattr(orchestrator, "_process_artifact", _fake)

        config = InvestigationConfig(
            max_depth=3,
            check_breaches=False,
            search_usernames=False,
            check_external_tools=False,
        )
        run_investigation(conn, seeds=[{"type": "username", "value": "seed"}], config=config)

        processed_types = {c[0] for c in calls}
        # The expandable child was processed; the leaf risk_indicator was not.
        assert ("username", "child") in calls
        assert "risk_indicator" not in processed_types

    def test_expandable_types_constant(self):
        """Sanity check on the re-queue allowlist."""
        assert "username" in EXPANDABLE_ARTIFACT_TYPES
        assert "risk_indicator" not in EXPANDABLE_ARTIFACT_TYPES
        # platform_presence must stay expandable so the profile_image plugin runs.
        assert "platform_presence" in EXPANDABLE_ARTIFACT_TYPES

    def test_tool_only_types_are_expandable(self):
        """Types with no native module are still expanded by the tools."""
        assert TOOL_ONLY_ARTIFACT_TYPES <= EXPANDABLE_ARTIFACT_TYPES

    def test_budget_still_persists_metadata_and_presence(self, conn, monkeypatch):
        """Hitting the budget must not drop already-collected writes.

        Every processed artifact's metadata + platform presences should be
        persisted even for results iterated after the artifact budget is
        exhausted; only new-artifact expansion is suppressed.
        """
        def _fake(inv_id, artifact, config, plugin_manager=None):
            res = ArtifactProcessResult(artifact=artifact)
            res.source_metadata = f"meta:{artifact['value']}"
            res.platform_presences = [{"platform_name": f"P-{artifact['value']}"}]
            if artifact["depth"] == 0:
                res.discovered = [
                    {"type": "username", "value": f"child{i}", "source": "test"}
                    for i in range(20)
                ]
            return res

        monkeypatch.setattr(orchestrator, "_process_artifact", _fake)

        config = InvestigationConfig(
            max_depth=3,
            check_breaches=False,
            search_usernames=False,
            check_external_tools=False,
            max_total_artifacts=5,
        )
        # Multiple seeds so several results are iterated in the same level; the
        # budget is exhausted partway through their discovered expansion.
        result = run_investigation(
            conn,
            seeds=[
                {"type": "username", "value": "seedA"},
                {"type": "username", "value": "seedB"},
                {"type": "username", "value": "seedC"},
            ],
            config=config,
        )

        presences = db.get_platform_presences(conn, result.investigation_id)
        seed_presences = {
            p["platform_name"] for p in presences
            if p["platform_name"] in {"P-seedA", "P-seedB", "P-seedC"}
        }
        # All three seeds' presences persisted despite the budget being hit.
        assert seed_presences == {"P-seedA", "P-seedB", "P-seedC"}

    def test_dedup_preserved_across_levels(self, conn, monkeypatch):
        """The same discovered value should be stored only once."""
        discovered = [
            {"type": "username", "value": "dup", "source": "test"},
            {"type": "username", "value": "dup", "source": "test"},
        ]
        monkeypatch.setattr(orchestrator, "_process_artifact", self._stub_processor(discovered))

        config = InvestigationConfig(
            max_depth=2,
            check_breaches=False,
            search_usernames=False,
            check_external_tools=False,
        )
        result = run_investigation(
            conn,
            seeds=[{"type": "username", "value": "seed"}],
            config=config,
        )
        artifacts = db.get_artifacts(conn, result.investigation_id)
        dup_artifacts = [a for a in artifacts if a["value"] == "dup"]
        assert len(dup_artifacts) == 1


class TestArtifactDispatch:
    """_process_artifact routing of types without a native OSINT module."""

    def test_tool_only_type_dispatches_without_warning(self, caplog, monkeypatch):
        """A domain has no module, but it is expected -- not 'Unknown'."""
        monkeypatch.setattr(orchestrator, "_process_external_tools", lambda *a, **k: [])
        config = InvestigationConfig(check_external_tools=True)

        with caplog.at_level("WARNING"):
            result = orchestrator._process_artifact(
                "INV-1", {"type": "domain", "value": "example.com"}, config
            )

        assert result.discovered == []
        assert "Unknown artifact type" not in caplog.text

    def test_unknown_type_still_warns(self, caplog, monkeypatch):
        monkeypatch.setattr(orchestrator, "_process_external_tools", lambda *a, **k: [])
        config = InvestigationConfig(check_external_tools=True)

        with caplog.at_level("WARNING"):
            orchestrator._process_artifact(
                "INV-1", {"type": "banana", "value": "x"}, config
            )

        assert "Unknown artifact type: banana" in caplog.text

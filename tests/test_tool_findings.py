"""Tests for surfacing external-tool findings under correlated identities."""

import json
import tempfile
from pathlib import Path

import pytest

from src.correlation.linker import correlate_identities
from src.orchestrator import ArtifactProcessResult, _normalize_tool_artifacts
from src.storage import database as db


@pytest.fixture
def conn():
    connection = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield connection
    connection.close()


class TestNormalizeToolArtifacts:
    def test_extra_fields_are_folded_into_metadata(self):
        result = ArtifactProcessResult(artifact={})
        normalized = _normalize_tool_artifacts([{
            "type": "open_port",
            "value": "1.2.3.4:22",
            "source": "nmap",
            "confidence": 0.9,
            "service": "ssh",
            "protocol": "tcp",
        }], result)

        assert normalized[0]["type"] == "open_port"
        assert json.loads(normalized[0]["metadata"]) == {"service": "ssh", "protocol": "tcp"}
        assert normalized[0]["link_type"] == "found_by_nmap"

    def test_username_presence_becomes_a_platform_presence_row(self):
        result = ArtifactProcessResult(artifact={})
        normalized = _normalize_tool_artifacts([{
            "type": "username_presence",
            "value": "torvalds",
            "platform": "GitHub",
            "profile_url": "https://github.com/torvalds",
            "source": "sherlock",
            "confidence": 0.8,
        }], result)

        assert result.platform_presences == [{
            "platform_name": "GitHub",
            "profile_url": "https://github.com/torvalds",
            "username": "torvalds",
            "display_name": None,
            "bio": None,
            "follower_count": None,
            "profile_image_url": None,
        }]
        # The artifact is keyed by profile URL so hits on different platforms
        # are not collapsed into a single artifact.
        assert normalized[0]["value"] == "https://github.com/torvalds"

    def test_same_profile_reported_by_two_tools_yields_one_presence(self):
        result = ArtifactProcessResult(artifact={})
        raw = {
            "type": "username_presence",
            "value": "torvalds",
            "platform": "GitHub",
            "profile_url": "https://github.com/torvalds",
            "confidence": 0.8,
        }
        _normalize_tool_artifacts(
            [dict(raw, source="sherlock"), dict(raw, source="maigret")], result
        )
        assert len(result.platform_presences) == 1


class TestToolFindingCorrelation:
    def test_findings_attach_to_the_identity_they_came_from(self, conn):
        inv_id = db.create_investigation(conn)
        email_id = db.add_artifact(conn, inv_id, "email", "target@example.com", source="seed")
        port_id = db.add_artifact(
            conn, inv_id, "open_port", "1.2.3.4:22", source="nmap", confidence=0.9,
            metadata=json.dumps({"service": "ssh"}),
        )
        db.add_link(conn, inv_id, email_id, port_id, "found_by_nmap", 0.9)

        result = correlate_identities(conn, inv_id)
        identity = next(i for i in result.identities if "target@example.com" in i.emails)

        assert identity.tool_findings["open_port"] == [{
            "value": "1.2.3.4:22",
            "source": "nmap",
            "confidence": 0.9,
            "details": {"service": "ssh"},
        }]
        assert identity.tool_finding_sections[0]["label"] == "Open Ports"
        assert identity.to_dict()["tool_findings"]["open_port"][0]["value"] == "1.2.3.4:22"

    def test_findings_are_followed_through_intermediate_artifacts(self, conn):
        inv_id = db.create_investigation(conn)
        email_id = db.add_artifact(conn, inv_id, "email", "target@example.com", source="seed")
        domain_id = db.add_artifact(conn, inv_id, "domain", "example.com", source="email_domain")
        dns_id = db.add_artifact(conn, inv_id, "dns_a", "1.2.3.4", source="dig", confidence=0.95)
        db.add_link(conn, inv_id, email_id, domain_id, "discovered_from", 0.9)
        db.add_link(conn, inv_id, domain_id, dns_id, "found_by_dig", 0.95)

        result = correlate_identities(conn, inv_id)
        identity = next(i for i in result.identities if "target@example.com" in i.emails)

        assert [f["value"] for f in identity.tool_findings["dns_a"]] == ["1.2.3.4"]

    def test_non_tool_artifacts_are_not_reported_as_findings(self, conn):
        inv_id = db.create_investigation(conn)
        email_id = db.add_artifact(conn, inv_id, "email", "target@example.com", source="seed")
        other_id = db.add_artifact(conn, inv_id, "username", "target", source="email_local_part")
        db.add_link(conn, inv_id, email_id, other_id, "discovered_from", 0.9)

        result = correlate_identities(conn, inv_id)
        identity = next(i for i in result.identities if "target@example.com" in i.emails)

        assert identity.tool_findings == {}

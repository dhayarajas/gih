"""Tests for external OSINT tool parsers and their correlation into identity profiles."""

import tempfile
from pathlib import Path

import pytest

from src.correlation.linker import correlate_identities
from src.modules.external_tools import (
    ANALYSIS_METHODS,
    _parse_found_accounts,
    _parse_subdomains,
    get_tool_coverage,
    get_tool_integrations,
)
from src.storage import database as db

SHERLOCK_OUTPUT = """[*] Checking username octocat on:

[+] 7Cups: https://www.7cups.com/@octocat
[+] GitHub: https://github.com/octocat
[+] GitHub: https://github.com/octocat
[-] Facebook: Not Found!
"""

SUBFINDER_OUTPUT = """accelerator.github.com
f.cloud.github.com
github.com
https://example.org/redirect?url=%2Fdocs.github.com
"""


class TestAccountParsing:
    """Parsing of sherlock/maigret '[+] Platform: url' output."""

    def test_extracts_found_accounts(self):
        artifacts = _parse_found_accounts(SHERLOCK_OUTPUT, "octocat", "sherlock", 0.8)
        values = [a["value"] for a in artifacts]

        assert values == ["https://www.7cups.com/@octocat", "https://github.com/octocat"]
        assert all(a["type"] == "username_presence" for a in artifacts)
        assert all(a["source"] == "sherlock" for a in artifacts)
        assert artifacts[1]["platform"] == "GitHub"
        assert artifacts[1]["username"] == "octocat"

    def test_ignores_not_found_lines(self):
        artifacts = _parse_found_accounts("[-] Facebook: Not Found!", "octocat", "sherlock", 0.8)
        assert artifacts == []


class TestSubdomainParsing:
    """Parsing of subfinder/sublist3r/amass/theHarvester output."""

    def test_extracts_unique_subdomains(self):
        artifacts = _parse_subdomains(SUBFINDER_OUTPUT, "github.com", "subfinder")
        values = [a["value"] for a in artifacts]

        assert values == ["accelerator.github.com", "f.cloud.github.com"]
        assert all(a["type"] == "subdomain" for a in artifacts)
        assert all(a["source"] == "subfinder" for a in artifacts)

    def test_ignores_percent_encoded_prefixes(self):
        artifacts = _parse_subdomains("%2Fdocs.github.com", "github.com", "subfinder")
        assert artifacts == []


class TestToolCoverage:
    """Every declared tool is either integrated or documented as unimplemented."""

    def test_every_tool_has_a_status(self):
        coverage = get_tool_coverage()

        assert len(coverage) >= 30
        for name, info in coverage.items():
            assert isinstance(info["available"], bool), name
            if info["integrated"]:
                assert info["artifact_types"], name
            else:
                assert info["reason"], name

    def test_integrations_expose_their_analysis_methods(self):
        for name, integration in get_tool_integrations().items():
            assert name in ANALYSIS_METHODS, name
            for method_name in ANALYSIS_METHODS[name].values():
                assert hasattr(integration, method_name), (name, method_name)


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


class TestToolFindingCorrelation:
    """Tool output linked to a seed lands in that seed's identity profile."""

    def test_findings_attach_to_seed_identity(self, conn):
        inv_id = db.create_investigation(conn)

        username = db.add_artifact(conn, inv_id, "username", "octocat", source="seed")
        domain = db.add_artifact(conn, inv_id, "domain", "github.com", source="whois")
        subdomain = db.add_artifact(
            conn, inv_id, "subdomain", "api.github.com", source="subfinder"
        )
        presence = db.add_artifact(
            conn, inv_id, "username_presence", "https://github.com/octocat",
            source="sherlock", metadata='{"platform": "GitHub"}',
        )
        port = db.add_artifact(conn, inv_id, "open_port", "443/tcp https", source="nmap")

        for target in (domain, presence):
            db.add_link(conn, inv_id, username, target, "discovered_from")
        db.add_link(conn, inv_id, domain, subdomain, "discovered_from")
        db.add_link(conn, inv_id, domain, port, "discovered_from")

        result = correlate_identities(conn, inv_id)
        profile = next(p for p in result.identities if "octocat" in p.usernames)

        assert "github.com" in profile.domains
        assert "api.github.com" in profile.subdomains
        assert "443/tcp https" in profile.open_ports
        assert {"sherlock", "subfinder", "nmap", "whois"} <= set(profile.tools_used)
        assert any(p["platform"] == "GitHub" for p in profile.platforms)

    def test_image_metadata_attaches_to_image_identity(self, conn):
        inv_id = db.create_investigation(conn)

        image = db.add_artifact(conn, inv_id, "image", "/tmp/evidence.jpg", source="seed")
        gps = db.add_artifact(
            conn, inv_id, "gps_coordinates", "37.77 N, 122.41 W", source="exiftool"
        )
        camera = db.add_artifact(conn, inv_id, "camera_info", "Canon EOS 80D", source="exiftool")

        for target in (gps, camera):
            db.add_link(conn, inv_id, image, target, "discovered_from")

        result = correlate_identities(conn, inv_id)
        profile = next(p for p in result.identities if "/tmp/evidence.jpg" in p.images)

        assert "37.77 N, 122.41 W" in profile.geolocations
        assert "Canon EOS 80D" in profile.device_info
        assert profile.tools_used == ["exiftool"]

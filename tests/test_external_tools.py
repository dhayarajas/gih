"""Tests for external OSINT tool parsers and their correlation into identity profiles."""

import json
import tempfile
from pathlib import Path

import pytest

from src.correlation.linker import correlate_identities
from src.modules.external_tools import (
    ANALYSIS_METHODS,
    ExifToolIntegration,
    ToolResult,
    get_tool_coverage,
    get_tool_integrations,
)
from src.modules.tool_parsers import (
    parse_holehe_text,
    parse_sherlock,
    parse_subdomains,
)
from src.orchestrator import _artifact_metadata
from src.storage import database as db
from src.utils import tool_checker

SHERLOCK_OUTPUT = """[*] Checking username octocat on:

[+] 7Cups: https://www.7cups.com/@octocat
[+] GitHub: https://github.com/octocat
[+] GitHub: https://github.com/octocat
[-] Facebook: Not Found!
"""

HOLEHE_OUTPUT = """[+] github.com
[+] github.com
[+] twitter.com
[-] spotify.com
[x] rate limited
"""

SUBFINDER_OUTPUT = """accelerator.github.com
f.cloud.github.com
github.com
https://example.org/redirect?url=%2Fdocs.github.com
"""


class TestAccountParsing:
    """Parsing of sherlock/maigret '[+] Platform: url' output."""

    def test_extracts_found_accounts(self):
        artifacts = parse_sherlock(SHERLOCK_OUTPUT, "octocat")
        values = [a["value"] for a in artifacts]

        assert values == ["https://www.7cups.com/@octocat", "https://github.com/octocat"]
        assert all(a["type"] == "username_presence" for a in artifacts)
        assert all(a["source"] == "sherlock" for a in artifacts)
        assert artifacts[1]["platform"] == "GitHub"
        assert artifacts[1]["username"] == "octocat"

    def test_ignores_not_found_lines(self):
        artifacts = parse_sherlock("[-] Facebook: Not Found!", "octocat")
        assert artifacts == []


class TestSubdomainParsing:
    """Parsing of subfinder/sublist3r/amass/theHarvester output."""

    def test_extracts_unique_subdomains(self):
        artifacts = parse_subdomains(SUBFINDER_OUTPUT, "github.com", "subfinder")
        values = [a["value"] for a in artifacts]

        assert values == ["accelerator.github.com", "f.cloud.github.com"]
        assert all(a["type"] == "subdomain" for a in artifacts)
        assert all(a["source"] == "subfinder" for a in artifacts)

    def test_ignores_percent_encoded_prefixes(self):
        artifacts = parse_subdomains("%2Fdocs.github.com", "github.com", "subfinder")
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

    def test_dns_resolution_is_not_dispatched(self):
        """dig resolves the mail/web provider, not the seed.

        For `-e user@gmail.com` its records describe Google's infrastructure and
        get attributed to the person, so the tool is documented as unimplemented
        rather than integrated.
        """
        coverage = get_tool_coverage()

        assert coverage["dig"]["integrated"] is False
        assert coverage["dig"]["reason"]
        assert "dig" not in get_tool_integrations()
        assert "dig" not in ANALYSIS_METHODS

        orchestrator_source = Path("src/orchestrator.py").read_text()
        assert '"dig"' not in orchestrator_source

    def test_integrations_expose_their_analysis_methods(self):
        for name, integration in get_tool_integrations().items():
            assert name in ANALYSIS_METHODS, name
            for method_name in ANALYSIS_METHODS[name].values():
                assert hasattr(integration, method_name), (name, method_name)


class TestArtifactMetadata:
    """Discovered-artifact metadata keeps its top-level keys addressable."""

    def test_preserves_pre_serialized_json_metadata(self):
        artifact = {
            "type": "platform_presence",
            "value": "https://github.com/octocat",
            "metadata": '{"platform": "GitHub", "risk_indicators": ["breach"]}',
        }

        stored = json.loads(_artifact_metadata(artifact))

        assert stored["platform"] == "GitHub"
        assert stored["risk_indicators"] == ["breach"]

    def test_wraps_non_json_metadata(self):
        stored = json.loads(_artifact_metadata({"type": "email", "metadata": "plain text"}))
        assert stored == {"value": "plain text"}

    def test_keeps_tool_specific_extras(self):
        stored = json.loads(_artifact_metadata({
            "type": "username_presence",
            "value": "https://github.com/octocat",
            "platform": "GitHub",
            "username": "octocat",
        }))

        assert stored == {"platform": "GitHub", "username": "octocat"}


class TestEmailAccountParsing:
    """Holehe hits stay distinct artifacts rather than collapsing on the email."""

    def test_each_platform_is_a_distinct_artifact(self):
        artifacts = parse_holehe_text(HOLEHE_OUTPUT, "octocat@github.com")
        values = [a["value"] for a in artifacts]

        assert values == [
            "github.com:octocat@github.com",
            "twitter.com:octocat@github.com",
        ]
        assert all(a["type"] == "email_presence" for a in artifacts)
        assert all(a["username"] == "octocat@github.com" for a in artifacts)


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


class TestExifToolTargets:
    """exiftool reads local files only; image artifacts may be remote URLs."""

    @pytest.fixture(autouse=True)
    def _exiftool_available(self, monkeypatch):
        monkeypatch.setattr(tool_checker, "check_tool_availability", lambda name: True)

    def test_remote_url_is_not_scanned(self, monkeypatch):
        integration = ExifToolIntegration()
        monkeypatch.setattr(
            integration, "run_tool",
            lambda *a, **k: pytest.fail("exiftool must not run on a URL"),
        )

        result = integration.extract_metadata("https://cdn.example.com/avatar.jpg")

        assert not result.success
        assert "Not a local file" in result.error_message

    def test_local_file_is_scanned(self, monkeypatch, tmp_path):
        image = tmp_path / "evidence.jpg"
        image.write_bytes(b"")
        integration = ExifToolIntegration()
        commands = []

        def _run(tool_name, command, **kwargs):
            commands.append(command)
            return ToolResult(tool_name=tool_name, success=False, output="")

        monkeypatch.setattr(integration, "run_tool", _run)
        integration.extract_metadata(str(image))

        assert commands == [["exiftool", "-json", str(image)]]


class TestIpArtifactTypeIsConsistent:
    """Every producer of an IP must agree on the type, or the same address
    becomes two nodes and the nmap findings hanging off one of them are
    orphaned from the identity that reaches the other."""

    def test_plugins_use_ip_address(self):
        from src.plugins.builtins.shodan_plugin import ShodanPlugin
        from src.plugins.builtins.whois_plugin import WhoisPlugin

        for plugin in (ShodanPlugin(), WhoisPlugin()):
            supported = plugin.get_supported_artifact_types()
            assert "ip" not in supported, plugin.name
            assert "ip_address" in supported, plugin.name

    def test_open_ports_reach_the_identity_that_owns_the_ip(self, conn):
        """email -> domain -> ip_address -> open_port must land on the profile."""
        inv_id = db.create_investigation(conn)

        email = db.add_artifact(conn, inv_id, "email", "ada@example.com", source="seed")
        domain = db.add_artifact(conn, inv_id, "domain", "example.com", source="whois")
        ip = db.add_artifact(conn, inv_id, "ip_address", "93.184.216.34", source="whatweb")
        port = db.add_artifact(
            conn, inv_id, "open_port", "93.184.216.34:22", source="nmap"
        )

        db.add_link(conn, inv_id, email, domain, "discovered_from")
        db.add_link(conn, inv_id, domain, ip, "discovered_from")
        db.add_link(conn, inv_id, ip, port, "discovered_from")

        result = correlate_identities(conn, inv_id)
        profile = next(p for p in result.identities if "ada@example.com" in p.emails)

        assert "93.184.216.34" in profile.ip_addresses
        assert "93.184.216.34:22" in profile.open_ports


class TestToolArguments:
    """The argv each integration builds is part of its contract with the parser."""

    def _capture(self, monkeypatch, integration):
        """Record the argv an integration passes to run_tool, without executing it."""
        calls = []

        def fake_run_tool(tool_name, command, timeout=None):
            calls.append(command)
            return ToolResult(tool_name=tool_name, success=True, output="")

        monkeypatch.setattr(integration, "run_tool", fake_run_tool)
        return calls

    def test_theharvester_runs_once_per_domain(self, monkeypatch):
        from src.modules.external_tools import TheHarvesterIntegration

        integration = TheHarvesterIntegration()
        calls = self._capture(monkeypatch, integration)
        monkeypatch.setattr(tool_checker, "check_tool_availability", lambda name: True)

        integration.harvest_email("example.com")
        integration.harvest_subdomains("example.com")
        integration.harvest_email("other.com")

        assert [c[2] for c in calls] == ["example.com", "other.com"]

    def test_nmap_ports_come_from_config(self, monkeypatch):
        from src.modules.external_tools import NmapIntegration

        integration = NmapIntegration()
        calls = self._capture(monkeypatch, integration)
        monkeypatch.setattr(tool_checker, "check_tool_availability", lambda name: True)

        monkeypatch.setattr("src.modules.external_tools._get_nmap_ports", lambda: "common")
        integration.scan_host("1.2.3.4")
        monkeypatch.setattr("src.modules.external_tools._get_nmap_ports", lambda: "22,443")
        integration.scan_host("1.2.3.4")

        assert "-F" in calls[0] and "-p" not in calls[0]
        assert calls[1][calls[1].index("-p") + 1] == "22,443"

"""
External OSINT Tools Integration Module

This module integrates external OSINT tools installed in the VM environment
with the Ghost Identity Hunter investigation pipeline, providing unified
access to tool outputs and results.
"""

import subprocess
import json
import logging
import os
import signal
import re
import tempfile
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from src.config.loader import get_config
from src.modules import tool_parsers
from src.storage import evidence
from src.utils.concurrency import io_slot
from src.utils.tool_checker import (
    check_tool_availability,
    get_tool_checker,
    skip_if_not_available,
)

logger = logging.getLogger(__name__)

# Fallback timeout (seconds) used when a tool has no `timeout` configured.
DEFAULT_TOOL_TIMEOUT = 60


def _get_tool_timeout(tool_name: str, default: int = DEFAULT_TOOL_TIMEOUT) -> int:
    """Resolve the configured per-tool subprocess timeout from config.yaml.

    Per-tool timeouts live under the ``plugins.<tool_name>.timeout`` section
    (with a top-level ``<tool_name>.timeout`` also honored as a fallback). This
    ensures every integration uses its configured budget instead of the old
    hardcoded 60s default (or nmap's hardcoded 300s).
    """
    try:
        config = get_config()
        plugins_cfg = config.get("plugins", {}) or {}
        tool_cfg = plugins_cfg.get(tool_name) or config.get(tool_name) or {}
        return int(tool_cfg.get("timeout", default))
    except Exception:
        return default


# Port selection for nmap; "common" maps to nmap's own -F top-100 list.
DEFAULT_NMAP_PORTS = "common"


def _get_nmap_ports(default: str = DEFAULT_NMAP_PORTS) -> str:
    """Resolve the configured nmap port selection from config.yaml."""
    try:
        config = get_config()
        nmap_cfg = (config.get("plugins", {}) or {}).get("nmap") or {}
        ports = (nmap_cfg.get("custom_params") or {}).get("ports")
        return str(ports) if ports else default
    except Exception:
        return default


class ToolOutputFormat(Enum):
    """Output format types from OSINT tools."""
    JSON = "json"
    TEXT = "text"
    XML = "xml"
    CSV = "csv"
    UNKNOWN = "unknown"


@dataclass
class ToolResult:
    """Result from an external OSINT tool execution."""
    tool_name: str
    success: bool
    output: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    execution_time: float = 0.0
    artifacts_discovered: List[Dict[str, Any]] = field(default_factory=list)


# A tool that never stops printing would otherwise be held in memory in full.
MAX_TOOL_OUTPUT_BYTES = 32 * 1024 * 1024


def _decode(raw: Any) -> str:
    """Text from a tool's pipe, whatever bytes it actually wrote.

    Tools print filenames and page titles in whatever encoding they were given,
    so strict decoding would throw away a whole run over one byte.
    """
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _run_subprocess(
    command: List[str],
    timeout: int,
    cwd: Optional[str],
) -> tuple[int, str]:
    """Run a tool to completion or to its deadline, leaving nothing behind.

    ``subprocess.run`` kills only the process it started: a tool that forks
    (amass, theHarvester) leaves children holding the pipes open, and the
    cleanup read after the kill then blocks forever, hanging the whole
    investigation. The child therefore leads its own process group, and the
    group is signalled as a whole.
    """
    popen_kwargs: Dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": cwd,
    }
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(command, **popen_kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate(process)
        # The group is gone, so this read cannot block.
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            command, timeout, output=stdout, stderr=stderr
        )

    output = _decode(stdout) + _decode(stderr)
    if len(output) > MAX_TOOL_OUTPUT_BYTES:
        logger.warning(
            "%s printed %d bytes; keeping the first %d",
            command[0], len(output), MAX_TOOL_OUTPUT_BYTES,
        )
        output = output[:MAX_TOOL_OUTPUT_BYTES]
    return process.returncode, output


def _terminate(process: "subprocess.Popen") -> None:
    """End the tool and everything it started."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:
            process.terminate()
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)
    except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired) as exc:
        logger.debug("Could not fully stop pid %s: %s", process.pid, exc)


class ExternalToolsIntegration:
    """Integration layer for external OSINT tools."""
    
    def __init__(self):
        self.results_cache: Dict[str, ToolResult] = {}
    
    def run_tool(self, tool_name: str, command: List[str], timeout: Optional[int] = None,
                 cwd: Optional[str] = None) -> ToolResult:
        """
        Execute an external OSINT tool and capture output.
        
        Args:
            tool_name: Name of the tool being executed
            command: Command list to execute
            timeout: Execution timeout in seconds. When ``None`` (the default),
                the configured ``<tool_name>.timeout`` from config.yaml is used,
                falling back to ``DEFAULT_TOOL_TIMEOUT``.
            cwd: Working directory for the subprocess, for the tools that write
                their report beside themselves rather than where told.
            
        Returns:
            ToolResult with execution output and status
        """
        if timeout is None:
            timeout = _get_tool_timeout(tool_name)
        result = ToolResult(tool_name=tool_name, success=False, output="")
        exit_status = "unknown"
        started = time.monotonic()

        try:
            logger.info(f"Running {tool_name}: {' '.join(command)}")

            with io_slot():
                returncode, output = _run_subprocess(command, timeout, cwd)

            result.success = returncode == 0
            result.output = output
            exit_status = f"exit {returncode}"

            if returncode != 0:
                result.error_message = f"Tool exited with code {returncode}"
                logger.warning(f"{tool_name} failed: {result.error_message}")

            logger.debug(f"{tool_name} completed successfully")

        except subprocess.TimeoutExpired as expired:
            result.error_message = f"Tool execution timed out after {timeout}s"
            exit_status = "timeout"
            # Whatever it printed before the deadline is still evidence.
            result.output = _decode(expired.stdout) + _decode(expired.stderr)
            logger.error(f"{tool_name} timeout: {result.error_message}")
            
        except FileNotFoundError:
            result.error_message = f"Tool command not found: {command[0]}"
            exit_status = "not_found"
            logger.error(f"{tool_name} not found: {result.error_message}")
            
        except Exception as e:
            result.error_message = f"Unexpected error: {str(e)}"
            exit_status = "error"
            logger.error(f"{tool_name} error: {result.error_message}")

        result.execution_time = time.monotonic() - started
        # The raw output is what a reviewer has to be able to re-read months
        # later; the parsed artifacts alone cannot be re-derived or challenged.
        evidence.record(
            tool_name,
            result.output or (result.error_message or ""),
            command=" ".join(command),
            duration_seconds=result.execution_time,
            exit_status=exit_status,
        )
        return result
    
    def parse_json_output(self, output: str) -> Dict[str, Any]:
        """Parse JSON output from tool."""
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON output")
            return {}
    
    def extract_artifacts_from_text(self, output: str, patterns: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Extract artifacts from text output using regex patterns.
        
        Args:
            output: Tool output text
            patterns: Dictionary of artifact type to regex pattern
            
        Returns:
            List of discovered artifacts
        """
        artifacts = []
        
        for artifact_type, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                artifacts.append({
                    "type": artifact_type,
                    "value": match,
                    "source": "external_tool"
                })
        
        return artifacts


# Re-exported so the integrations and their parsers share one bound.
MAX_ARTIFACTS_PER_TOOL = tool_parsers.MAX_ARTIFACTS_PER_TOOL

# Matches the "[+] Platform: https://..." lines emitted by sherlock and maigret.
FOUND_ACCOUNT_PATTERN = re.compile(r"^\[\+\]\s*(?P<platform>[^:]+?):\s*(?P<url>https?://\S+)\s*$")

# Declared tools that intentionally have no integration, with the reason why.
# Surfaced by get_tool_coverage() so the "25+ tools" claim stays accurate.
UNIMPLEMENTED_TOOLS: Dict[str, str] = {
    "social_analyzer": "No stable CLI contract; node/python variants differ and output is not machine-parseable",
    "emailharvester": "Superseded by theHarvester, which is integrated and covers the same sources",
    "recon-ng": "Interactive framework requiring per-module API keys and a workspace; not batch-invocable",
    "spiderfoot": "Server/daemon oriented, requires its own database and web UI to collect results",
    "ghunt": "Requires authenticated Google session cookies supplied by the operator",
    "photon": "Crawler output duplicates wayback_machine historical URLs",
    "metagoofil": "Document harvesting requires a search-engine API key and downloads remote files",
    "etherscan": "Requires an Etherscan API key and a wallet-address artifact type",
    "geonames": "Requires a GeoNames account; geodata is derived from exiftool GPS instead",
    "wappalyzer": "Superseded by whatweb, which is integrated and detects the same technologies",
    "masscan": "Requires raw-socket (root) privileges; nmap covers the same port-scan role",
    "nikto": "Vulnerability scanner, out of scope for identity attribution",
    "sqlmap": "Exploitation tool, out of scope for identity attribution",
    "tor_browser": "Interactive browser, not a data source",
    "flagfox": "Browser extension, not a data source",
    "user_agent_switcher": "Browser extension, not a data source",
    "curl": "Generic transport used by other integrations rather than a data source",
    "wget": "Generic transport used by other integrations rather than a data source",
    "nslookup": "DNS resolution is not dispatched: a mail domain resolves the provider, not the seed",
    "dig": "Resolves the mail/web provider rather than the seed itself, so its records misattribute the target",
    "google_dorks": "Implemented in src.modules.google_dorks and invoked directly for username artifacts",
    "leakosint": "Implemented in src.modules.leakosint and dispatched through the plugin system",
}


class SherlockIntegration(ExternalToolsIntegration):
    """Integration for Sherlock username search tool."""
    
    @skip_if_not_available("sherlock")
    def search_username(self, username: str) -> ToolResult:
        """Search for username across social networks using Sherlock."""
        command = [
            "sherlock", username,
            "--print-found",
            "--timeout", "5",
            "--no-color",
            "--no-txt",  # keep sherlock from writing <username>.txt into the working directory
        ]
        result = self.run_tool("sherlock", command)
        
        if result.success:
            result.artifacts_discovered = tool_parsers.parse_sherlock(result.output, username)
            result.parsed_data = {
                "username": username,
                "platforms": {a["platform"]: a["value"] for a in result.artifacts_discovered},
            }
            logger.info(f"Sherlock found {len(result.artifacts_discovered)} platforms for {username}")
        
        return result


class MaigretIntegration(ExternalToolsIntegration):
    """Integration for Maigret username search tool."""

    @skip_if_not_available("maigret")
    def search_username(self, username: str) -> ToolResult:
        """Search for username across the top Maigret sites.

        maigret prints a tree and writes a report; only the report carries the
        detail its site extractors pulled out of each claimed account, so the
        run asks for a newline-delimited JSON report and reads that. The
        printed tree remains the evidence of what happened.
        """
        with tempfile.TemporaryDirectory(prefix="maigret-") as out_dir:
            command = [
                "maigret", username,
                "--top-sites", "150",
                "--timeout", "5",
                "--no-progressbar",
                "--no-color",
                "--no-recursion",
                "-J", "ndjson",
                "-fo", out_dir,
            ]
            result = self.run_tool("maigret", command)

            if not result.success:
                return result

            report = _read_first_file(out_dir, f"report_{username}_ndjson.json")

        findings = tool_parsers.parse_maigret_ndjson(report, username) if report else []
        if not findings:
            # Without a readable report the printed tree is all there is; its
            # "[+]" lines still name the accounts, just not what maigret
            # extracted from them.
            logger.warning("no maigret report for %s; falling back to its output", username)
            findings = tool_parsers.parse_sherlock(result.output, username)
            for artifact in findings:
                artifact["source"] = "maigret"
                artifact["confidence"] = 0.75
        result.artifacts_discovered = findings

        result.parsed_data = {
            "username": username,
            "platforms": {
                a["platform"]: a["value"] for a in result.artifacts_discovered
                if a["type"] == "username_presence"
            },
        }
        logger.info(
            "Maigret found %d findings for %s",
            len(result.artifacts_discovered), username,
        )

        return result


def _read_first_file(directory: str, preferred: str = "") -> Optional[str]:
    """Read a tool's report out of the directory it was told to write to.

    Tools name their report after the target and their own conventions, so the
    expected name is tried first and any single file in the directory second.
    """
    candidates = []
    if preferred:
        candidates.append(os.path.join(directory, preferred))
    try:
        candidates.extend(sorted(
            os.path.join(directory, name) for name in os.listdir(directory)
        ))
    except OSError:
        return None

    for path in candidates:
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    return handle.read()
        except OSError:
            continue
    return None


class HoleheIntegration(ExternalToolsIntegration):
    """Integration for Holehe email account discovery."""

    @skip_if_not_available("holehe")
    def check_email(self, email: str) -> ToolResult:
        """Discover which services an email address is registered on.

        The CSV report is asked for because a site may return a masked
        recovery address or phone number alongside the yes/no, and the
        terminal output shows only the yes.
        """
        with tempfile.TemporaryDirectory(prefix="holehe-") as out_dir:
            command = ["holehe", email, "--only-used", "--no-color", "--no-clear", "-C"]
            result = self.run_tool("holehe", command, cwd=out_dir)

            if not result.success:
                return result

            report = _read_first_file(out_dir)

        if report:
            result.artifacts_discovered = tool_parsers.parse_holehe_csv(report, email)
        else:
            logger.warning("holehe CSV report missing for %s; reading its output", email)
            result.artifacts_discovered = tool_parsers.parse_holehe_text(result.output, email)

        result.parsed_data = {
            "email": email,
            "platforms": [a["platform"] for a in result.artifacts_discovered],
        }
        logger.info(
            "Holehe found %d accounts for %s", len(result.artifacts_discovered), email,
        )
        return result


class OsrframeworkIntegration(ExternalToolsIntegration):
    """Integration for OSRFramework's usufy username checker."""

    @skip_if_not_available("osrframework")
    def search_username(self, username: str) -> ToolResult:
        """Check a username across the OSRFramework platform list."""
        # usufy only writes its structured results to a file; stdout is a
        # human-readable table, so the output directory is the real interface.
        with tempfile.TemporaryDirectory(prefix="usufy-") as out_dir:
            command = [
                "usufy",
                "-n", username,
                # The full platform list takes well over the time budget; the
                # "social" tag covers the platforms useful for attribution.
                "-t", "social",
                "-T", "32",
                "-e", "json",
                "-o", out_dir,
                "--avoid_download",
            ]
            result = self.run_tool("osrframework", command)

            if not result.success:
                return result

            profiles_file = os.path.join(out_dir, "profiles.json")
            try:
                with open(profiles_file, "r", encoding="utf-8") as handle:
                    profiles = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                result.success = False
                result.error_message = f"Could not read usufy output: {exc}"
                return result

        result.artifacts_discovered = tool_parsers.parse_usufy_profiles(profiles, username)
        result.parsed_data = {"username": username, "profiles": profiles}
        logger.info(
            "OSRFramework found %d profiles for %s",
            len(result.artifacts_discovered), username,
        )

        return result



class TheHarvesterIntegration(ExternalToolsIntegration):
    """Integration for theHarvester OSINT tool."""

    def __init__(self):
        super().__init__()
        # One theHarvester run yields both the emails and the subdomains, so the
        # two analyses share a single subprocess per domain instead of issuing
        # the identical command twice.
        self._runs: Dict[str, ToolResult] = {}
        self._reports: Dict[str, Optional[str]] = {}
        self._runs_lock = threading.Lock()

    def _harvest(self, domain: str) -> ToolResult:
        """Run theHarvester once per domain, keeping its output and report.

        -f makes theHarvester write a JSON report naming what each finding is;
        the printed summary separates emails, hosts, people and ASNs into
        sections that a regex sweeping the whole text cannot tell apart.
        """
        with self._runs_lock:
            cached = self._runs.get(domain)
            if cached is not None:
                return cached

            with tempfile.TemporaryDirectory(prefix="theharvester-") as out_dir:
                report_path = os.path.join(out_dir, "report")
                command = ["theHarvester", "-d", domain, "-b", "duckduckgo",
                           "-f", report_path]
                result = self.run_tool("theharvester", command)
                self._reports[domain] = _read_first_file(out_dir, "report.json")

            self._runs[domain] = result
            return result

    def _fresh_result(self, domain: str) -> ToolResult:
        """A per-analysis copy of the shared run, so parsers do not share state."""
        shared = self._harvest(domain)
        return ToolResult(
            tool_name=shared.tool_name,
            success=shared.success,
            output=shared.output,
            error_message=shared.error_message,
            execution_time=shared.execution_time,
        )

    def _findings(self, domain: str, result: ToolResult) -> List[Dict[str, Any]]:
        """Everything the run found, from the report when there is one.

        Uncapped: one run feeds two analyses, and capping here would let a
        domain with fifteen published addresses report no hosts at all. Each
        analysis caps its own half.
        """
        report = self._reports.get(domain)
        if report:
            parsed = tool_parsers.parse_theharvester_json(report, domain)
            if parsed:
                return parsed
            logger.debug("theHarvester report for %s held no findings", domain)
        return (tool_parsers.parse_emails(result.output, domain, "theharvester")
                + tool_parsers.parse_subdomains(result.output, domain, "theharvester"))

    @skip_if_not_available("theharvester")
    def harvest_email(self, domain: str) -> ToolResult:
        """Harvest emails and the people behind them using theHarvester."""
        result = self._fresh_result(domain)

        if result.success:
            result.artifacts_discovered = [
                a for a in self._findings(domain, result)
                if a["type"] in ("email", "fullname")
            ][:MAX_ARTIFACTS_PER_TOOL]
            logger.info(
                "theHarvester found %d contacts for %s",
                len(result.artifacts_discovered), domain,
            )

        return result

    @skip_if_not_available("theharvester")
    def harvest_subdomains(self, domain: str) -> ToolResult:
        """Harvest subdomains, their addresses and ASNs using theHarvester."""
        result = self._fresh_result(domain)

        if result.success:
            result.artifacts_discovered = [
                a for a in self._findings(domain, result)
                if a["type"] not in ("email", "fullname")
            ][:MAX_ARTIFACTS_PER_TOOL]
            logger.info(
                "theHarvester found %d hosts for %s",
                len(result.artifacts_discovered), domain,
            )

        return result


class SubfinderIntegration(ExternalToolsIntegration):
    """Integration for subfinder passive subdomain enumeration."""

    @skip_if_not_available("subfinder")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains using subfinder.

        -json names the passive source behind each name, which is how a reader
        judges a subdomain only one aggregator has ever seen.
        """
        command = ["subfinder", "-d", domain, "-silent", "-json", "-timeout", "10"]
        result = self.run_tool("subfinder", command)

        if result.success:
            result.artifacts_discovered = (
                tool_parsers.parse_subfinder_json(result.output, domain)
                or tool_parsers.parse_subdomains(result.output, domain, "subfinder")
            )
            logger.info(f"Subfinder found {len(result.artifacts_discovered)} subdomains for {domain}")

        return result


class Sublist3rIntegration(ExternalToolsIntegration):
    """Integration for Sublist3r subdomain enumeration."""

    @skip_if_not_available("sublist3r")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains using Sublist3r."""
        command = ["sublist3r", "-d", domain, "-n"]
        result = self.run_tool("sublist3r", command)

        if result.success:
            result.artifacts_discovered = tool_parsers.parse_subdomains(
                result.output, domain, "sublist3r")
            logger.info(f"Sublist3r found {len(result.artifacts_discovered)} subdomains for {domain}")

        return result


class WhatWebIntegration(ExternalToolsIntegration):
    """Integration for WhatWeb technology fingerprinting."""

    @skip_if_not_available("whatweb")
    def fingerprint(self, target: str) -> ToolResult:
        """Fingerprint the web technologies served by a domain or host.

        The JSON log keeps the plugin, its value and its module apart, so the
        page title, the country and the HTTP status stay distinguishable from
        the technology list instead of being flattened into one bracket soup.
        """
        with tempfile.TemporaryDirectory(prefix="whatweb-") as out_dir:
            log_path = os.path.join(out_dir, "whatweb.json")
            command = ["whatweb", "--color=never", "--no-errors", "-a", "1",
                       f"--log-json={log_path}", target]
            result = self.run_tool("whatweb", command)

            if not result.success:
                return result

            log = _read_first_file(out_dir, "whatweb.json")

        parsed, findings = (
            tool_parsers.parse_whatweb_json(log, target) if log else ({}, [])
        )
        if not findings:
            # whatweb writes one JSON document per scanned target, so a
            # redirect chain produces a log the parser cannot read as a whole.
            logger.warning("no whatweb JSON log for %s; reading its summary", target)
            parsed, findings = tool_parsers.parse_whatweb_summary(result.output, target)
        result.parsed_data, result.artifacts_discovered = parsed, findings

        logger.info(f"WhatWeb identified {len(result.artifacts_discovered)} findings for {target}")
        return result


class ShodanIntegration(ExternalToolsIntegration):
    """Integration for Shodan search engine."""
    
    @skip_if_not_available("shodan")
    def search_host(self, ip_address: str) -> ToolResult:
        """Search for host information on Shodan."""
        command = ["shodan", "host", ip_address]
        result = self.run_tool("shodan", command)

        if result.success:
            result.parsed_data, result.artifacts_discovered = (
                tool_parsers.parse_shodan_host(result.output, ip_address)
            )
            logger.info(
                "Shodan found info for %s: %d artifacts",
                ip_address, len(result.artifacts_discovered),
            )

        return result


class AmassIntegration(ExternalToolsIntegration):
    """Integration for Amass subdomain enumeration."""
    
    @skip_if_not_available("amass")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains using Amass."""
        command = ["amass", "enum", "-passive", "-d", domain]
        result = self.run_tool("amass", command)
        
        if result.success:
            result.artifacts_discovered = tool_parsers.parse_subdomains(
                result.output, domain, "amass")
            logger.info(f"Amass found {len(result.artifacts_discovered)} subdomains for {domain}")
        
        return result


class WhoisIntegration(ExternalToolsIntegration):
    """Integration for Whois domain lookup."""
    
    @skip_if_not_available("whois")
    def lookup_domain(self, domain: str) -> ToolResult:
        """Perform whois lookup for domain."""
        command = ["whois", domain]
        result = self.run_tool("whois", command)

        if result.success:
            result.parsed_data, result.artifacts_discovered = (
                tool_parsers.parse_whois(result.output, domain)
            )
            logger.info(
                "Whois lookup found %d fields for %s",
                len(result.parsed_data), domain,
            )

        return result


class NmapIntegration(ExternalToolsIntegration):
    """Integration for Nmap network scanner."""
    
    @skip_if_not_available("nmap")
    def scan_host(self, target: str, ports: Optional[str] = None) -> ToolResult:
        """Scan host using Nmap.

        ``ports`` defaults to ``plugins.nmap.custom_params.ports`` in
        config.yaml, so an operator can widen or narrow the scan without a code
        change; "common" keeps nmap's own top-100 list (``-F``).
        """
        if ports is None:
            ports = _get_nmap_ports()

        selection = ["-F"] if ports == "common" else ["-p", ports]
        with tempfile.TemporaryDirectory(prefix="nmap-") as out_dir:
            xml_path = os.path.join(out_dir, "scan.xml")
            command = (["nmap", "-Pn"] + selection
                       + ["-sV", "--version-light", "-oX", xml_path, target])
            result = self.run_tool("nmap", command)

            if not result.success:
                return result

            report = _read_first_file(out_dir, "scan.xml")

        parsed, findings = (
            tool_parsers.parse_nmap_xml(report, target) if report else ({}, [])
        )
        if not findings:
            logger.warning("no readable nmap XML for %s; reading its table", target)
            findings = tool_parsers.parse_nmap_text(result.output, target)
        result.parsed_data, result.artifacts_discovered = parsed, findings

        logger.info(f"Nmap found {len(result.artifacts_discovered)} findings on {target}")
        return result


class ExifToolIntegration(ExternalToolsIntegration):
    """Integration for ExifTool metadata extraction."""
    
    @skip_if_not_available("exiftool")
    def extract_metadata(self, file_path: str) -> ToolResult:
        """Extract metadata from file using ExifTool."""
        # Image artifacts include scraped profile-picture URLs; exiftool only reads
        # local files, so anything else would be a guaranteed-failing subprocess.
        if not os.path.isfile(file_path):
            return ToolResult(
                tool_name="exiftool",
                success=False,
                output="",
                error_message=f"Not a local file: {file_path}",
            )

        command = ["exiftool", "-json", file_path]
        result = self.run_tool("exiftool", command)

        if result.success:
            result.parsed_data, result.artifacts_discovered = (
                tool_parsers.parse_exiftool_json(result.output, file_path)
            )
            logger.info(
                "ExifTool extracted %d artifacts from %s",
                len(result.artifacts_discovered), file_path,
            )

        return result


class WaybackMachineIntegration(ExternalToolsIntegration):
    """Integration for Wayback Machine historical data."""
    
    def get_historical_urls(self, domain: str) -> ToolResult:
        """Get historical URLs from Wayback Machine using their API."""
        import requests
        
        result = ToolResult(tool_name="wayback_machine", success=False, output="")
        url = ""
        exit_status = "unknown"
        started = time.monotonic()

        try:
            # Use Wayback Machine CDX API
            url = (
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
                f"&fl=timestamp,original,statuscode,mimetype&collapse=urlkey"
                f"&limit={MAX_ARTIFACTS_PER_TOOL}"
            )
            with io_slot():
                response = requests.get(url, timeout=30)
            
            exit_status = f"HTTP {response.status_code}"
            result.output = response.text

            if response.status_code == 200:
                result.success = True
                
                result.artifacts_discovered = tool_parsers.parse_wayback_cdx(
                    response.json(), domain
                )
                if result.artifacts_discovered:
                    logger.info(
                        "Wayback Machine found %d historical URLs for %s",
                        len(result.artifacts_discovered), domain,
                    )
            else:
                result.error_message = f"API request failed: {response.status_code}"
                
        except Exception as e:
            result.error_message = f"Wayback Machine error: {str(e)}"
            if exit_status == "unknown":
                # A response that arrived and then failed to parse is still that
                # response; only a request that never completed is an error.
                exit_status = "error"
            logger.error(f"Wayback Machine error: {e}")

        result.execution_time = time.monotonic() - started
        evidence.record(
            "wayback_machine",
            result.output or (result.error_message or ""),
            operation="cdx_query",
            target=domain,
            command=f"GET {url}",
            duration_seconds=result.execution_time,
            exit_status=exit_status,
        )
        return result


# Global integration instances
_sherlock = SherlockIntegration()
_maigret = MaigretIntegration()
_holehe = HoleheIntegration()
_osrframework = OsrframeworkIntegration()
_theharvester = TheHarvesterIntegration()
_subfinder = SubfinderIntegration()
_sublist3r = Sublist3rIntegration()
_whatweb = WhatWebIntegration()
_shodan = ShodanIntegration()
_amass = AmassIntegration()
_whois = WhoisIntegration()
_nmap = NmapIntegration()
_exiftool = ExifToolIntegration()
_wayback = WaybackMachineIntegration()


def get_tool_integrations() -> Dict[str, ExternalToolsIntegration]:
    """Get all available tool integrations."""
    return {
        "sherlock": _sherlock,
        "maigret": _maigret,
        "holehe": _holehe,
        "osrframework": _osrframework,
        "theharvester": _theharvester,
        "subfinder": _subfinder,
        "sublist3r": _sublist3r,
        "whatweb": _whatweb,
        "shodan": _shodan,
        "amass": _amass,
        "whois": _whois,
        "nmap": _nmap,
        "exiftool": _exiftool,
        "wayback_machine": _wayback,
    }


# Analysis type -> integration method name, per tool.
ANALYSIS_METHODS: Dict[str, Dict[str, str]] = {
    "sherlock": {"username_search": "search_username"},
    "maigret": {"username_search": "search_username"},
    "holehe": {"email_check": "check_email"},
    "osrframework": {"username_search": "search_username"},
    "theharvester": {
        "email_harvest": "harvest_email",
        "subdomain_harvest": "harvest_subdomains",
    },
    "subfinder": {"subdomain_enum": "enumerate_subdomains"},
    "sublist3r": {"subdomain_enum": "enumerate_subdomains"},
    "whatweb": {"tech_fingerprint": "fingerprint"},
    "shodan": {"host_search": "search_host"},
    "amass": {"subdomain_enum": "enumerate_subdomains"},
    "whois": {"domain_lookup": "lookup_domain"},
    "nmap": {"host_scan": "scan_host"},
    "exiftool": {"metadata_extract": "extract_metadata"},
    "wayback_machine": {"historical_urls": "get_historical_urls"},
}

# Artifact types each integrated tool contributes to an investigation.
TOOL_ARTIFACT_TYPES: Dict[str, List[str]] = {
    "sherlock": ["username_presence"],
    # maigret's site extractors return the account holder's details, not only
    # the account.
    "maigret": ["username_presence", "fullname", "image_url", "location",
                "email", "phone"],
    "holehe": ["email_presence"],
    "osrframework": ["username_presence"],
    "theharvester": ["email", "subdomain", "ip_address", "url", "fullname", "asn"],
    "subfinder": ["subdomain"],
    "sublist3r": ["subdomain"],
    "whatweb": ["ip_address", "web_technology", "email"],
    "shodan": ["host_info", "open_port", "hostname"],
    "amass": ["subdomain"],
    "whois": ["domain_info", "email", "fullname", "name_server"],
    "nmap": ["open_port", "hostname"],
    "exiftool": ["gps_coordinates", "camera_info", "creation_date", "fullname",
                 "software", "device_serial", "copyright", "note"],
    "wayback_machine": ["historical_url"],
    "leakosint": ["leak_record"],
}

# Artifact types each tool is dispatched for, mirroring the dispatch in
# orchestrator._analyze_with_external_tools. A tool whose input type never
# appears in an investigation is silent for that reason alone, which is what
# the report says instead of leaving it unexplained.
TOOL_INPUT_TYPES: Dict[str, List[str]] = {
    "sherlock": ["username"],
    "maigret": ["username"],
    "osrframework": ["username"],
    "holehe": ["email"],
    "theharvester": ["domain", "subdomain"],
    "subfinder": ["domain", "subdomain"],
    "sublist3r": ["domain", "subdomain"],
    "amass": ["domain", "subdomain"],
    "whois": ["domain", "subdomain"],
    "whatweb": ["domain", "subdomain"],
    "wayback_machine": ["domain", "subdomain"],
    "shodan": ["ip_address"],
    "nmap": ["ip_address"],
    "exiftool": ["image"],
    "leakosint": ["email", "phone", "username", "fullname"],
}


def get_tool_coverage() -> Dict[str, Dict[str, Any]]:
    """
    Report, for every declared OSINT tool, whether it is integrated.

    Returns a mapping of tool name to availability, integration status,
    the artifact types it produces and, when unimplemented, the reason.
    """
    checker = get_tool_checker()
    integrations = get_tool_integrations()
    coverage = {}

    for tool_name in checker.tools:
        integrated = tool_name in integrations
        coverage[tool_name] = {
            "available": checker.is_available(tool_name),
            "integrated": integrated,
            "artifact_types": TOOL_ARTIFACT_TYPES.get(tool_name, []),
            "reason": None if integrated else UNIMPLEMENTED_TOOLS.get(tool_name, "No integration implemented"),
        }

    return coverage


# Per-run memoization of tool analyses. The BFS rediscovers the same
# domain/email/username from multiple parents; without this each occurrence
# re-runs the same subprocess/HTTP work before dedup happens at persistence
# time. Keyed by (tool_name, analysis_type, target); cleared at the start of
# each investigation via clear_tool_analysis_cache().
_analysis_cache: Dict[tuple, ToolResult] = {}
_analysis_cache_lock = threading.Lock()


def clear_tool_analysis_cache() -> None:
    """Reset the per-run tool-analysis memoization cache."""
    with _analysis_cache_lock:
        _analysis_cache.clear()


def run_tool_analysis(tool_name: str, analysis_type: str, target: str) -> ToolResult:
    """
    Run analysis using a specific external tool.
    
    Args:
        tool_name: Name of the tool to use
        analysis_type: Type of analysis to perform
        target: Target for analysis (domain, username, IP, etc.)
        
    Returns:
        ToolResult with analysis output and discovered artifacts
    """
    cache_key = (tool_name, analysis_type, target)
    with _analysis_cache_lock:
        cached = _analysis_cache.get(cache_key)
    if cached is not None:
        logger.debug("Tool analysis cache hit: %s/%s for %s", tool_name, analysis_type, target)
        return cached

    integrations = get_tool_integrations()
    
    if tool_name not in integrations:
        logger.error(f"Unknown tool integration: {tool_name}")
        return ToolResult(tool_name=tool_name, success=False, error_message="Unknown tool")
    
    integration = integrations[tool_name]

    if analysis_type not in ANALYSIS_METHODS.get(tool_name, {}):
        logger.error(f"Unknown analysis type: {analysis_type} for tool: {tool_name}")
        return ToolResult(tool_name=tool_name, success=False, error_message="Unknown analysis type")
    
    method = getattr(integration, ANALYSIS_METHODS[tool_name][analysis_type])
    with evidence.analysing(analysis_type, target):
        result = method(target)

    if result is None:
        # skip_if_not_available short-circuited the call
        return ToolResult(
            tool_name=tool_name,
            success=False,
            output="",
            error_message=f"{tool_name} is not available",
        )

    with _analysis_cache_lock:
        _analysis_cache[cache_key] = result
    return result

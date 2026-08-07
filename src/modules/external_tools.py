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
import re
import tempfile
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from src.config.loader import get_config
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


class ExternalToolsIntegration:
    """Integration layer for external OSINT tools."""
    
    def __init__(self):
        self.results_cache: Dict[str, ToolResult] = {}
    
    def run_tool(self, tool_name: str, command: List[str], timeout: Optional[int] = None) -> ToolResult:
        """
        Execute an external OSINT tool and capture output.
        
        Args:
            tool_name: Name of the tool being executed
            command: Command list to execute
            timeout: Execution timeout in seconds. When ``None`` (the default),
                the configured ``<tool_name>.timeout`` from config.yaml is used,
                falling back to ``DEFAULT_TOOL_TIMEOUT``.
            
        Returns:
            ToolResult with execution output and status
        """
        if timeout is None:
            timeout = _get_tool_timeout(tool_name)
        result = ToolResult(tool_name=tool_name, success=False, output="")
        
        try:
            logger.info(f"Running {tool_name}: {' '.join(command)}")
            
            with io_slot():
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            
            result.success = process.returncode == 0
            result.output = process.stdout + process.stderr
            
            if process.returncode != 0:
                result.error_message = f"Tool exited with code {process.returncode}"
                logger.warning(f"{tool_name} failed: {result.error_message}")
            
            logger.debug(f"{tool_name} completed successfully")
            
        except subprocess.TimeoutExpired:
            result.error_message = f"Tool execution timed out after {timeout}s"
            logger.error(f"{tool_name} timeout: {result.error_message}")
            
        except FileNotFoundError:
            result.error_message = f"Tool command not found: {command[0]}"
            logger.error(f"{tool_name} not found: {result.error_message}")
            
        except Exception as e:
            result.error_message = f"Unexpected error: {str(e)}"
            logger.error(f"{tool_name} error: {result.error_message}")
        
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


# Maximum number of artifacts a single tool run contributes to an investigation.
# Keeps BFS expansion (and report size) bounded on high-volume tools.
MAX_ARTIFACTS_PER_TOOL = 15

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


def _parse_found_accounts(output: str, username: str, tool_name: str, confidence: float) -> List[Dict[str, Any]]:
    """Parse '[+] Platform: url' lines shared by sherlock and maigret."""
    artifacts = []
    seen = set()

    for line in output.splitlines():
        match = FOUND_ACCOUNT_PATTERN.match(line.strip())
        if not match:
            continue

        platform = match.group("platform").strip()
        url = match.group("url").strip()
        if url in seen:
            continue
        seen.add(url)

        artifacts.append({
            "type": "username_presence",
            "value": url,
            "platform": platform,
            "username": username,
            "source": tool_name,
            "confidence": confidence,
        })

        if len(artifacts) >= MAX_ARTIFACTS_PER_TOOL:
            break

    return artifacts


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
            result.artifacts_discovered = _parse_found_accounts(
                result.output, username, "sherlock", confidence=0.8
            )
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
        """Search for username across the top Maigret sites."""
        command = [
            "maigret", username,
            "--top-sites", "150",
            "--timeout", "5",
            "--no-progressbar",
            "--no-color",
            "--no-recursion",
        ]
        result = self.run_tool("maigret", command)

        if result.success:
            result.artifacts_discovered = _parse_found_accounts(
                result.output, username, "maigret", confidence=0.75
            )
            result.parsed_data = {
                "username": username,
                "platforms": {a["platform"]: a["value"] for a in result.artifacts_discovered},
            }
            logger.info(f"Maigret found {len(result.artifacts_discovered)} platforms for {username}")

        return result


def _parse_email_accounts(output: str, email: str) -> List[Dict[str, Any]]:
    """Parse the '[+] service.tld' lines holehe emits for used accounts."""
    artifacts = []
    seen = set()

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("[+]"):
            continue

        platform = line[3:].strip()
        if not platform or " " in platform or platform in seen:
            continue
        seen.add(platform)

        artifacts.append({
            # Platform-qualified so each account is a distinct artifact; a bare
            # email would collapse every hit into a single graph node.
            "type": "email_presence",
            "value": f"{platform}:{email}",
            "platform": platform,
            "username": email,
            "source": "holehe",
            "confidence": 0.8,
        })

        if len(artifacts) >= MAX_ARTIFACTS_PER_TOOL:
            break

    return artifacts


class HoleheIntegration(ExternalToolsIntegration):
    """Integration for Holehe email account discovery."""

    @skip_if_not_available("holehe")
    def check_email(self, email: str) -> ToolResult:
        """Discover which services an email address is registered on."""
        command = ["holehe", email, "--only-used", "--no-color"]
        result = self.run_tool("holehe", command)

        if result.success:
            result.artifacts_discovered.extend(_parse_email_accounts(result.output, email))
            logger.info(f"Holehe found {len(result.artifacts_discovered)} accounts for {email}")

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

        result.artifacts_discovered = _parse_usufy_profiles(profiles, username)
        result.parsed_data = {"username": username, "profiles": profiles}
        logger.info(
            "OSRFramework found %d profiles for %s",
            len(result.artifacts_discovered), username,
        )

        return result


def _parse_usufy_profiles(profiles: Any, username: str) -> List[Dict[str, Any]]:
    """Turn usufy's i3visio entity list into username_presence artifacts.

    Each profile carries its URI, alias and platform as sibling attributes
    tagged with a "com.i3visio.*" type rather than as named fields.
    """
    artifacts = []
    seen = set()

    if not isinstance(profiles, list):
        return artifacts

    for profile in profiles:
        attributes = profile.get("attributes", []) if isinstance(profile, dict) else []
        values = {
            attribute.get("type"): attribute.get("value")
            for attribute in attributes
            if isinstance(attribute, dict)
        }

        url = values.get("com.i3visio.URI")
        if not url or url in seen:
            continue
        seen.add(url)

        artifacts.append({
            "type": "username_presence",
            "value": url,
            "platform": values.get("com.i3visio.Platform", "unknown"),
            "username": values.get("com.i3visio.Alias", username),
            "source": "osrframework",
            "confidence": 0.7,
        })

        if len(artifacts) >= MAX_ARTIFACTS_PER_TOOL:
            break

    return artifacts


class TheHarvesterIntegration(ExternalToolsIntegration):
    """Integration for theHarvester OSINT tool."""

    def __init__(self):
        super().__init__()
        # One theHarvester run yields both the emails and the subdomains, so the
        # two analyses share a single subprocess per domain instead of issuing
        # the identical command twice.
        self._runs: Dict[str, ToolResult] = {}
        self._runs_lock = threading.Lock()

    def _harvest(self, domain: str) -> ToolResult:
        """Run theHarvester once per domain and memoize its raw output."""
        with self._runs_lock:
            cached = self._runs.get(domain)
            if cached is not None:
                return cached

            command = ["theHarvester", "-d", domain, "-b", "duckduckgo"]
            result = self.run_tool("theharvester", command)
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

    @skip_if_not_available("theharvester")
    def harvest_email(self, domain: str) -> ToolResult:
        """Harvest emails from domain using theHarvester."""
        result = self._fresh_result(domain)
        
        if result.success:
            # Extract email addresses from output
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            harvested = self.extract_artifacts_from_text(
                result.output,
                {"email": email_pattern}
            )
            
            # Remove duplicates
            seen_emails = set()
            unique_artifacts = []
            for artifact in harvested:
                if artifact["value"] not in seen_emails:
                    seen_emails.add(artifact["value"])
                    artifact["source"] = "theharvester"
                    artifact["confidence"] = 0.8
                    unique_artifacts.append(artifact)
            
            result.artifacts_discovered = unique_artifacts[:MAX_ARTIFACTS_PER_TOOL]
            logger.info(f"theHarvester found {len(result.artifacts_discovered)} emails for {domain}")
        
        return result
    
    @skip_if_not_available("theharvester")
    def harvest_subdomains(self, domain: str) -> ToolResult:
        """Harvest subdomains using theHarvester."""
        result = self._fresh_result(domain)
        
        if result.success:
            result.artifacts_discovered = _parse_subdomains(result.output, domain, "theharvester")
            
            logger.info(f"theHarvester found {len(result.artifacts_discovered)} subdomains for {domain}")
        
        return result


class SubfinderIntegration(ExternalToolsIntegration):
    """Integration for subfinder passive subdomain enumeration."""

    @skip_if_not_available("subfinder")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains using subfinder."""
        command = ["subfinder", "-d", domain, "-silent", "-timeout", "10"]
        result = self.run_tool("subfinder", command)

        if result.success:
            result.artifacts_discovered = _parse_subdomains(result.output, domain, "subfinder")
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
            result.artifacts_discovered = _parse_subdomains(result.output, domain, "sublist3r")
            logger.info(f"Sublist3r found {len(result.artifacts_discovered)} subdomains for {domain}")

        return result


class WhatWebIntegration(ExternalToolsIntegration):
    """Integration for WhatWeb technology fingerprinting."""

    @skip_if_not_available("whatweb")
    def fingerprint(self, target: str) -> ToolResult:
        """Fingerprint the web technologies served by a domain or host."""
        command = ["whatweb", "--color=never", "--no-errors", "-a", "1", target]
        result = self.run_tool("whatweb", command)

        if result.success:
            technologies = set()
            addresses = set()

            for plugin, detail in re.findall(r"([A-Za-z0-9_-]+)\[([^\]]*)\]", result.output):
                if plugin == "IP":
                    addresses.add(detail)
                elif plugin in ("Country", "RedirectLocation", "Cookies", "HttpOnly"):
                    continue
                else:
                    technologies.add(f"{plugin}[{detail}]" if detail else plugin)

            for address in addresses:
                result.artifacts_discovered.append({
                    "type": "ip_address",
                    "value": address,
                    "source": "whatweb",
                    "confidence": 0.85,
                })

            for technology in sorted(technologies)[:MAX_ARTIFACTS_PER_TOOL]:
                result.artifacts_discovered.append({
                    "type": "web_technology",
                    "value": technology,
                    "target": target,
                    "source": "whatweb",
                    "confidence": 0.8,
                })

            result.parsed_data = {"technologies": sorted(technologies), "addresses": sorted(addresses)}
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
            result.parsed_data = self.parse_json_output(result.output)
            ports = result.parsed_data.get("ports", []) if result.parsed_data else []

            if not result.parsed_data:
                # The CLI prints a human-readable summary rather than JSON
                summary = {}
                for key, pattern in (
                    ("organization", r"Organization:\s*(.+)"),
                    ("country", r"Country:\s*(.+)"),
                    ("city", r"City:\s*(.+)"),
                    ("operating_system", r"Operating System:\s*(.+)"),
                ):
                    match = re.search(pattern, result.output)
                    if match:
                        summary[key] = match.group(1).strip()
                result.parsed_data = summary
                ports = re.findall(r"^(\d+)/(?:tcp|udp)", result.output, re.MULTILINE)

            if result.parsed_data or ports:
                result.artifacts_discovered.append({
                    "type": "host_info",
                    "value": ip_address,
                    "data": result.parsed_data,
                    "source": "shodan",
                    "confidence": 0.9
                })

                for port in ports:
                    result.artifacts_discovered.append({
                        "type": "open_port",
                        "value": f"{ip_address}:{port}",
                        "source": "shodan",
                        "confidence": 0.95
                    })
                
                logger.info(f"Shodan found info for {ip_address}: {len(result.artifacts_discovered)} artifacts")
        
        return result


def _parse_subdomains(output: str, domain: str, tool_name: str) -> List[Dict[str, Any]]:
    """Extract unique subdomains of ``domain`` from tool output."""
    pattern = re.compile(
        r"(?<![\w.%-])((?:[a-zA-Z0-9_-]+\.)+" + re.escape(domain) + r")(?![\w-])",
        re.IGNORECASE,
    )
    artifacts = []
    seen = set()

    for match in pattern.findall(output):
        subdomain = match.lower().strip(".")
        if subdomain in seen or subdomain == domain.lower():
            continue
        seen.add(subdomain)

        artifacts.append({
            "type": "subdomain",
            "value": subdomain,
            "domain": domain,
            "source": tool_name,
            "confidence": 0.85,
        })

        if len(artifacts) >= MAX_ARTIFACTS_PER_TOOL:
            break

    return artifacts


class AmassIntegration(ExternalToolsIntegration):
    """Integration for Amass subdomain enumeration."""
    
    @skip_if_not_available("amass")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains using Amass."""
        command = ["amass", "enum", "-passive", "-d", domain]
        result = self.run_tool("amass", command)
        
        if result.success:
            result.artifacts_discovered = _parse_subdomains(result.output, domain, "amass")
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
            # Extract key information from whois output
            patterns = {
                "registrar": r'Registrar:\s*(.+)',
                "creation_date": r'Creation Date:\s*(.+)',
                "expiration_date": r'Expiration Date:\s*(.+)',
                "name_server": r'Name Server:\s*(.+)',
                "registrant_email": r'Registrant Email:\s*(.+)',
            }
            
            for field, pattern in patterns.items():
                matches = re.findall(pattern, result.output, re.IGNORECASE)
                if matches:
                    result.parsed_data[field] = matches[0].strip()
            
            # Create artifact with domain information
            result.artifacts_discovered.append({
                "type": "domain_info",
                "value": domain,
                "data": result.parsed_data,
                "source": "whois",
                "confidence": 0.95
            })
            
            logger.info(f"Whois lookup completed for {domain}")
        
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

        if ports == "common":
            command = ["nmap", "-Pn", "-F", "-sV", "--version-light", target]
        else:
            command = ["nmap", "-Pn", "-p", ports, "-sV", "--version-light", target]
        
        result = self.run_tool("nmap", command)
        
        if result.success:
            # Parse Nmap output for open ports and services
            port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)'
            matches = re.findall(port_pattern, result.output)
            
            for port, protocol, service, version in matches:
                result.artifacts_discovered.append({
                    "type": "open_port",
                    "value": f"{target}:{port}",
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "source": "nmap",
                    "confidence": 0.9
                })
            
            logger.info(f"Nmap found {len(result.artifacts_discovered)} open ports on {target}")
        
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
            result.parsed_data = self.parse_json_output(result.output)
            
            if result.parsed_data and isinstance(result.parsed_data, list):
                metadata = result.parsed_data[0] if result.parsed_data else {}
                
                # Extract GPS coordinates if available
                if "GPSLatitude" in metadata and "GPSLongitude" in metadata:
                    result.artifacts_discovered.append({
                        "type": "gps_coordinates",
                        "value": f"{metadata['GPSLatitude']}, {metadata['GPSLongitude']}",
                        "source": "exiftool",
                        "confidence": 0.9
                    })
                
                # Extract camera information
                if "Make" in metadata or "Model" in metadata:
                    result.artifacts_discovered.append({
                        "type": "camera_info",
                        "value": f"{metadata.get('Make', '')} {metadata.get('Model', '')}",
                        "source": "exiftool",
                        "confidence": 0.9
                    })
                
                # Extract creation date
                if "CreateDate" in metadata:
                    result.artifacts_discovered.append({
                        "type": "creation_date",
                        "value": metadata["CreateDate"],
                        "source": "exiftool",
                        "confidence": 0.9
                    })
                
                logger.info(f"ExifTool extracted {len(result.artifacts_discovered)} artifacts from {file_path}")
        
        return result


class WaybackMachineIntegration(ExternalToolsIntegration):
    """Integration for Wayback Machine historical data."""
    
    def get_historical_urls(self, domain: str) -> ToolResult:
        """Get historical URLs from Wayback Machine using their API."""
        import requests
        
        result = ToolResult(tool_name="wayback_machine", success=False, output="")
        
        try:
            # Use Wayback Machine CDX API
            url = (
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
                f"&fl=timestamp,original,statuscode,mimetype&collapse=urlkey"
                f"&limit={MAX_ARTIFACTS_PER_TOOL}"
            )
            with io_slot():
                response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                result.success = True
                result.output = response.text
                
                # Parse JSON response
                data = response.json()
                if len(data) > 1:  # First row is headers
                    for row in data[1:]:
                        timestamp, original_url, status, mime_type = row
                        result.artifacts_discovered.append({
                            "type": "historical_url",
                            "value": original_url,
                            "timestamp": timestamp,
                            "status_code": status,
                            "mime_type": mime_type,
                            "source": "wayback_machine",
                            "confidence": 0.8
                        })
                    
                    logger.info(f"Wayback Machine found {len(result.artifacts_discovered)} historical URLs for {domain}")
            else:
                result.error_message = f"API request failed: {response.status_code}"
                
        except Exception as e:
            result.error_message = f"Wayback Machine error: {str(e)}"
            logger.error(f"Wayback Machine error: {e}")
        
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
    "maigret": ["username_presence"],
    "holehe": ["email_presence"],
    "osrframework": ["username_presence"],
    "theharvester": ["email", "subdomain"],
    "subfinder": ["subdomain"],
    "sublist3r": ["subdomain"],
    "whatweb": ["ip_address", "web_technology"],
    "shodan": ["host_info", "open_port"],
    "amass": ["subdomain"],
    "whois": ["domain_info"],
    "nmap": ["open_port"],
    "exiftool": ["gps_coordinates", "camera_info", "creation_date"],
    "wayback_machine": ["historical_url"],
    "leakosint": ["leak_record"],
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

"""
External OSINT Tools Integration Module

This module integrates external OSINT tools installed in the VM environment
with the Ghost Identity Hunter investigation pipeline, providing unified
access to tool outputs and results.
"""

import subprocess
import json
import logging
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from src.config.loader import get_config
from src.utils.tool_checker import check_tool_availability, skip_if_not_available

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


# The CDX API happily returns tens of thousands of rows for a busy domain;
# only the first slice is turned into artifacts.
MAX_WAYBACK_URLS = 100

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Matches the "[+] <Site>: <url>" lines printed by sherlock and maigret.
_FOUND_LINE_RE = re.compile(r"^\s*\[\+\]\s*([^:]+):\s*(https?://\S+)\s*$")


def _parse_found_lines(output: str) -> List[tuple]:
    """Extract ``(site, url)`` pairs from sherlock/maigret "found" output."""
    found = []
    seen = set()
    for line in output.splitlines():
        match = _FOUND_LINE_RE.match(line)
        if not match:
            continue
        site, url = match.group(1).strip(), match.group(2).strip()
        if url in seen:
            continue
        seen.add(url)
        found.append((site, url))
    return found


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


class SherlockIntegration(ExternalToolsIntegration):
    """Integration for Sherlock username search tool."""
    
    @skip_if_not_available("sherlock")
    def search_username(self, username: str) -> ToolResult:
        """Search for username across social networks using Sherlock.

        Sherlock reports hits on stdout as ``[+] <Site>: <url>`` lines; those
        are parsed into ``username_presence`` artifacts carrying the platform
        name and profile URL so they can be folded into the platform presence
        matrix.
        """
        command = [
            "sherlock", username,
            # --no-txt keeps sherlock from writing a <username>.txt result file
            # into the working directory; findings are parsed from stdout.
            "--print-found", "--no-color", "--no-txt", "--timeout", "10",
        ]
        result = self.run_tool("sherlock", command)

        # Sherlock returns a non-zero exit code when some sites error out, so
        # findings are parsed regardless of the exit status.
        for platform, url in _parse_found_lines(result.output):
            result.artifacts_discovered.append({
                "type": "username_presence",
                "value": username,
                "platform": platform,
                "profile_url": url,
                "source": "sherlock",
                "confidence": 0.8,
            })

        result.success = result.success or bool(result.artifacts_discovered)
        result.parsed_data = {
            "username": username,
            "platforms": [a["platform"] for a in result.artifacts_discovered],
        }
        logger.info("Sherlock found %d platforms for %s",
                    len(result.artifacts_discovered), username)
        return result


class MaigretIntegration(ExternalToolsIntegration):
    """Integration for Maigret username search tool."""

    @skip_if_not_available("maigret")
    def search_username(self, username: str) -> ToolResult:
        """Search for username across sites using Maigret."""
        # maigret prints found accounts by default; --print-not-found would be
        # the opt-in for the noisy variant.
        command = [
            "maigret", username,
            "--no-color", "--no-progressbar",
            "--timeout", "10", "--top-sites", "150",
        ]
        result = self.run_tool("maigret", command)

        # Maigret exits non-zero on partial failures but still prints findings.
        for platform, url in _parse_found_lines(result.output):
            result.artifacts_discovered.append({
                "type": "username_presence",
                "value": username,
                "platform": platform,
                "profile_url": url,
                "source": "maigret",
                "confidence": 0.8,
            })

        result.success = result.success or bool(result.artifacts_discovered)
        result.parsed_data = {
            "username": username,
            "platforms": [a["platform"] for a in result.artifacts_discovered],
        }
        logger.info("Maigret found %d platforms for %s",
                    len(result.artifacts_discovered), username)
        return result


class HoleheIntegration(ExternalToolsIntegration):
    """Integration for holehe email account discovery."""

    @skip_if_not_available("holehe")
    def check_email(self, email: str) -> ToolResult:
        """Check which services an email address is registered on."""
        command = ["holehe", "--only-used", "--no-color", email]
        result = self.run_tool("holehe", command)

        for line in result.output.splitlines():
            line = line.strip()
            if not line.startswith("[+]"):
                continue
            service = line[3:].strip()
            if not service or " " in service or "." not in service:
                continue
            result.artifacts_discovered.append({
                "type": "email_account",
                "value": f"{email}@{service}",
                "platform": service,
                "email": email,
                "source": "holehe",
                "confidence": 0.85,
            })

        result.success = result.success or bool(result.artifacts_discovered)
        result.parsed_data = {
            "email": email,
            "services": [a["platform"] for a in result.artifacts_discovered],
        }
        logger.info("holehe found %d registered services for %s",
                    len(result.artifacts_discovered), email)
        return result


class SubfinderIntegration(ExternalToolsIntegration):
    """Integration for subfinder passive subdomain enumeration."""

    @skip_if_not_available("subfinder")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains passively using subfinder."""
        command = ["subfinder", "-d", domain, "-silent"]
        result = self.run_tool("subfinder", command)

        seen: set = set()
        for line in result.output.splitlines():
            candidate = line.strip()
            if not candidate or not candidate.endswith(domain) or candidate in seen:
                continue
            seen.add(candidate)
            result.artifacts_discovered.append({
                "type": "subdomain",
                "value": candidate,
                "source": "subfinder",
                "confidence": 0.9,
            })

        logger.info("subfinder found %d subdomains for %s",
                    len(result.artifacts_discovered), domain)
        return result


class TheHarvesterIntegration(ExternalToolsIntegration):
    """Integration for theHarvester OSINT tool."""
    
    @skip_if_not_available("theharvester")
    def harvest_email(self, domain: str) -> ToolResult:
        """Harvest emails from domain using theHarvester."""
        command = ["theHarvester", "-d", domain, "-b", "google", "-e", "all"]
        result = self.run_tool("theharvester", command)
        
        if result.success:
            # Extract email addresses from output
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            result.artifacts_discovered = self.extract_artifacts_from_text(
                result.output,
                {"email": email_pattern}
            )
            
            # Remove duplicates
            seen_emails = set()
            unique_artifacts = []
            for artifact in result.artifacts_discovered:
                if artifact["value"] not in seen_emails:
                    seen_emails.add(artifact["value"])
                    unique_artifacts.append(artifact)
            
            result.artifacts_discovered = unique_artifacts
            logger.info(f"theHarvester found {len(result.artifacts_discovered)} emails for {domain}")
        
        return result
    
    @skip_if_not_available("theharvester")
    def harvest_subdomains(self, domain: str) -> ToolResult:
        """Harvest subdomains using theHarvester."""
        command = ["theHarvester", "-d", domain, "-b", "google", "-h", "all"]
        result = self.run_tool("theharvester", command)
        
        if result.success:
            # Extract subdomains from output
            subdomain_pattern = r'[a-zA-Z0-9.-]+\.' + re.escape(domain)
            result.artifacts_discovered = self.extract_artifacts_from_text(
                result.output,
                {"subdomain": subdomain_pattern}
            )
            
            logger.info(f"theHarvester found {len(result.artifacts_discovered)} subdomains for {domain}")
        
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
            
            if result.parsed_data:
                # Extract key information
                result.artifacts_discovered.append({
                    "type": "host_info",
                    "value": ip_address,
                    "data": result.parsed_data,
                    "source": "shodan",
                    "confidence": 0.9
                })
                
                # Extract open ports
                if "ports" in result.parsed_data:
                    for port in result.parsed_data["ports"]:
                        result.artifacts_discovered.append({
                            "type": "open_port",
                            "value": f"{ip_address}:{port}",
                            "source": "shodan",
                            "confidence": 0.95
                        })
                
                logger.info(f"Shodan found info for {ip_address}: {len(result.artifacts_discovered)} artifacts")
        
        return result


class AmassIntegration(ExternalToolsIntegration):
    """Integration for Amass subdomain enumeration."""
    
    @skip_if_not_available("amass")
    def enumerate_subdomains(self, domain: str) -> ToolResult:
        """Enumerate subdomains using Amass."""
        command = ["amass", "enum", "-passive", "-d", domain]
        result = self.run_tool("amass", command)
        
        if result.success:
            # Extract subdomains from output
            subdomain_pattern = r'[a-zA-Z0-9.-]+\.' + re.escape(domain)
            result.artifacts_discovered = self.extract_artifacts_from_text(
                result.output,
                {"subdomain": subdomain_pattern}
            )
            
            # Remove duplicates
            seen_subdomains = set()
            unique_artifacts = []
            for artifact in result.artifacts_discovered:
                if artifact["value"] not in seen_subdomains:
                    seen_subdomains.add(artifact["value"])
                    unique_artifacts.append(artifact)
            
            result.artifacts_discovered = unique_artifacts
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


class DigIntegration(ExternalToolsIntegration):
    """Integration for DNS dig tool."""
    
    @skip_if_not_available("dig")
    def dns_lookup(self, domain: str, record_type: str = "A") -> ToolResult:
        """Perform DNS lookup using dig."""
        command = ["dig", domain, record_type, "+short"]
        result = self.run_tool("dig", command)
        
        if result.success:
            # Extract DNS records from output
            records = [line.strip() for line in result.output.split('\n') if line.strip()]
            
            for record in records:
                result.artifacts_discovered.append({
                    "type": f"dns_{record_type.lower()}",
                    "value": record,
                    "domain": domain,
                    "source": "dig",
                    "confidence": 0.95
                })

                # An A record resolves to an address; surface it as an
                # ip_address artifact so the host-oriented tools (Shodan,
                # Nmap) actually have an input to work from.
                if record_type.upper() == "A" and _IPV4_RE.match(record):
                    result.artifacts_discovered.append({
                        "type": "ip_address",
                        "value": record,
                        "domain": domain,
                        "source": "dig",
                        "confidence": 0.9,
                    })
            
            logger.info(f"Dig found {len(result.artifacts_discovered)} {record_type} records for {domain}")
        
        return result


class NmapIntegration(ExternalToolsIntegration):
    """Integration for Nmap network scanner."""
    
    @skip_if_not_available("nmap")
    def scan_host(self, target: str, ports: str = "common") -> ToolResult:
        """Scan host using Nmap."""
        if ports == "common":
            # Top-100 ports with a fast timing template keeps a scan inside the
            # configured per-tool budget; a full -sC/-sV sweep does not.
            command = ["nmap", "-Pn", "-T4", "--top-ports", "100", "-sV", target]
        else:
            command = ["nmap", "-Pn", "-T4", "-p", ports, "-sV", target]
        
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
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
                f"&output=json&fl=timestamp,original,statuscode,mimetype"
                f"&limit={MAX_WAYBACK_URLS}"
            )
            response = requests.get(url, timeout=_get_tool_timeout("wayback_machine", 30))
            
            if response.status_code == 200:
                result.success = True
                result.output = response.text
                
                # Parse JSON response
                data = response.json()
                if len(data) > 1:  # First row is headers
                    for row in data[1:MAX_WAYBACK_URLS + 1]:
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
_theharvester = TheHarvesterIntegration()
_shodan = ShodanIntegration()
_amass = AmassIntegration()
_whois = WhoisIntegration()
_dig = DigIntegration()
_nmap = NmapIntegration()
_exiftool = ExifToolIntegration()
_wayback = WaybackMachineIntegration()
_maigret = MaigretIntegration()
_holehe = HoleheIntegration()
_subfinder = SubfinderIntegration()


def get_tool_integrations() -> Dict[str, ExternalToolsIntegration]:
    """Get all available tool integrations."""
    return {
        "sherlock": _sherlock,
        "theharvester": _theharvester,
        "shodan": _shodan,
        "amass": _amass,
        "whois": _whois,
        "dig": _dig,
        "nmap": _nmap,
        "exiftool": _exiftool,
        "wayback_machine": _wayback,
        "maigret": _maigret,
        "holehe": _holehe,
        "subfinder": _subfinder,
    }


# Maps (tool, analysis type) to the unbound integration method implementing it.
# Unbound methods are used so building the table never touches an unrelated
# integration instance (binding them eagerly made every dispatch fail with an
# AttributeError for the methods the selected integration does not define).
ANALYSIS_METHODS = {
    "sherlock": {
        "username_search": SherlockIntegration.search_username,
    },
    "maigret": {
        "username_search": MaigretIntegration.search_username,
    },
    "theharvester": {
        "email_harvest": TheHarvesterIntegration.harvest_email,
        "subdomain_harvest": TheHarvesterIntegration.harvest_subdomains,
    },
    "holehe": {
        "email_accounts": HoleheIntegration.check_email,
    },
    "shodan": {
        "host_search": ShodanIntegration.search_host,
    },
    "amass": {
        "subdomain_enum": AmassIntegration.enumerate_subdomains,
    },
    "subfinder": {
        "subdomain_enum": SubfinderIntegration.enumerate_subdomains,
    },
    "whois": {
        "domain_lookup": WhoisIntegration.lookup_domain,
    },
    "dig": {
        "dns_lookup": DigIntegration.dns_lookup,
    },
    "nmap": {
        "host_scan": NmapIntegration.scan_host,
    },
    "exiftool": {
        "metadata_extract": ExifToolIntegration.extract_metadata,
    },
    "wayback_machine": {
        "historical_urls": WaybackMachineIntegration.get_historical_urls,
    },
}


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
    integrations = get_tool_integrations()
    
    if tool_name not in integrations:
        logger.error(f"Unknown tool integration: {tool_name}")
        return ToolResult(
            tool_name=tool_name, success=False, output="", error_message="Unknown tool"
        )
    
    integration = integrations[tool_name]

    methods = ANALYSIS_METHODS.get(tool_name, {})
    if analysis_type not in methods:
        logger.error(f"Unknown analysis type: {analysis_type} for tool: {tool_name}")
        return ToolResult(
            tool_name=tool_name, success=False, output="",
            error_message="Unknown analysis type",
        )

    result = methods[analysis_type](integration, target)
    # The availability decorator returns None when the tool is not installed.
    if result is None:
        return ToolResult(
            tool_name=tool_name,
            success=False,
            output="",
            error_message=f"{tool_name} is not installed",
        )
    return result

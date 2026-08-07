"""
Tool availability checker for OSINT tools.

This module provides functionality to detect if external OSINT tools
are installed on the system and gracefully handle missing dependencies.
"""

import os
import shutil
import subprocess
import logging
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Status of tool availability."""
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"
    PERMISSION_DENIED = "permission_denied"
    ERROR = "error"


@dataclass
class ToolInfo:
    """Information about an OSINT tool."""
    name: str
    command: str
    description: str
    status: ToolStatus = ToolStatus.NOT_INSTALLED
    version: Optional[str] = None
    error_message: Optional[str] = None
    api_based: bool = False  # Reached over HTTP, so no local command is required
    # Environment variables the HTTP API's credential may be stored in; when set,
    # the tool counts as available only once one of them (or the configured
    # api_key) holds a value.
    api_key_envs: tuple = ()
    # Whether availability has already been resolved this process run. Used to
    # memoize check_tool so the `<tool> --version` subprocess runs at most once
    # per tool (it is otherwise invoked per-artifact per-tool inside the BFS loop).
    checked: bool = False


def _api_credential_present(tool_name: str, env_names: tuple) -> bool:
    """Whether an API-based tool's credential is configured.

    Checked in the same order the integrations resolve it: the tool's
    ``plugins.<tool>.api_key`` entry first, then the environment variables.
    """
    try:
        from src.config.loader import get_config
        configured = ((get_config().get("plugins", {}) or {}).get(tool_name) or {}).get("api_key")
        if configured and str(configured).strip():
            return True
    except Exception as exc:
        logger.debug("API key config lookup failed for %s: %s", tool_name, exc)
    return any(os.environ.get(name, "").strip() for name in env_names)


class ToolChecker:
    """Check availability of external OSINT tools."""
    
    def __init__(self):
        self.tools: Dict[str, ToolInfo] = {}
        # Guards the memoization cache so concurrent BFS workers resolve each
        # tool's availability exactly once.
        self._lock = threading.Lock()
        self._initialize_common_tools()
    
    def _initialize_common_tools(self):
        """Initialize comprehensive OSINT tools to check."""
        common_tools = [
            # Username Search Tools
            ToolInfo(name="sherlock", command="sherlock", description="Find usernames across social networks"),
            ToolInfo(name="maigret", command="maigret", description="Username search across multiple platforms"),
            ToolInfo(name="social_analyzer", command="social-analyzer", description="Social media username analysis"),
            
            # Email Investigation Tools
            ToolInfo(name="holehe", command="holehe", description="Email investigation and account discovery"),
            ToolInfo(name="emailharvester", command="EmailHarvester", description="Email harvesting from domains"),
            ToolInfo(name="theharvester", command="theHarvester", description="Email, subdomain and people harvesting"),
            
            # Domain and DNS Tools
            ToolInfo(name="whois", command="whois", description="Domain and IP ownership information"),
            ToolInfo(name="dig", command="dig", description="DNS lookup utility"),
            ToolInfo(name="amass", command="amass", description="Attack surface discovery and enumeration"),
            ToolInfo(name="subfinder", command="subfinder", description="Fast subdomain enumeration"),
            ToolInfo(name="sublist3r", command="sublist3r", description="Fast subdomains enumeration tool"),
            
            # Network Scanning Tools
            ToolInfo(name="nmap", command="nmap", description="Network mapper and security scanner"),
            ToolInfo(name="masscan", command="masscan", description="Mass IP port scanner"),
            ToolInfo(name="whatweb", command="whatweb", description="Web technology identification"),
            ToolInfo(name="wappalyzer", command="wappalyzer", description="Web technology detection"),
            
            # OSINT Frameworks
            ToolInfo(name="recon-ng", command="recon-ng", description="Web reconnaissance framework"),
            ToolInfo(name="spiderfoot", command="spiderfoot", description="Open source intelligence automation"),
            # OSRFramework installs per-utility entrypoints; usufy is the one integrated.
            ToolInfo(name="osrframework", command="usufy", description="Open Sources Research Framework"),
            
            # Specialized Investigation Tools
            ToolInfo(name="shodan", command="shodan", description="Search engine for Internet-connected devices"),
            ToolInfo(name="ghunt", command="ghunt", description="Google account investigation tool"),
            ToolInfo(name="photon", command="photon", description="Web crawler for OSINT"),
            ToolInfo(name="metagoofil", command="metagoofil", description="Metadata extraction from documents"),
            
            # Image and Metadata Tools
            ToolInfo(name="exiftool", command="exiftool", description="Read and write file metadata"),
            
            # Historical and Archive Tools
            ToolInfo(name="wayback_machine", command="wayback_machine", description="Historical web data access", api_based=True),
            
            # Blockchain and Crypto Tools
            ToolInfo(name="etherscan", command="etherscan", description="Blockchain investigation tool"),

            # Breach Data Tools
            ToolInfo(name="leakosint", command="leakosint",
                     description="Leaked-database record search (LeakOSINT API)",
                     api_based=True,
                     api_key_envs=("LEAKOSINT_API_TOKEN", "LEAKOSINT_API_KEY")),
            
            # Search and Dorking Tools
            ToolInfo(name="google_dorks", command="google_dorks", description="Google Dorks for advanced username discovery", api_based=True),
            
            # Geolocation Tools
            ToolInfo(name="geonames", command="geonames", description="Geographical database and search"),
            
            # Basic Network Tools
            ToolInfo(name="curl", command="curl", description="Command line tool for transferring data"),
            ToolInfo(name="wget", command="wget", description="Network downloader"),
            ToolInfo(name="nslookup", command="nslookup", description="DNS query utility"),
            
            # Security Tools
            ToolInfo(name="nikto", command="nikto", description="Web server scanner"),
            ToolInfo(name="sqlmap", command="sqlmap", description="Automatic SQL injection tool"),
            
            # Browser-based Tools (for reference, may not be directly integrable)
            ToolInfo(name="tor_browser", command="tor-browser", description="Anonymous web browser"),
            ToolInfo(name="flagfox", command="flagfox", description="Browser extension for geolocation"),
            ToolInfo(name="user_agent_switcher", command="user-agent-switcher", description="Browser extension for UA switching"),
        ]
        
        for tool in common_tools:
            self.tools[tool.name] = tool
    
    def check_tool(self, tool_name: str, force: bool = False) -> ToolInfo:
        """Check if a specific tool is available.

        The result is memoized in ``self.tools[tool_name]`` so the underlying
        ``shutil.which``/``--version`` subprocess runs at most once per process
        run. Pass ``force=True`` to re-resolve (e.g. after installing a tool).
        """
        if tool_name not in self.tools:
            logger.warning(f"Unknown tool: {tool_name}")
            return ToolInfo(
                name=tool_name,
                command=tool_name,
                description="Unknown tool",
                status=ToolStatus.ERROR,
                error_message="Tool not in known tools list"
            )
        
        tool = self.tools[tool_name]

        # Fast path: already resolved this run.
        if tool.checked and not force:
            return tool

        with self._lock:
            # Re-check under the lock in case another thread resolved it while
            # we were waiting.
            if tool.checked and not force:
                return tool
            return self._resolve_tool(tool)

    def _resolve_tool(self, tool: ToolInfo) -> ToolInfo:
        """Resolve a tool's availability and version (no caching logic)."""
        try:
            if tool.api_based and tool.api_key_envs:
                if _api_credential_present(tool.name, tool.api_key_envs):
                    tool.status = ToolStatus.AVAILABLE
                    tool.version = "HTTP API"
                else:
                    tool.status = ToolStatus.NOT_INSTALLED
                    tool.error_message = f"{tool.api_key_envs[0]} not configured"
            elif tool.api_based:
                tool.status = ToolStatus.AVAILABLE
                tool.version = "HTTP API"
            # Check if command exists
            elif shutil.which(tool.command):
                tool.status = ToolStatus.AVAILABLE
                # Try to get version
                try:
                    result = subprocess.run(
                        [tool.command, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        tool.version = result.stdout.split('\n')[0].strip()
                    else:
                        # Try alternative version command
                        result = subprocess.run(
                            [tool.command, "-v"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            tool.version = result.stdout.split('\n')[0].strip()
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
            else:
                tool.status = ToolStatus.NOT_INSTALLED
                tool.error_message = f"Command '{tool.command}' not found in PATH"
                
        except PermissionError:
            tool.status = ToolStatus.PERMISSION_DENIED
            tool.error_message = f"Permission denied checking tool '{tool.command}'"
        except Exception as e:
            tool.status = ToolStatus.ERROR
            tool.error_message = f"Error checking tool '{tool.command}': {str(e)}"

        tool.checked = True
        return tool
    
    def check_all_tools(self) -> Dict[str, ToolInfo]:
        """Check availability of all known tools."""
        for tool_name in self.tools:
            self.check_tool(tool_name)
        return self.tools
    
    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available for use."""
        tool_info = self.check_tool(tool_name)
        return tool_info.status == ToolStatus.AVAILABLE
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tool names."""
        available = []
        for tool_name, tool_info in self.check_all_tools().items():
            if tool_info.status == ToolStatus.AVAILABLE:
                available.append(tool_name)
        return available
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tool names."""
        missing = []
        for tool_name, tool_info in self.check_all_tools().items():
            if tool_info.status != ToolStatus.AVAILABLE:
                missing.append(tool_name)
        return missing
    
    def print_status(self):
        """Print status of all tools."""
        logger.info("OSINT Tool Availability Status:")
        logger.info("=" * 60)
        
        available_count = 0
        missing_count = 0
        
        for tool_name, tool_info in self.tools.items():
            status_symbol = "✓" if tool_info.status == ToolStatus.AVAILABLE else "✗"
            logger.info(f"{status_symbol} {tool_name:20s} - {tool_info.description}")
            
            if tool_info.status == ToolStatus.AVAILABLE:
                available_count += 1
                if tool_info.version:
                    logger.info(f"  Version: {tool_info.version}")
            else:
                missing_count += 1
                if tool_info.error_message:
                    logger.info(f"  Error: {tool_info.error_message}")
        
        logger.info("=" * 60)
        logger.info(f"Available: {available_count}/{len(self.tools)}")
        logger.info(f"Missing: {missing_count}/{len(self.tools)}")


# Global tool checker instance
_tool_checker = None


def get_tool_checker() -> ToolChecker:
    """Get the global tool checker instance."""
    global _tool_checker
    if _tool_checker is None:
        _tool_checker = ToolChecker()
    return _tool_checker


def check_tool_availability(tool_name: str) -> bool:
    """Convenience function to check if a tool is available."""
    return get_tool_checker().is_available(tool_name)


def skip_if_not_available(tool_name: str):
    """Decorator to skip function execution if tool is not available."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not check_tool_availability(tool_name):
                logger.info(f"Skipping {func.__name__}: {tool_name} not available")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator

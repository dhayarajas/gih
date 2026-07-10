"""
Tool availability checker for OSINT tools.

This module provides functionality to detect if external OSINT tools
are installed on the system and gracefully handle missing dependencies.
"""

import shutil
import subprocess
import logging
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


class ToolChecker:
    """Check availability of external OSINT tools."""
    
    def __init__(self):
        self.tools: Dict[str, ToolInfo] = {}
        self._initialize_common_tools()
    
    def _initialize_common_tools(self):
        """Initialize common OSINT tools to check."""
        common_tools = [
            ToolInfo(
                name="nmap",
                command="nmap",
                description="Network mapper and security scanner"
            ),
            ToolInfo(
                name="whois",
                command="whois",
                description="Domain and IP ownership information"
            ),
            ToolInfo(
                name="dig",
                command="dig",
                description="DNS lookup utility"
            ),
            ToolInfo(
                name="nslookup",
                command="nslookup",
                description="DNS query utility"
            ),
            ToolInfo(
                name="curl",
                command="curl",
                description="Command line tool for transferring data"
            ),
            ToolInfo(
                name="wget",
                command="wget",
                description="Network downloader"
            ),
            ToolInfo(
                name="theHarvester",
                command="theHarvester",
                description="E-mail, subdomain and people harvesting"
            ),
            ToolInfo(
                name="sherlock",
                command="sherlock",
                description="Find usernames across social networks"
            ),
            ToolInfo(
                name="maltego",
                command="maltego",
                description="Open source intelligence and graphical link analysis"
            ),
            ToolInfo(
                name="recon-ng",
                command="recon-ng",
                description="Web reconnaissance framework"
            ),
            ToolInfo(
                name="shodan",
                command="shodan",
                description="Search engine for Internet-connected devices"
            ),
            ToolInfo(
                name="sublist3r",
                command="sublist3r",
                description="Fast subdomains enumeration tool"
            ),
            ToolInfo(
                name="amass",
                command="amass",
                description="Attack surface discovery and enumeration"
            ),
            ToolInfo(
                name="masscan",
                command="masscan",
                description="Mass IP port scanner"
            ),
            ToolInfo(
                name="nikto",
                command="nikto",
                description="Web server scanner"
            ),
            ToolInfo(
                name="sqlmap",
                command="sqlmap",
                description="Automatic SQL injection tool"
            ),
        ]
        
        for tool in common_tools:
            self.tools[tool.name] = tool
    
    def check_tool(self, tool_name: str) -> ToolInfo:
        """Check if a specific tool is available."""
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
        
        try:
            # Check if command exists
            if shutil.which(tool.command):
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
        for tool_name, tool_info in self.tools.items():
            if tool_info.status == ToolStatus.AVAILABLE:
                available.append(tool_name)
        return available
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tool names."""
        missing = []
        for tool_name, tool_info in self.tools.items():
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

"""
Base plugin interface for OSINT tools.

All OSINT tool plugins must inherit from OSINTPlugin and implement
the required methods for tool execution and findings extraction.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class PluginStatus(Enum):
    """Status of plugin execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class PluginConfig:
    """Configuration for a plugin."""
    enabled: bool = True
    timeout: int = 30
    max_retries: int = 3
    api_key: Optional[str] = None
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Artifact:
    """An artifact discovered by OSINT investigation."""
    type: str  # username, email, phone, domain, url, etc.
    value: str
    source: str  # Which tool/plugin discovered this
    confidence: float = 0.5  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginResult:
    """Result from plugin execution."""
    plugin_name: str
    status: PluginStatus
    artifacts: List[Artifact] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class OSINTPlugin(ABC):
    """
    Abstract base class for OSINT tool plugins.
    
    All plugins must implement these methods to be compatible
    with the plugin system.
    """
    
    def __init__(self, config: Optional[PluginConfig] = None):
        """
        Initialize the plugin.
        
        Args:
            config: Plugin configuration (optional)
        """
        self.config = config or PluginConfig()
        self.name = self.__class__.__name__
    
    @abstractmethod
    def get_name(self) -> str:
        """
        Get the plugin name.
        
        Returns:
            Plugin name
        """
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """
        Get the plugin version.
        
        Returns:
            Plugin version string
        """
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """
        Get the plugin description.
        
        Returns:
            Plugin description
        """
        pass
    
    @abstractmethod
    def get_supported_artifact_types(self) -> List[str]:
        """
        Get the artifact types this plugin can process.
        
        Returns:
            List of artifact types (username, email, phone, domain, etc.)
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the plugin is available for execution.
        
        Returns:
            True if plugin can be executed, False otherwise
        """
        pass
    
    @abstractmethod
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute the plugin on an artifact.
        
        Args:
            artifact: The artifact to investigate
            
        Returns:
            PluginResult with discovered artifacts and metadata
        """
        pass
    
    def validate_artifact(self, artifact: Artifact) -> bool:
        """
        Validate that the artifact can be processed by this plugin.
        
        Args:
            artifact: The artifact to validate
            
        Returns:
            True if artifact is valid for this plugin
        """
        supported_types = self.get_supported_artifact_types()
        return artifact.type in supported_types
    
    def preprocess_artifact(self, artifact: Artifact) -> Artifact:
        """
        Preprocess artifact before execution.
        
        Args:
            artifact: The artifact to preprocess
            
        Returns:
            Preprocessed artifact
        """
        return artifact
    
    def postprocess_result(self, result: PluginResult) -> PluginResult:
        """
        Postprocess result after execution.
        
        Args:
            result: The result to postprocess
            
        Returns:
            Postprocessed result
        """
        return result
    
    def get_required_dependencies(self) -> List[str]:
        """
        Get the required dependencies for this plugin.
        
        Returns:
            List of required package names or commands
        """
        return []
    
    def get_optional_dependencies(self) -> List[str]:
        """
        Get the optional dependencies for this plugin.
        
        Returns:
            List of optional package names or commands
        """
        return []

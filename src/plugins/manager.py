"""
Plugin manager for executing OSINT tool plugins and managing results.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from .base import Artifact, OSINTPlugin, PluginConfig, PluginResult, PluginStatus
from .registry import PluginRegistry
from ..config import get_config

logger = logging.getLogger(__name__)


class PluginManager:
    """
    Manager for executing OSINT plugins and aggregating results.
    
    Handles plugin execution, error handling, and result aggregation.
    """
    
    def __init__(self, registry: Optional[PluginRegistry] = None):
        """
        Initialize the plugin manager.
        
        Args:
            registry: Plugin registry to use (default: global registry)
        """
        self.registry = registry or PluginRegistry()
        self._execution_stats: Dict[str, Dict] = {}
        self.config = get_config()
    
    def execute_plugin(
        self,
        plugin_name: str,
        artifact: Artifact,
        config: Optional[PluginConfig] = None
    ) -> PluginResult:
        """
        Execute a single plugin on an artifact.
        
        Args:
            plugin_name: Name of the plugin to execute
            artifact: Artifact to investigate
            config: Optional plugin configuration
            
        Returns:
            PluginResult with findings
        """
        # Check if plugin is enabled in configuration
        plugin_config = self.config.get_plugin_config(plugin_name)
        if not plugin_config.get("enabled", True):
            logger.debug(f"Plugin '{plugin_name}' is disabled in configuration")
            return PluginResult(
                plugin_name=plugin_name,
                status=PluginStatus.SKIPPED,
                error="Plugin disabled in configuration"
            )
        
        plugin = self.registry.get_plugin_instance(plugin_name)
        if not plugin:
            return PluginResult(
                plugin_name=plugin_name,
                status=PluginStatus.FAILURE,
                error=f"Plugin not found: {plugin_name}"
            )
        
        if not plugin.is_available():
            return PluginResult(
                plugin_name=plugin_name,
                status=PluginStatus.SKIPPED,
                error=f"Plugin not available: {plugin_name}"
            )
        
        if not plugin.validate_artifact(artifact):
            return PluginResult(
                plugin_name=plugin_name,
                status=PluginStatus.SKIPPED,
                error=f"Artifact type not supported: {artifact.type}"
            )
        
        # Apply configuration settings
        if config is None:
            config = PluginConfig(
                enabled=plugin_config.get("enabled", True),
                timeout=plugin_config.get("timeout", 30),
                max_retries=plugin_config.get("max_retries", 3),
                api_key=plugin_config.get("api_key"),
                custom_params=plugin_config.get("custom_params", {})
            )
        
        plugin.config = config
        
        start_time = time.time()
        
        try:
            # Preprocess artifact
            processed_artifact = plugin.preprocess_artifact(artifact)
            
            # Execute plugin
            result = plugin.execute(processed_artifact)
            
            # Postprocess result
            result = plugin.postprocess_result(result)
            
            # Record execution time
            result.execution_time = time.time() - start_time
            
            # Update stats
            self._update_stats(plugin_name, result.status, result.execution_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Plugin execution failed for {plugin_name}: {e}")
            return PluginResult(
                plugin_name=plugin_name,
                status=PluginStatus.FAILURE,
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    def execute_plugins_for_artifact(
        self,
        artifact: Artifact,
        plugin_names: Optional[List[str]] = None,
        parallel: bool = True,
        max_workers: Optional[int] = None
    ) -> List[PluginResult]:
        """
        Execute multiple plugins on an artifact.
        
        Args:
            artifact: Artifact to investigate
            plugin_names: List of plugin names to execute (None for all compatible)
            parallel: Whether to execute plugins in parallel
            max_workers: Maximum number of parallel workers (None to use config)
            
        Returns:
            List of PluginResults
        """
        # Determine which plugins to execute
        if plugin_names is None:
            plugin_names = self.registry.get_plugins_by_artifact_type(artifact.type)
        
        if not plugin_names:
            logger.warning(f"No plugins available for artifact type: {artifact.type}")
            return []
        
        # Get max_workers from config if not specified
        if max_workers is None:
            plugin_settings = self.config.get("plugin_settings", {})
            max_workers = plugin_settings.get("max_parallel_workers", 50)
        
        results = []
        
        if parallel and len(plugin_names) > 1:
            # Execute in parallel
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        self.execute_plugin, 
                        plugin_name, 
                        artifact
                    ): plugin_name 
                    for plugin_name in plugin_names
                }
                
                for future in as_completed(futures):
                    plugin_name = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Parallel execution failed for {plugin_name}: {e}")
                        results.append(PluginResult(
                            plugin_name=plugin_name,
                            status=PluginStatus.FAILURE,
                            error=str(e)
                        ))
        else:
            # Execute sequentially
            for plugin_name in plugin_names:
                result = self.execute_plugin(plugin_name, artifact)
                results.append(result)
        
        return results
    
    def execute_plugins_for_artifacts(
        self,
        artifacts: List[Artifact],
        plugin_names: Optional[List[str]] = None,
        parallel: bool = True,
        max_workers: Optional[int] = None
    ) -> Dict[str, List[PluginResult]]:
        """
        Execute plugins on multiple artifacts.
        
        Args:
            artifacts: List of artifacts to investigate
            plugin_names: List of plugin names to execute (None for all compatible)
            parallel: Whether to execute in parallel
            max_workers: Maximum number of parallel workers (None to use config)
            
        Returns:
            Dictionary mapping artifact values to lists of PluginResults
        """
        # Get max_workers from config if not specified
        if max_workers is None:
            plugin_settings = self.config.get("plugin_settings", {})
            max_workers = plugin_settings.get("max_parallel_workers", 50)
        
        results = {}
        
        if parallel and len(artifacts) > 1:
            # Execute all artifacts in parallel
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        self.execute_plugins_for_artifact,
                        artifact,
                        plugin_names,
                        True,  # Enable parallel within each artifact too
                        max_workers
                    ): artifact.value
                    for artifact in artifacts
                }
                
                for future in as_completed(futures):
                    artifact_value = futures[future]
                    try:
                        artifact_results = future.result()
                        results[artifact_value] = artifact_results
                    except Exception as e:
                        logger.error(f"Parallel execution failed for artifact {artifact_value}: {e}")
                        results[artifact_value] = []
        else:
            # Execute sequentially
            for artifact in artifacts:
                artifact_results = self.execute_plugins_for_artifact(
                    artifact,
                    plugin_names,
                    parallel,
                    max_workers
                )
                results[artifact.value] = artifact_results
        
        return results
    
    def aggregate_findings(self, results: List[PluginResult]) -> List[Artifact]:
        """
        Aggregate artifacts from multiple plugin results.
        
        Args:
            results: List of PluginResults
            
        Returns:
            List of unique artifacts discovered
        """
        all_artifacts = []
        seen = set()
        
        for result in results:
            for artifact in result.artifacts:
                # Create unique key for deduplication
                key = (artifact.type, artifact.value, artifact.source)
                if key not in seen:
                    seen.add(key)
                    all_artifacts.append(artifact)
        
        return all_artifacts
    
    def get_execution_stats(self) -> Dict[str, Dict]:
        """
        Get execution statistics for all plugins.
        
        Returns:
            Dictionary of plugin execution stats
        """
        return self._execution_stats.copy()
    
    def get_plugin_stats(self, plugin_name: str) -> Dict:
        """
        Get execution statistics for a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Dictionary of plugin stats
        """
        return self._execution_stats.get(plugin_name, {})
    
    def _update_stats(self, plugin_name: str, status: PluginStatus, execution_time: float) -> None:
        """
        Update execution statistics for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            status: Execution status
            execution_time: Execution time in seconds
        """
        if plugin_name not in self._execution_stats:
            self._execution_stats[plugin_name] = {
                'total_executions': 0,
                'successful': 0,
                'failed': 0,
                'skipped': 0,
                'total_time': 0.0,
                'avg_time': 0.0
            }
        
        stats = self._execution_stats[plugin_name]
        stats['total_executions'] += 1
        stats['total_time'] += execution_time
        stats['avg_time'] = stats['total_time'] / stats['total_executions']
        
        if status == PluginStatus.SUCCESS:
            stats['successful'] += 1
        elif status == PluginStatus.FAILURE:
            stats['failed'] += 1
        elif status == PluginStatus.SKIPPED:
            stats['skipped'] += 1
    
    def reset_stats(self) -> None:
        """Reset all execution statistics."""
        self._execution_stats.clear()

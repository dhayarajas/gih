# Plugin Development Guide

## Overview

Ghost Identity Hunter uses a plugin architecture to integrate OSINT tools. This guide explains how to create custom plugins for new OSINT tools.

## Plugin Architecture

### Base Plugin Interface

All plugins must inherit from the `OSINTPlugin` base class:

```python
from src.plugins.base import OSINTPlugin, PluginResult

class MyCustomPlugin(OSINTPlugin):
    def __init__(self):
        super().__init__(
            name="my_custom_plugin",
            version="1.0.0",
            description="Description of what this plugin does",
            supported_artifacts=["username", "email"],  # Artifact types this plugin can process
            author="Your Name"
        )
    
    def execute(self, artifact: Artifact) -> PluginResult:
        """
        Execute the plugin on an artifact.
        
        Args:
            artifact: The artifact to investigate
            
        Returns:
            PluginResult with findings
        """
        # Your implementation here
        return PluginResult(
            plugin_name=self.name,
            artifact_value=artifact.value,
            success=True,
            findings=[],
            metadata={}
        )
```

### Plugin Result Structure

```python
@dataclass
class PluginResult:
    plugin_name: str
    artifact_value: str
    success: bool
    findings: list[dict]  # List of discovered artifacts
    metadata: dict  # Additional metadata about the execution
    error: Optional[str] = None
```

## Plugin Discovery

Plugins are automatically discovered from the `src/plugins/` directory. To create a new plugin:

1. Create a new file in `src/plugins/` (e.g., `my_plugin.py`)
2. Define your plugin class inheriting from `OSINTPlugin`
3. The plugin will be automatically discovered by the `PluginRegistry`

## Configuration

Plugin settings are managed in `config/config.yaml`:

```yaml
plugin_settings:
  parallel_execution: true
  max_parallel_workers: 50
  plugins:
    my_custom_plugin:
      enabled: true
      config:
        api_key: "your_api_key"
        timeout: 10
```

Access configuration in your plugin:

```python
from src.config.loader import get_config

config = get_config()
plugin_config = config.get("plugin_settings", {}).get("my_custom_plugin", {})
api_key = plugin_config.get("config", {}).get("api_key")
```

## Artifact Types

Supported artifact types:
- `username`: Social media usernames
- `email`: Email addresses
- `phone`: Phone numbers
- `image`: Image files/URLs
- `fullname`: Full names

## Example: Username Search Plugin

```python
from typing import Optional
from src.plugins.base import OSINTPlugin, PluginResult, Artifact
import requests

class MyPlatformSearchPlugin(OSINTPlugin):
    def __init__(self):
        super().__init__(
            name="my_platform_search",
            version="1.0.0",
            description="Search for usernames on MyPlatform",
            supported_artifacts=["username"],
            author="Your Name"
        )
    
    def execute(self, artifact: Artifact) -> PluginResult:
        username = artifact.value
        findings = []
        
        try:
            # Check if username exists on MyPlatform
            url = f"https://myplatform.com/api/users/{username}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                findings.append({
                    "type": "platform_presence",
                    "value": f"https://myplatform.com/{username}",
                    "source": "my_platform_search",
                    "confidence": 0.9,
                    "link_type": "profile_found"
                })
                
                # Extract additional information
                if data.get("display_name"):
                    findings.append({
                        "type": "display_name",
                        "value": data["display_name"],
                        "source": "my_platform_search",
                        "confidence": 0.95
                    })
            
            return PluginResult(
                plugin_name=self.name,
                artifact_value=username,
                success=True,
                findings=findings,
                metadata={"status_code": response.status_code}
            )
            
        except requests.RequestException as e:
            return PluginResult(
                plugin_name=self.name,
                artifact_value=username,
                success=False,
                findings=[],
                error=str(e)
            )
```

## Best Practices

1. **Error Handling**: Always wrap external API calls in try-except blocks
2. **Timeouts**: Use appropriate timeouts for network requests
3. **Rate Limiting**: Respect API rate limits
4. **Confidence Scores**: Assign appropriate confidence scores (0.0-1.0)
5. **Metadata**: Include useful metadata for debugging
6. **Logging**: Use the logging module for debug information

## Testing Your Plugin

```python
from src.plugins.base import Artifact
from src.plugins.my_plugin import MyCustomPlugin

# Create plugin instance
plugin = MyCustomPlugin()

# Create test artifact
artifact = Artifact(
    type="username",
    value="testuser",
    source="test"
)

# Execute plugin
result = plugin.execute(artifact)

print(f"Success: {result.success}")
print(f"Findings: {result.findings}")
```

## Plugin Registry

The `PluginRegistry` manages plugin discovery and execution:

```python
from src.plugins.manager import PluginRegistry, PluginManager

# Discover all plugins
registry = PluginRegistry()
registry.discover_plugins()

# Get available plugins
plugins = registry.get_available_plugins()

# Get plugins for a specific artifact type
username_plugins = registry.get_plugins_by_artifact_type("username")

# Execute plugins
manager = PluginManager(registry)
results = manager.execute_plugins_for_artifact(artifact)
```

## Advanced Features

### Parallel Execution

Plugins can be executed in parallel using `ThreadPoolExecutor`:

```python
from concurrent.futures import ThreadPoolExecutor

def execute_parallel(artifacts: list[Artifact], max_workers: int = 10):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(plugin.execute, artifact) for artifact in artifacts]
        return [future.result() for future in futures]
```

### Caching

Implement caching to avoid redundant API calls:

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def check_username(username: str) -> dict:
    # This result will be cached
    response = requests.get(f"https://api.example.com/{username}")
    return response.json()
```

### Batch Processing

Process multiple artifacts in a single API call:

```python
def batch_check_usernames(usernames: list[str]) -> list[dict]:
    # API that accepts multiple usernames
    response = requests.post(
        "https://api.example.com/batch",
        json={"usernames": usernames}
    )
    return response.json()
```

## Troubleshooting

### Plugin Not Discovered

- Ensure plugin file is in `src/plugins/` directory
- Check that plugin class inherits from `OSINTPlugin`
- Verify no syntax errors in plugin file

### Plugin Execution Fails

- Check logs in `logs/` directory
- Verify API credentials in config.yaml
- Test API endpoint independently
- Check network connectivity

### Performance Issues

- Reduce max_parallel_workers in config.yaml
- Implement caching for repeated queries
- Use batch processing when available
- Add rate limiting to avoid API throttling

## Contributing

To contribute a new plugin to the main project:

1. Create the plugin following this guide
2. Add comprehensive documentation
3. Include unit tests
4. Submit a pull request with description of the plugin's functionality

## Additional Resources

- Base plugin interface: `src/plugins/base.py`
- Plugin manager: `src/plugins/manager.py`
- Configuration: `config/config.yaml`
- Example plugins: `src/plugins/` directory

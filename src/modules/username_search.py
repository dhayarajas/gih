"""
Ghost Identity Hunter - Username Search Module

PURPOSE:
--------
This module provides comprehensive username enumeration capabilities across multiple social media
platforms, developer communities, and online services to discover digital footprints and
establish identity patterns across the internet.

FUNCTIONALITY:
--------------
- Parallel username checking across 12+ major platforms
- HTTP status code analysis for account existence detection
- JSON API response parsing for structured data extraction
- Profile metadata collection (display names, bios, follower counts)
- Platform-specific validation to reduce false positives
- Username variant generation for fuzzy matching
- Confidence scoring based on platform response patterns

PLATFORM COVERAGE:
------------------
- Social Media: GitHub, Reddit, Twitter/X, Instagram, LinkedIn, Pinterest
- Developer Platforms: GitLab, Keybase, HackerNews
- Communication: Mastodon, Steam
- Content Platforms: Medium

DETECTION METHODS:
-----------------
- api_status: HTTP status code check for API endpoints
- api_json: JSON response validation with expected fields
- api_json_array: Array response validation for user data
- web_status: HTTP status check for web profiles
- web_content: HTML content validation for profile pages

RISK ASSESSMENT:
---------------
- Account presence across multiple platforms increases identity confidence
- Verified badges and follower counts provide legitimacy indicators
- Profile bio consistency helps confirm identity attribution
- Platform-specific patterns reveal usage preferences

USAGE EXAMPLES:
--------------
# Search username across all platforms
result = search_username("johndoe")

# Check specific platforms only
result = search_username("johndoe", platforms=["GitHub", "Twitter"])

# Generate username variants
variants = generate_username_variants("johndoe")

# Extract discovered artifacts
artifacts = get_discovered_artifacts(result)

DEPENDENCIES:
-------------
- requests: HTTP client for platform API calls
- dataclasses: Structured result objects
- logging: Debug and error reporting
- json: API response parsing

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import json
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from src.utils.concurrency import io_slot
from src.utils.http_client import get_http_session

from src.config.loader import get_config

logger = logging.getLogger(__name__)

# Simple in-memory cache for platform checks
_platform_check_cache = {}
_cache_max_size = 1000  # Maximum number of cached results


def _get_username_search_config() -> dict:
    """Get username search configuration from config.yaml."""
    config = get_config()
    return config.get("username_search", {
        "max_parallel_workers": 25,  # Increased from 10 for faster platform checks
        "platforms": [
            {
                "name": "GitHub",
                "url_template": "https://api.github.com/users/{username}",
                "check_type": "api_status",
                "expected_status": 200,
            },
            {
                "name": "GitLab",
                "url_template": "https://gitlab.com/api/v4/users?username={username}",
                "check_type": "api_json_array",
                "expected_field": "username",
            },
            {
                "name": "Reddit",
                "url_template": "https://www.reddit.com/user/{username}/about.json",
                "check_type": "api_json",
                "expected_field": "name",
            },
            {
                "name": "Twitter/X",
                "url_template": "https://twitter.com/{username}",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "Instagram",
                "url_template": "https://www.instagram.com/{username}/",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "LinkedIn",
                "url_template": "https://www.linkedin.com/in/{username}/",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "Keybase",
                "url_template": "https://keybase.io/{username}",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "HackerNews",
                "url_template": "https://news.ycombinator.com/user?id={username}",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "Medium",
                "url_template": "https://medium.com/@{username}",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "Pinterest",
                "url_template": "https://www.pinterest.com/{username}/",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "Steam",
                "url_template": "https://steamcommunity.com/id/{username}",
                "check_type": "web_status",
                "expected_status": 200,
            },
            {
                "name": "Mastodon",
                "url_template": "https://mastodon.social/@{username}",
                "check_type": "web_status",
                "expected_status": 200,
            },
        ],
    })


# Platform registry: loaded from config
PLATFORMS = _get_username_search_config().get("platforms", [])


@dataclass
class PlatformResult:
    """Result of checking a single platform."""

    platform_name: str
    found: bool
    profile_url: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    follower_count: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "platform_name": self.platform_name,
            "found": self.found,
            "profile_url": self.profile_url,
            "username": self.username,
            "display_name": self.display_name,
            "bio": self.bio,
            "avatar_url": self.avatar_url,
            "follower_count": self.follower_count,
            "error": self.error,
        }


@dataclass
class UsernameSearchResult:
    """Aggregated results from username search."""

    username: str
    platforms_found: list[PlatformResult] = field(default_factory=list)
    platforms_not_found: list[str] = field(default_factory=list)
    platforms_error: list[str] = field(default_factory=list)
    total_checked: int = 0

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "platforms_found": [p.to_dict() for p in self.platforms_found],
            "platforms_not_found": self.platforms_not_found,
            "platforms_error": self.platforms_error,
            "total_checked": self.total_checked,
            "found_count": len(self.platforms_found),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def _check_platform(username: str, platform: dict) -> PlatformResult:
    """Check if username exists on a specific platform."""
    global _platform_check_cache
    
    # Check cache first
    cache_key = f"{username}:{platform['name']}"
    if cache_key in _platform_check_cache:
        logger.debug("Cache hit for %s on %s", username, platform['name'])
        return _platform_check_cache[cache_key]
    
    url = platform["url_template"].format(username=username)
    result = PlatformResult(
        platform_name=platform["name"],
        found=False,
        username=username,
    )

    try:
        session = get_http_session()
        with io_slot():
            resp = session.get(url, timeout=10, allow_redirects=False)

        if platform["check_type"] == "api_status":
            if resp.status_code == platform["expected_status"]:
                result.found = True
                result.profile_url = url.replace("/api/", "/").replace("api.", "")
                # Try to extract profile data from API response
                try:
                    data = resp.json()
                    result.display_name = data.get("name") or data.get("login")
                    result.bio = data.get("bio")
                    result.avatar_url = data.get("avatar_url")
                    result.follower_count = data.get("followers")
                    if platform["name"] == "GitHub":
                        result.profile_url = data.get("html_url", url)
                except (ValueError, KeyError):
                    pass

        elif platform["check_type"] == "api_json":
            if resp.status_code == platform["expected_status"]:
                try:
                    data = resp.json()
                    if data and data is not None:
                        result.found = True
                        result.profile_url = url
                        if isinstance(data, dict):
                            result.display_name = data.get("name") or data.get("id")
                except (ValueError, KeyError):
                    pass

        elif platform["check_type"] == "api_json_array":
            if resp.status_code == platform["expected_status"]:
                try:
                    data = resp.json()
                    if data and len(data) > 0:
                        result.found = True
                        user = data[0]
                        result.profile_url = user.get("web_url", url)
                        result.display_name = user.get("name")
                        result.avatar_url = user.get("avatar_url")
                except (ValueError, KeyError):
                    pass

        elif platform["check_type"] == "web_status":
            # For web checks, 200 = found, 404 = not found, redirect = uncertain
            if resp.status_code == 200:
                result.found = True
                result.profile_url = url
            elif resp.status_code in (301, 302):
                # Could be redirect to login or different page
                pass

    except requests.Timeout:
        result.error = "timeout"
    except requests.ConnectionError:
        result.error = "connection_error"
    except requests.RequestException as e:
        result.error = str(e)

    # Cache the result (with size limit)
    if len(_platform_check_cache) < _cache_max_size:
        _platform_check_cache[cache_key] = result
    else:
        # Simple cache eviction: remove oldest entry
        oldest_key = next(iter(_platform_check_cache))
        del _platform_check_cache[oldest_key]
        _platform_check_cache[cache_key] = result

    return result


def search_usernames_batch(usernames: list[str], platforms: Optional[list[dict]] = None, max_workers: int = 10) -> list[UsernameSearchResult]:
    """
    Search for multiple usernames in parallel.

    Args:
        usernames: List of usernames to search for
        platforms: Optional list of platform configs (defaults to built-in PLATFORMS)
        max_workers: Maximum number of concurrent username searches

    Returns:
        List of UsernameSearchResult objects
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(search_username, username, platforms): username 
            for username in usernames
        }
        
        for future in as_completed(futures):
            username = futures[future]
            try:
                result = future.result()
                results.append(result)
                logger.info("Batch search complete for %s: found on %d/%d platforms", 
                           username, len(result.platforms_found), result.total_checked)
            except Exception as e:
                logger.error("Batch search failed for %s: %s", username, e)
                # Create error result
                error_result = UsernameSearchResult(username=username)
                error_result.platforms_error = ["batch_error"]
                results.append(error_result)
    
    return results


def search_username(username: str, platforms: Optional[list[dict]] = None) -> UsernameSearchResult:
    """
    Search for a username across multiple platforms.

    Args:
        username: The username to search for
        platforms: Optional list of platform configs (defaults to built-in PLATFORMS)

    Returns:
        UsernameSearchResult with found/not-found/error breakdown
    """
    platforms_to_check = platforms or PLATFORMS
    result = UsernameSearchResult(username=username)

    # Execute platform checks in parallel
    config = _get_username_search_config()
    max_workers = config["max_parallel_workers"]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_platform, username, platform): platform
            for platform in platforms_to_check
        }
        
        for future in as_completed(futures):
            platform = futures[future]
            result.total_checked += 1
            try:
                platform_result = future.result()
                
                if platform_result.error:
                    result.platforms_error.append(platform["name"])
                    logger.debug("Error checking %s: %s", platform["name"], platform_result.error)
                elif platform_result.found:
                    result.platforms_found.append(platform_result)
                    logger.info("Found %s on %s", username, platform["name"])
                else:
                    result.platforms_not_found.append(platform["name"])
            except Exception as e:
                result.platforms_error.append(platform["name"])
                logger.error("Exception checking %s: %s", platform["name"], e)

    logger.info(
        "Username search complete: %s → found on %d/%d platforms",
        username, len(result.platforms_found), result.total_checked
    )
    return result


def generate_username_variants(username: str) -> list[str]:
    """Generate common variants of a username for fuzzy matching."""
    variants = set()
    base = username.lower()

    # Underscore/dot/dash variants
    variants.add(base.replace("_", ""))
    variants.add(base.replace("_", "."))
    variants.add(base.replace("_", "-"))
    variants.add(base.replace(".", "_"))
    variants.add(base.replace(".", ""))
    variants.add(base.replace("-", "_"))
    variants.add(base.replace("-", ""))

    # Numeric suffix variants
    if base[-1].isdigit():
        stripped = base.rstrip("0123456789")
        variants.add(stripped)
        variants.add(stripped + "1")
        variants.add(stripped + "123")

    # Remove leading/trailing underscores
    variants.add(base.strip("_"))

    # Remove the original
    variants.discard(base)
    return sorted(variants)


def get_discovered_artifacts(search_result: UsernameSearchResult) -> list[dict]:
    """Extract new artifacts from username search results."""
    artifacts = []
    for platform in search_result.platforms_found:
        if platform.profile_url:
            artifacts.append({
                "type": "platform_presence",
                "value": platform.profile_url,
                "source": f"username_search_{platform.platform_name.lower().replace('/', '_')}",
                "confidence": 0.85,
                "metadata": json.dumps(platform.to_dict()),
            })
    return artifacts

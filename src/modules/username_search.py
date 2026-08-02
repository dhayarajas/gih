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

WEB CONTENT VALIDATION:
-----------------------
Many sites answer 200 for non-existent usernames (soft 404s, login/consent walls,
JavaScript app shells), so a bare status check produces false positives. Both
``web_status`` and ``web_content`` platforms therefore validate the response body
before reporting a hit. Per-platform config fields:

- failure_markers: substrings that prove the account does NOT exist (soft 404).
- success_markers: substrings that prove a real profile page was served. When set,
  at least one must be present.
- require_username_in_body: when true (default for web checks), the username must
  appear somewhere in the body.
- redirect_means: how to read a 3xx response -- "not_found" (default; e.g. a bounce
  to a login or home page), "found", or "uncertain".

Markers may contain a ``{username}`` placeholder, which is substituted before
matching. Matching is case-insensitive. A hit backed by content validation is
reported with a high confidence; a bare status-200 hit (platform defines no
content rules) is reported as unvalidated with a low confidence so the report can
flag it.

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

from src.utils.http_client import get_http_session

from src.config.loader import get_config

logger = logging.getLogger(__name__)

# Simple in-memory cache for platform checks
_platform_check_cache = {}
_cache_max_size = 1000  # Maximum number of cached results


# Validation strengths reported alongside a platform hit.
VALIDATION_CONTENT = "content"  # response body confirmed a real profile
VALIDATION_API = "api"  # structured API response confirmed the account
VALIDATION_STATUS = "status"  # bare HTTP 200, no content evidence

# Confidence attached to a discovered platform presence per validation strength.
VALIDATION_CONFIDENCE = {
    VALIDATION_CONTENT: 0.9,
    VALIDATION_API: 0.9,
    VALIDATION_STATUS: 0.4,
}

# Content rules for the web platforms, applied on top of a 200 response. Every
# one of these sites can answer 200 for a username that does not exist.
WEB_PLATFORM_CONTENT_RULES = {
    # X serves a JS shell with a consent/login wall; the handle is present in the
    # server-rendered metadata only for real profiles. Redirects go to the login
    # or home page, never to a profile.
    "Twitter/X": {
        "failure_markers": [
            "this account doesn’t exist",
            "this account doesn't exist",
            "page doesn’t exist",
            "page doesn't exist",
        ],
        "success_markers": ["@{username}", "/{username}"],
    },
    # Instagram soft-404s with a "page isn't available" shell and bounces
    # logged-out visitors to /accounts/login.
    "Instagram": {
        "failure_markers": [
            "sorry, this page isn't available",
            "page not found",
            "the link you followed may be broken",
        ],
        "success_markers": ["\"username\":\"{username}\"", "@{username}"],
    },
    # LinkedIn answers 200 with an authwall for both real and fake profiles, so
    # only the canonical /in/{username} link proves the profile exists.
    "LinkedIn": {
        "failure_markers": [
            "page not found",
            "this page doesn’t exist",
            "this page doesn't exist",
        ],
        "success_markers": ["linkedin.com/in/{username}", "/in/{username}"],
    },
    "Keybase": {
        "failure_markers": ["user not found", "sorry, we couldn"],
        "success_markers": ["keybase.io/{username}", "@{username}"],
    },
    # Hacker News returns 200 with "No such user." for unknown ids.
    "HackerNews": {
        "failure_markers": ["no such user"],
        "success_markers": ["user:", "karma:"],
    },
    "Medium": {
        "failure_markers": ["out of nothing, something", "page not found", "404"],
        "success_markers": ["medium.com/@{username}", "@{username}"],
    },
    "Pinterest": {
        "failure_markers": ["user not found", "page not found", "sorry! we couldn"],
        "success_markers": ["pinterest.com/{username}", "\"username\":\"{username}\""],
    },
    # Steam renders "The specified profile could not be found." with status 200.
    "Steam": {
        "failure_markers": [
            "the specified profile could not be found",
            "no user could be found",
        ],
        "success_markers": ["steamcommunity.com/id/{username}", "{username}"],
    },
    "Mastodon": {
        "failure_markers": [
            "the page you are looking for isn't here",
            "not found",
        ],
        "success_markers": ["@{username}", "/users/{username}"],
    },
}


def _web_platform(name: str, url_template: str) -> dict:
    """Build a content-validated web platform entry for the fallback config."""
    platform = {
        "name": name,
        "url_template": url_template,
        "check_type": "web_content",
        "expected_status": 200,
        "require_username_in_body": True,
        "redirect_means": "not_found",
    }
    platform.update(WEB_PLATFORM_CONTENT_RULES.get(name, {}))
    return platform


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
            _web_platform("Twitter/X", "https://twitter.com/{username}"),
            _web_platform("Instagram", "https://www.instagram.com/{username}/"),
            _web_platform("LinkedIn", "https://www.linkedin.com/in/{username}/"),
            _web_platform("Keybase", "https://keybase.io/{username}"),
            _web_platform("HackerNews", "https://news.ycombinator.com/user?id={username}"),
            _web_platform("Medium", "https://medium.com/@{username}"),
            _web_platform("Pinterest", "https://www.pinterest.com/{username}/"),
            _web_platform("Steam", "https://steamcommunity.com/id/{username}"),
            _web_platform("Mastodon", "https://mastodon.social/@{username}"),
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
    # How the hit was established: "content", "api" or "status" (see module docstring).
    validation_method: Optional[str] = None
    # Human-readable justification for the verdict, kept for the evidence chain.
    validation_evidence: Optional[str] = None

    @property
    def is_validated(self) -> bool:
        """True when the hit is backed by content/API evidence, not a bare 200."""
        return self.found and self.validation_method in (VALIDATION_CONTENT, VALIDATION_API)

    @property
    def confidence(self) -> float:
        """Confidence reflecting how strongly the account existence was proven."""
        return VALIDATION_CONFIDENCE.get(self.validation_method, VALIDATION_CONFIDENCE[VALIDATION_STATUS])

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
            "validation_method": self.validation_method,
            "validation_evidence": self.validation_evidence,
            "is_validated": self.is_validated,
            "confidence": self.confidence,
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


def _expand_markers(markers, username: str) -> list[str]:
    """Lowercase markers with the {username} placeholder substituted."""
    expanded = []
    for marker in markers or []:
        text = str(marker)
        if "{username}" in text:
            text = text.replace("{username}", username)
        expanded.append(text.lower())
    return expanded


def _validate_web_content(username: str, platform: dict, body: str) -> tuple[bool, str, str]:
    """Decide whether a 200 response body really is the user's profile page.

    Returns ``(found, validation_method, evidence)``. A platform that defines no
    content rules at all falls back to the legacy status-only verdict, which is
    reported as unvalidated so downstream consumers can flag it.
    """
    failure_markers = _expand_markers(platform.get("failure_markers"), username)
    success_markers = _expand_markers(platform.get("success_markers"), username)
    require_username = platform.get(
        "require_username_in_body",
        platform["check_type"] in ("web_status", "web_content"),
    )
    expected_field = platform.get("expected_field")
    if expected_field and not success_markers:
        success_markers = _expand_markers([expected_field], username)

    has_rules = bool(failure_markers or success_markers or require_username)
    if not has_rules:
        return True, VALIDATION_STATUS, "HTTP 200, no content rules configured"

    if not body:
        return False, VALIDATION_CONTENT, "HTTP 200 with empty body"

    haystack = body.lower()

    for marker in failure_markers:
        if marker in haystack:
            return False, VALIDATION_CONTENT, f"not-found marker present: {marker!r}"

    if success_markers:
        matched = next((m for m in success_markers if m in haystack), None)
        if matched is None:
            return False, VALIDATION_CONTENT, "no profile marker in body (login wall or app shell)"
        return True, VALIDATION_CONTENT, f"profile marker present: {matched!r}"

    if require_username:
        if username.lower() in haystack:
            return True, VALIDATION_CONTENT, "username present in page body"
        return False, VALIDATION_CONTENT, "username absent from page body"

    return True, VALIDATION_STATUS, "HTTP 200, no content rules configured"


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
        resp = session.get(url, timeout=10, allow_redirects=False)

        expected_status = platform.get("expected_status", 200)

        if platform["check_type"] == "api_status":
            if resp.status_code == expected_status:
                result.found = True
                result.validation_method = VALIDATION_API
                result.validation_evidence = f"API returned {resp.status_code}"
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
            if resp.status_code == expected_status:
                try:
                    data = resp.json()
                    if data and data is not None:
                        result.found = True
                        result.validation_method = VALIDATION_API
                        result.validation_evidence = "API returned a user object"
                        result.profile_url = url
                        if isinstance(data, dict):
                            result.display_name = data.get("name") or data.get("id")
                except (ValueError, KeyError):
                    pass

        elif platform["check_type"] == "api_json_array":
            if resp.status_code == expected_status:
                try:
                    data = resp.json()
                    if data and len(data) > 0:
                        result.found = True
                        result.validation_method = VALIDATION_API
                        result.validation_evidence = "API returned a non-empty user array"
                        user = data[0]
                        result.profile_url = user.get("web_url", url)
                        result.display_name = user.get("name")
                        result.avatar_url = user.get("avatar_url")
                except (ValueError, KeyError):
                    pass

        elif platform["check_type"] in ("web_status", "web_content"):
            # A 200 is necessary but not sufficient: the body has to look like a
            # real profile page before the account is reported as found.
            if resp.status_code == expected_status:
                found, method, evidence = _validate_web_content(
                    username, platform, resp.text or ""
                )
                result.found = found
                result.validation_method = method
                result.validation_evidence = f"HTTP {resp.status_code}; {evidence}"
                if found:
                    result.profile_url = url
            elif resp.status_code in (301, 302, 303, 307, 308):
                # Redirects are read per platform: for all bundled web platforms a
                # redirect is a bounce to a login/consent or home page, i.e. the
                # profile does not exist. Platforms that legitimately redirect to a
                # canonical profile URL set redirect_means: found.
                redirect_means = platform.get("redirect_means", "not_found")
                location = resp.headers.get("Location", "")
                if redirect_means == "found":
                    result.found = True
                    result.profile_url = location or url
                    result.validation_method = VALIDATION_STATUS
                    result.validation_evidence = (
                        f"HTTP {resp.status_code} redirect to {location or 'unknown'} "
                        "treated as found for this platform"
                    )
                else:
                    result.validation_method = VALIDATION_CONTENT
                    result.validation_evidence = (
                        f"HTTP {resp.status_code} redirect to {location or 'unknown'} "
                        f"treated as {redirect_means}"
                    )
            else:
                result.validation_evidence = f"HTTP {resp.status_code}"

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
    """Extract new artifacts from username search results.

    Confidence follows the strength of the check: content/API validated hits score
    high, bare status-200 hits score low so analysts can discount them.
    """
    artifacts = []
    for platform in search_result.platforms_found:
        if platform.profile_url:
            artifacts.append({
                "type": "platform_presence",
                "value": platform.profile_url,
                "source": f"username_search_{platform.platform_name.lower().replace('/', '_')}",
                "confidence": platform.confidence,
                "metadata": json.dumps(platform.to_dict()),
            })
    return artifacts

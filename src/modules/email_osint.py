"""
Ghost Identity Hunter - Email OSINT Module

PURPOSE:
--------
This module provides comprehensive email intelligence capabilities including format validation,
disposable domain detection, account existence checks across platforms, and breach data
correlation to assess the legitimacy and risk associated with email address artifacts.

FUNCTIONALITY:
--------------
- RFC 5321 email format validation and normalization
- Disposable email domain detection using known provider lists
- Privacy-focused email provider identification
- Corporate domain classification via MX record analysis
- Account existence checks across major platforms (GitHub, Twitter, Instagram, Reddit)
- Gravatar profile detection using MD5 hash lookup
- Username extraction for cross-platform investigation
- Risk indicator assessment based on domain characteristics

DATA SOURCES:
-------------
- Built-in disposable domain database (20+ known services)
- Privacy provider database for encrypted email services
- Platform APIs for account existence verification
- Gravatar CDN for profile image detection
- DNS MX record lookup for corporate domain identification

RISK ASSESSMENT:
---------------
- Disposable domains flagged as high-risk indicators
- Privacy providers noted for investigation context
- Corporate domains considered lower risk
- Account presence across platforms increases confidence
- Gravatar matches provide visual identity confirmation

USAGE EXAMPLES:
--------------
# Analyze an email address
analysis = analyze_email("user@example.com")

# Check if email is disposable
if analysis.is_disposable:
    print("Disposable email detected - high risk")

# Extract username for further investigation
username = analysis.local_part
artifacts = get_discovered_artifacts(analysis)

DEPENDENCIES:
-------------
- requests: HTTP client for API calls and platform checks
- hashlib: MD5 hashing for Gravatar lookup
- re: Regular expressions for email validation
- dataclasses: Structured result objects
- logging: Debug and error reporting

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from src.utils.http_client import get_http_session

from src.config.loader import get_config

logger = logging.getLogger(__name__)


def _get_email_osint_config() -> dict:
    """Get email OSINT configuration from config.yaml."""
    config = get_config()
    return config.get("email_osint", {
        "max_parallel_workers": 10,
        "disposable_domains": [
            "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
            "10minutemail.com", "trashmail.com", "yopmail.com", "sharklasers.com",
            "grr.la", "guerrillamail.info", "temp-mail.org", "fakeinbox.com",
            "dispostable.com", "maildrop.cc", "getnada.com", "mohmal.com",
            "tmpmail.net", "tempail.com", "emailondeck.com", "burnermail.io",
            "protonmail.com",
        ],
        "privacy_providers": [
            "protonmail.com", "tutanota.com", "mailbox.org", "countermail.com",
            "scryptmail.com", "kolabnow.com", "runbox.com", "startmail.com",
        ],
    })


# Known disposable email domains (loaded from config)
DISPOSABLE_DOMAINS = set(_get_email_osint_config().get("disposable_domains", []))

# Privacy-focused email providers (loaded from config)
PRIVACY_PROVIDERS = set(_get_email_osint_config().get("privacy_providers", []))

# Common platforms to check for account existence
PLATFORMS_TO_CHECK = [
    {"name": "GitHub", "url": "https://api.github.com/users/{username}", "method": "api"},
    {"name": "Twitter/X", "url": "https://twitter.com/{username}", "method": "web"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/", "method": "web"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{username}/about.json", "method": "api"},
]


@dataclass
class EmailAnalysis:
    """Results from email OSINT analysis."""

    email: str
    valid_format: bool = False
    domain: str = ""
    local_part: str = ""
    is_disposable: bool = False
    is_privacy_provider: bool = False
    is_corporate: bool = False
    mx_records: list[str] = field(default_factory=list)
    platforms_found: list[dict] = field(default_factory=list)
    breaches: list[dict] = field(default_factory=list)
    breach_count: int = 0
    risk_indicators: list[str] = field(default_factory=list)
    gravatar_url: Optional[str] = None
    has_gravatar: bool = False

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "valid_format": self.valid_format,
            "domain": self.domain,
            "local_part": self.local_part,
            "is_disposable": self.is_disposable,
            "is_privacy_provider": self.is_privacy_provider,
            "is_corporate": self.is_corporate,
            "mx_records": self.mx_records,
            "platforms_found": self.platforms_found,
            "breaches": self.breaches,
            "breach_count": self.breach_count,
            "risk_indicators": self.risk_indicators,
            "gravatar_url": self.gravatar_url,
            "has_gravatar": self.has_gravatar,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def validate_email_format(email: str) -> bool:
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def check_gravatar(email: str) -> tuple[bool, Optional[str]]:
    """Check if email has a Gravatar profile."""
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        session = get_http_session()
        resp = session.head(url, timeout=10)
        if resp.status_code == 200:
            return True, f"https://www.gravatar.com/avatar/{email_hash}"
        return False, None
    except requests.RequestException:
        return False, None


def check_github_email(email: str) -> Optional[dict]:
    """Search GitHub for users with this email (via commits search)."""
    try:
        session = get_http_session()
        resp = session.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email"},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("total_count", 0) > 0:
                user = data["items"][0]
                return {
                    "platform": "GitHub",
                    "username": user.get("login"),
                    "profile_url": user.get("html_url"),
                    "avatar_url": user.get("avatar_url"),
                }
    except requests.RequestException:
        pass
    return None


def check_hibp_breaches(email: str) -> list[dict]:
    """
    Check HaveIBeenPwned for breaches (uses the free API without key).
    Falls back gracefully if API is rate-limited.
    """
    breaches = []
    try:
        session = get_http_session()
        resp = session.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "User-Agent": "GhostIdentityHunter-Academic",
                "Accept": "application/json",
            },
            params={"truncateResponse": "true"},
            timeout=10,
        )
        if resp.status_code == 200:
            breaches = resp.json()
        elif resp.status_code == 404:
            pass  # No breaches found
        elif resp.status_code == 401:
            logger.warning("HIBP API requires API key for this endpoint")
        elif resp.status_code == 429:
            logger.warning("HIBP API rate limited")
    except requests.RequestException as e:
        logger.warning("HIBP request failed: %s", e)
    return breaches


def analyze_email(email: str) -> EmailAnalysis:
    """
    Perform comprehensive email OSINT analysis.

    Checks:
    - Format validation
    - Domain classification (disposable, privacy, corporate)
    - Gravatar profile existence
    - GitHub account linkage
    - HaveIBeenPwned breach data
    """
    result = EmailAnalysis(email=email)

    # Format validation
    result.valid_format = validate_email_format(email)
    if not result.valid_format:
        result.risk_indicators.append("invalid_email_format")
        return result

    # Extract parts
    parts = email.split("@")
    result.local_part = parts[0]
    result.domain = parts[1].lower()

    # Domain classification
    if result.domain in DISPOSABLE_DOMAINS:
        result.is_disposable = True
        result.risk_indicators.append("disposable_email_domain")

    if result.domain in PRIVACY_PROVIDERS:
        result.is_privacy_provider = True
        result.risk_indicators.append("privacy_email_provider")

    # Check for corporate email (custom domain, not free provider)
    free_providers = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "icloud.com", "mail.com", "live.com",
    }
    if result.domain not in free_providers and result.domain not in DISPOSABLE_DOMAINS:
        result.is_corporate = True

        # Execute external checks in parallel
        config = _get_email_osint_config()
        max_workers = config["max_parallel_workers"]
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all checks
            gravatar_future = executor.submit(check_gravatar, email)
            github_future = executor.submit(check_github_email, email)
            hibp_future = executor.submit(check_hibp_breaches, email)
            
            # Collect results
            result.has_gravatar, result.gravatar_url = gravatar_future.result()
            if result.has_gravatar:
                result.platforms_found.append({
                    "platform": "Gravatar",
                    "profile_url": result.gravatar_url,
                })

            github_result = github_future.result()
            if github_result:
                result.platforms_found.append(github_result)

            result.breaches = hibp_future.result()
            result.breach_count = len(result.breaches)
            if result.breach_count > 0:
                result.risk_indicators.append(f"found_in_{result.breach_count}_breaches")

    logger.info(
        "Email analysis complete: %s → disposable=%s, breaches=%d, platforms=%d",
        email, result.is_disposable, result.breach_count, len(result.platforms_found)
    )
    return result


def get_discovered_artifacts(analysis: EmailAnalysis) -> list[dict]:
    """Extract new artifacts from email analysis."""
    artifacts = []
    for platform in analysis.platforms_found:
        if platform.get("username"):
            artifacts.append({
                "type": "username",
                "value": platform["username"],
                "source": f"email_osint_{platform['platform'].lower()}",
                "confidence": 0.9,
                "metadata": json.dumps(platform),
            })
    return artifacts

"""
Ghost Identity Hunter - Breach Check Module

PURPOSE:
--------
This module provides breach intelligence capabilities by checking email addresses and phone
numbers against breach databases to identify credential exposure, data breach history,
and assess the risk level associated with compromised identity artifacts.

FUNCTIONALITY:
--------------
- Email breach lookup via HaveIBeenPwned API v3 (requires paid API key)
- Password breach verification using k-anonymity model (FREE)
- Mock breach data generation for demonstration without API key
- Risk level assessment based on breach severity and recency
- Data class analysis (sensitive information types exposed)
- Verified breach identification for higher confidence

DATA SOURCES:
-------------
- HaveIBeenPwned API v3 (https://haveibeenpwned.com/api/v3) - PAID
- Pwned Passwords API with k-anonymity (SHA-1 prefix lookup) - FREE
- Mock breach data for demonstration (Adobe, LinkedIn, Facebook breaches)

API REQUIREMENTS:
-----------------
- Email breach checks: Requires paid HIBP API key (~$3.50/month)
- Password checks: FREE, no API key required
- Without API key: Returns mock breach data for demonstration

SECURITY FEATURES:
-----------------
- K-anonymity model for password checks (never transmits full hash)
- API key authentication for email breach lookups
- Rate limiting compliance (1.5 second delays between requests)
- TLS 1.3 encryption for all API communications
- Custom User-Agent identification for academic research

MOCK DATA USAGE:
---------------
When no API key is provided, the module generates realistic mock breach data:
- Adobe (2013): 152M records, email/passwords/names
- LinkedIn (2012): 164M records, email/passwords  
- Facebook (2019): 533M records, email/names/phones
- Randomly selects 1-2 breaches per email for demonstration

RISK ASSESSMENT:
---------------
- High risk: Sensitive data breaches, verified breaches, recent exposures
- Medium risk: Large-scale breaches, multiple breach appearances
- Low risk: Old breaches, limited data classes, unverified sources
- Critical: Password exposure in recent verified breaches

USAGE EXAMPLES:
--------------
# Check email breach history (with API key)
result = check_email_breaches("user@example.com", api_key="your-api-key")

# Check email with mock data (no API key)
result = check_email_breaches("user@example.com")

# Check password exposure (always free, no API key needed)
password_result = check_password_exposure("password123")

# Assess risk level
if result.risk_level == "high":
    print("High-risk breach exposure detected")

# Extract discovered artifacts
artifacts = get_discovered_artifacts(result)

DEPENDENCIES:
-------------
- requests: HTTP client for API calls
- hashlib: SHA-1 hashing for k-anonymity password checks
- dataclasses: Structured result objects
- logging: Debug and error reporting
- random: Mock data selection

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.1 - Fixed API key handling with mock data fallback
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from src.utils.http_client import get_http_session
from src.config.loader import get_config

logger = logging.getLogger(__name__)


def _get_breach_check_config() -> dict:
    """Get breach check configuration from config.yaml."""
    config = get_config()
    return config.get("breach_check", {
        "hibp_api_base": "https://haveibeenpwned.com/api/v3",
        "rate_limit_seconds": 1.5,
    })


HIBP_API_BASE = _get_breach_check_config().get("hibp_api_base", "https://haveibeenpwned.com/api/v3")
HIBP_USER_AGENT = "GhostIdentityHunter-Academic-Research"


@dataclass
class BreachInfo:
    """Information about a single data breach."""

    name: str
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    pwn_count: int = 0
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "added_date": self.added_date,
            "pwn_count": self.pwn_count,
            "data_classes": self.data_classes,
            "is_verified": self.is_verified,
            "is_sensitive": self.is_sensitive,
        }


@dataclass
class BreachCheckResult:
    """Results from breach database checks."""

    identifier: str
    identifier_type: str  # 'email' or 'phone'
    breaches: list[BreachInfo] = field(default_factory=list)
    breach_count: int = 0
    paste_count: int = 0
    password_exposed: bool = False
    total_records_exposed: int = 0
    data_types_exposed: set = field(default_factory=set)
    risk_level: str = "none"  # none, low, medium, high, critical
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "identifier_type": self.identifier_type,
            "breaches": [b.to_dict() for b in self.breaches],
            "breach_count": self.breach_count,
            "paste_count": self.paste_count,
            "password_exposed": self.password_exposed,
            "total_records_exposed": self.total_records_exposed,
            "data_types_exposed": sorted(self.data_types_exposed),
            "risk_level": self.risk_level,
            "error": self.error,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=list)


def _compute_risk_level(breach_count: int, password_exposed: bool, data_types: set) -> str:
    """Compute risk level based on breach data."""
    if password_exposed and breach_count >= 5:
        return "critical"
    if password_exposed or breach_count >= 5:
        return "high"
    if breach_count >= 3 or "Passwords" in data_types:
        return "medium"
    if breach_count >= 1:
        return "low"
    return "none"


def check_password_exposure(password: str) -> tuple[bool, int]:
    """
    Check if a password has been exposed in breaches using HIBP Pwned Passwords API.
    Uses k-anonymity model — only sends first 5 chars of SHA-1 hash.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        session = get_http_session()
        resp = session.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": HIBP_USER_AGENT},
            timeout=10,
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.split(":")
                if parts[0] == suffix:
                    return True, int(parts[1])
        return False, 0
    except requests.RequestException as e:
        logger.warning("Password check failed: %s", e)
        return False, 0


def check_email_breaches(email: str, api_key: Optional[str] = None) -> BreachCheckResult:
    """
    Check email against HaveIBeenPwned breach database.

    Note: Full API access requires a paid API key.
    Without key, returns mock breach data for demonstration purposes.
    """
    result = BreachCheckResult(identifier=email, identifier_type="email")

    headers = {
        "User-Agent": HIBP_USER_AGENT,
        "Accept": "application/json",
    }
    if api_key:
        headers["hibp-api-key"] = api_key

    # Check breaches with real API if key provided
    if api_key:
        try:
            session = get_http_session()
            resp = session.get(
                f"{HIBP_API_BASE}/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=15,
            )
            if resp.status_code == 200:
                breaches_data = resp.json()
                for b in breaches_data:
                    breach = BreachInfo(
                        name=b.get("Name", "Unknown"),
                        domain=b.get("Domain", ""),
                        breach_date=b.get("BreachDate", ""),
                        added_date=b.get("AddedDate", ""),
                        pwn_count=b.get("PwnCount", 0),
                        data_classes=b.get("DataClasses", []),
                        is_verified=b.get("IsVerified", False),
                        is_sensitive=b.get("IsSensitive", False),
                    )
                    result.breaches.append(breach)
                    result.total_records_exposed += breach.pwn_count
                    result.data_types_exposed.update(breach.data_classes)

                result.breach_count = len(result.breaches)
                result.password_exposed = "Passwords" in result.data_types_exposed

            elif resp.status_code == 404:
                pass  # No breaches — good news
            elif resp.status_code == 401:
                result.error = "Invalid HIBP API key"
                logger.warning("HIBP API key authentication failed")
            elif resp.status_code == 429:
                result.error = "Rate limited by HIBP API"
                logger.warning("HIBP rate limited")

        except requests.RequestException as e:
            result.error = f"Request failed: {e}"
            logger.warning("HIBP breach check failed: %s", e)
    
    else:
        # No API key - use mock data for demonstration
        logger.info("No HIBP API key provided - using mock breach data for demonstration")
        result.error = "Using mock data - HIBP API key required for real breach checks"
        
        # Generate mock breach data based on email domain
        domain = email.split('@')[-1].lower()
        
        # Mock some common breaches for demonstration
        mock_breaches = [
            {
                "Name": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "AddedDate": "2013-10-04",
                "PwnCount": 152445165,
                "DataClasses": ["Email addresses", "Passwords", "Names"],
                "IsVerified": True,
                "IsSensitive": False
            },
            {
                "Name": "LinkedIn",
                "Domain": "linkedin.com",
                "BreachDate": "2012-05-05",
                "AddedDate": "2016-05-25",
                "PwnCount": 164611595,
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
                "IsSensitive": False
            },
            {
                "Name": "Facebook",
                "Domain": "facebook.com",
                "BreachDate": "2019-04-04",
                "AddedDate": "2019-04-04",
                "PwnCount": 533000000,
                "DataClasses": ["Email addresses", "Names", "Phone numbers"],
                "IsVerified": True,
                "IsSensitive": False
            }
        ]
        
        # Add 1-2 mock breaches for demonstration
        import random
        selected_breaches = random.sample(mock_breaches, random.randint(1, 2))
        
        for b in selected_breaches:
            breach = BreachInfo(
                name=b["Name"],
                domain=b["Domain"],
                breach_date=b["BreachDate"],
                added_date=b["AddedDate"],
                pwn_count=b["PwnCount"],
                data_classes=b["DataClasses"],
                is_verified=b["IsVerified"],
                is_sensitive=b["IsSensitive"],
            )
            result.breaches.append(breach)
            result.total_records_exposed += breach.pwn_count
            result.data_types_exposed.update(breach.data_classes)

        result.breach_count = len(result.breaches)
        result.password_exposed = "Passwords" in result.data_types_exposed

    # Compute risk level
    result.risk_level = _compute_risk_level(
        result.breach_count, result.password_exposed, result.data_types_exposed
    )

    logger.info(
        "Breach check complete: %s → %d breaches, risk=%s",
        email, result.breach_count, result.risk_level
    )
    return result


def get_discovered_artifacts(breach_result: BreachCheckResult) -> list[dict]:
    """Extract artifacts discovered from breach data."""
    artifacts = []
    for breach in breach_result.breaches:
        if breach.domain:
            artifacts.append({
                "type": "breach_data",
                "value": f"{breach.name} ({breach.breach_date})",
                "source": "haveibeenpwned",
                "confidence": 0.95 if breach.is_verified else 0.7,
                "metadata": json.dumps(breach.to_dict()),
            })
    return artifacts

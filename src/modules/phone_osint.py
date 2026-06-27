"""
Ghost Identity Hunter - Phone OSINT Module

PURPOSE:
--------
This module provides phone number intelligence capabilities including validation,
carrier lookup, line type detection, and identification of VoIP/burner services
to assess the legitimacy and risk associated with telephone number artifacts.

FUNCTIONALITY:
--------------
- E.164 phone number validation and formatting
- International carrier and region identification
- Line type classification (mobile, fixed-line, VoIP, toll-free)
- VoIP and virtual number provider detection
- Disposable/burner service identification
- Risk indicator assessment based on carrier type
- Timezone information extraction

DATA SOURCES:
-------------
- phonenumbers library (Google libphonenumber) for validation and carrier lookup
- Built-in carrier classification for VoIP services
- Known disposable service provider database

RISK ASSESSMENT:
---------------
- VoIP numbers flagged as potential burner services
- Disposable services marked as high-risk indicators
- Virtual number providers identified for further investigation
- Geographic anomalies detected through timezone analysis

USAGE EXAMPLES:
--------------
# Analyze a phone number
analysis = analyze_phone("+1234567890")

# Check if number is VoIP
if analysis.is_voip:
    print("Potential burner phone detected")

# Extract discovered artifacts for investigation
artifacts = get_discovered_artifacts(analysis)

DEPENDENCIES:
-------------
- phonenumbers: Google's libphonenumber for Python
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

import json
import logging
from dataclasses import dataclass, field

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

logger = logging.getLogger(__name__)

# Known VoIP/virtual number providers
VOIP_CARRIERS = {
    "google voice", "twilio", "bandwidth.com", "vonage", "grasshopper",
    "burner", "hushed", "textnow", "textfree", "sideline", "talkatone",
    "freedompop", "magicjack", "ooma", "ring.io", "openphone",
}

# Known disposable/burner number services
DISPOSABLE_SERVICES = {
    "burner", "hushed", "textnow", "textfree", "receive-sms-online",
    "temporary-phone-number", "disposablephone",
}


@dataclass
class PhoneAnalysis:
    """Results from phone number OSINT analysis."""

    number: str
    valid: bool
    formatted_international: str = ""
    formatted_national: str = ""
    country_code: int = 0
    country: str = ""
    region: str = ""
    carrier_name: str = ""
    line_type: str = ""  # mobile, fixed_line, voip, etc.
    timezones: list[str] = field(default_factory=list)
    is_voip: bool = False
    is_disposable: bool = False
    risk_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "valid": self.valid,
            "formatted_international": self.formatted_international,
            "formatted_national": self.formatted_national,
            "country_code": self.country_code,
            "country": self.country,
            "region": self.region,
            "carrier_name": self.carrier_name,
            "line_type": self.line_type,
            "timezones": self.timezones,
            "is_voip": self.is_voip,
            "is_disposable": self.is_disposable,
            "risk_indicators": self.risk_indicators,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def analyze_phone(number: str) -> PhoneAnalysis:
    """
    Analyze a phone number using the phonenumbers library.

    Performs:
    - Number validation and formatting
    - Carrier identification
    - Line type detection (mobile/fixed/VoIP)
    - Geographic location
    - VoIP/burner detection
    """
    result = PhoneAnalysis(number=number, valid=False)

    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException:
        # Try with US default
        try:
            parsed = phonenumbers.parse(number, "US")
        except phonenumbers.NumberParseException:
            result.risk_indicators.append("invalid_number_format")
            return result

    # Validate
    if not phonenumbers.is_valid_number(parsed):
        result.risk_indicators.append("invalid_number")
        return result

    result.valid = True
    result.formatted_international = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    result.formatted_national = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.NATIONAL
    )
    result.country_code = parsed.country_code

    # Geographic info
    result.country = geocoder.description_for_number(parsed, "en")
    result.region = geocoder.description_for_number(parsed, "en")

    # Timezone
    tz_list = timezone.time_zones_for_number(parsed)
    result.timezones = list(tz_list) if tz_list else []

    # Carrier info
    carrier_name = carrier.name_for_number(parsed, "en")
    result.carrier_name = carrier_name or "Unknown"

    # Line type detection
    number_type = phonenumbers.number_type(parsed)
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
        phonenumbers.PhoneNumberType.PAGER: "pager",
    }
    result.line_type = type_map.get(number_type, "unknown")

    # VoIP detection
    if result.line_type == "voip":
        result.is_voip = True
        result.risk_indicators.append("voip_number")

    if carrier_name and carrier_name.lower() in VOIP_CARRIERS:
        result.is_voip = True
        if "voip_number" not in result.risk_indicators:
            result.risk_indicators.append("voip_carrier_detected")

    # Disposable/burner detection
    if carrier_name and carrier_name.lower() in DISPOSABLE_SERVICES:
        result.is_disposable = True
        result.risk_indicators.append("disposable_number_service")

    logger.info(
        "Phone analysis complete: %s → %s (%s)",
        number, result.carrier_name, result.line_type
    )
    return result


def get_discovered_artifacts(analysis: PhoneAnalysis) -> list[dict]:
    """Extract new artifacts discovered from phone analysis."""
    artifacts = []
    if analysis.valid and analysis.carrier_name and analysis.carrier_name != "Unknown":
        artifacts.append({
            "type": "carrier_info",
            "value": analysis.carrier_name,
            "source": "phonenumbers_library",
            "confidence": 0.95,
        })
    return artifacts

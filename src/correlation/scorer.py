"""
Ghost Identity Hunter - Confidence Scoring Module

PURPOSE:
--------
This module provides confidence scoring algorithms for identity links and profiles,
implementing a mathematically rigorous approach to assess the strength of relationships
between digital artifacts based on evidence type, data freshness, and source reliability.

FUNCTIONALITY:
--------------
- Link confidence scoring based on relationship type and evidence strength
- Data freshness decay calculations for temporal relevance
- Source reliability weighting for evidence quality assessment
- Identity profile confidence aggregation from multiple links
- Risk level classification based on accumulated evidence
- Cross-platform evidence strength evaluation

SCORING ALGORITHM:
-----------------
1. Base confidence assigned by link type (exact_match: 1.0, registered_with: 0.9, etc.)
2. Data freshness decay applied (>2 years: 0.6x, >1 year: 0.8x)
3. Source reliability multiplier applied (0.0-1.0)
4. Final score bounded between 0.0 and 1.0
5. Profile confidence aggregated from constituent links

LINK TYPES AND SCORES:
----------------------
- exact_match: 1.0 (Same identifier on multiple platforms)
- registered_with: 0.9 (Phone registered to email)
- breach_linked: 0.8 (Breach data correlation)
- image_match: 0.7 (Reverse image search confirmation)
- username_pattern: 0.6 (Similar username variations)
- temporal_match: 0.4 (Account creation proximity)
- possible_username: 0.5 (Derived username evidence)

RISK CLASSIFICATION:
--------------------
- CRITICAL: Score >= 0.9 with high-risk indicators
- HIGH: Score >= 0.7 with multiple risk factors
- MEDIUM: Score >= 0.5 with some risk indicators
- LOW: Score < 0.5 or minimal risk factors

USAGE EXAMPLES:
--------------
# Score a link between artifacts
confidence = compute_link_confidence("exact_match", data_age_days=30)

# Assess identity risk level
risk_level = classify_risk_level(indicators, confidence)

# Calculate profile confidence from links
profile_confidence = compute_identity_risk_score(links, indicators)

DEPENDENCIES:
-------------
- typing: Type hints for optional parameters
- logging: Debug and error reporting
- datetime: Date calculations for freshness decay

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Base confidence scores by link type
BASE_SCORES = {
    "exact_match": 1.0,          # Same identifier found on two platforms
    "registered_with": 0.9,      # Phone registered to email
    "breach_linked": 0.8,        # Breach data links email to name
    "found_in_breach": 0.8,      # Same as above
    "discovered_from": 0.7,      # Generic discovery link
    "username_pattern": 0.6,     # Similar username across platforms
    "image_match": 0.7,          # Reverse image search match
    "temporal_match": 0.4,       # Account created same week
    "possible_username": 0.5,    # Username derived from email local part
    "email_local_part": 0.5,     # Same as above
    "has_risk": 0.3,             # Risk indicator link
}


def compute_link_confidence(
    link_type: str,
    data_age_days: Optional[int] = None,
    source_reliability: float = 1.0,
) -> float:
    """
    Compute confidence score for a link between artifacts.

    Factors:
    - Base score from link type
    - Data freshness decay
    - Source reliability multiplier
    """
    base = BASE_SCORES.get(link_type, 0.3)

    # Apply data freshness decay
    if data_age_days is not None:
        if data_age_days > 730:  # > 2 years
            base *= 0.6
        elif data_age_days > 365:  # > 1 year
            base *= 0.8

    # Apply source reliability
    score = base * source_reliability

    return round(min(score, 1.0), 3)


# Risk weights per indicator type
RISK_WEIGHTS = {
    "disposable_email_domain": 0.3,
    "disposable_email": 0.3,
    "voip_number": 0.25,
    "voip_carrier_detected": 0.25,
    "voip_phone": 0.25,
    "disposable_number_service": 0.4,
    "privacy_email_provider": 0.15,
    "invalid_email_format": 0.2,
    "invalid_number": 0.2,
    "invalid_number_format": 0.2,
    "no_exif_metadata": 0.1,
    "contains_gps_coordinates": 0.05,  # Not risky, just informational
    "possible_stock_photo": 0.35,
    "found_in_breaches": 0.2,
}


def explain_identity_risk_score(risk_indicators: list[str]) -> dict:
    """
    Compute the risk score and report what each indicator contributed.

    Two identities can reach the same score by very different routes — one
    disposable-number service, or four minor indicators — and the response to
    each differs. The breakdown also makes the 1.0 cap visible instead of
    silently swallowing evidence.
    """
    if not risk_indicators:
        return {"score": 0.0, "raw_total": 0.0, "signals": [], "capped": False}

    signals = []
    for indicator in sorted(set(risk_indicators)):
        # Dynamic indicators like "found_in_7_breaches" scale with the count
        if indicator.startswith("found_in_") and indicator.endswith("_breaches"):
            try:
                count = int(indicator.split("_")[2])
                weight = min(count * 0.05, 0.3)
                detail = f"{count} breach(es) × 0.05, capped at 0.30"
            except (ValueError, IndexError):
                weight = 0.2
                detail = "breach count unparseable; default weight"
        else:
            weight = RISK_WEIGHTS.get(indicator, 0.1)
            detail = ("listed weight" if indicator in RISK_WEIGHTS
                      else "unrecognised indicator; default weight")
        signals.append({
            "indicator": indicator,
            "weight": round(weight, 3),
            "detail": detail,
        })

    raw = sum(s["weight"] for s in signals)
    return {
        "score": round(min(raw, 1.0), 3),
        "raw_total": round(raw, 3),
        "signals": signals,
        "capped": raw > 1.0,
    }


def compute_identity_risk_score(risk_indicators: list[str]) -> float:
    """
    Compute overall risk score for an identity based on accumulated risk indicators.

    Returns 0.0 (no risk) to 1.0 (maximum risk).
    """
    return explain_identity_risk_score(risk_indicators)["score"]


def classify_risk_level(risk_score: float) -> str:
    """Classify risk score into human-readable level."""
    if risk_score >= 0.8:
        return "critical"
    if risk_score >= 0.6:
        return "high"
    if risk_score >= 0.4:
        return "medium"
    if risk_score >= 0.2:
        return "low"
    return "minimal"

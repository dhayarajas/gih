"""Strict-match policy shared by every OSINT source.

Tools disagree about what counts as a hit: a search engine returns pages that
merely mention a handle, a status-200 profile check proves nothing on sites with
soft 404s, and a full name expands into guessed username variants. When strict
matching is on, only findings that carry the *exact* target value survive, so a
report contains full matches rather than plausible ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from src.config.loader import get_config

# A match flanked by any character a handle may itself contain is part of a
# longer handle (octocat-bot, octocat.dev) and therefore a different identity.
# Everything else -- URL separators, quotes, whitespace -- is a clean boundary.
_HANDLE_CHAR = re.compile(r"[A-Za-z0-9_.\-]")

# Artifact types whose value names an account and must therefore carry the
# target's exact handle to be kept.
ACCOUNT_ARTIFACT_TYPES = frozenset({"username_presence", "email_presence", "platform_presence"})

# Artifact types a search engine derives from a result page. They are only worth
# keeping when they are the target itself, not a neighbouring handle.
DERIVED_IDENTITY_TYPES = frozenset({"username", "email"})

# Seed types that name a person's handle. Only these can judge whether a finding
# is "the same identity": a domain or a full name legitimately yields handles and
# addresses that look nothing like it, and those pivots must survive.
HANDLE_TARGET_TYPES = frozenset({"username", "email"})


@dataclass(frozen=True)
class MatchPolicy:
    """How strictly a finding must match the target it was derived from."""

    enabled: bool = True
    # Drop platform hits established by a bare HTTP 200 with no content proof.
    require_validated_presence: bool = True
    # Expand a full name into guessed username candidates (first.last, flast...).
    # On by default: a fullname seed reaches no tool otherwise, and each
    # candidate still has to match exactly wherever it is searched.
    allow_name_variants: bool = True
    # Minimum probability for a face/image match to be recorded.
    min_image_probability: float = 0.9


_DEFAULT_POLICY = MatchPolicy()


def get_match_policy() -> MatchPolicy:
    """Read ``investigation.strict_match`` from config.yaml."""
    try:
        investigation = get_config().get("investigation", {}) or {}
        settings = investigation.get("strict_match")
        if not isinstance(settings, dict):
            return _DEFAULT_POLICY
        return MatchPolicy(
            enabled=bool(settings.get("enabled", _DEFAULT_POLICY.enabled)),
            require_validated_presence=bool(settings.get(
                "require_validated_presence", _DEFAULT_POLICY.require_validated_presence
            )),
            allow_name_variants=bool(settings.get(
                "allow_name_variants", _DEFAULT_POLICY.allow_name_variants
            )),
            min_image_probability=float(settings.get(
                "min_image_probability", _DEFAULT_POLICY.min_image_probability
            )),
        )
    except Exception:
        return _DEFAULT_POLICY


def contains_exact(haystack: Optional[str], target: str) -> bool:
    """True when ``target`` appears in ``haystack`` as a whole token.

    ``octocat`` matches ``https://github.com/octocat`` and ``github.com:octocat``
    but not ``octocat99`` or ``the_octocat``.
    """
    if not haystack or not target:
        return False

    hay = haystack.lower()
    needle = target.lower()
    start = hay.find(needle)

    while start != -1:
        before = hay[start - 1] if start > 0 else ""
        after_index = start + len(needle)
        after = hay[after_index] if after_index < len(hay) else ""
        if not _HANDLE_CHAR.match(before or " ") and not _HANDLE_CHAR.match(after or " "):
            return True
        start = hay.find(needle, start + 1)

    return False


def _target_handles(target: str, target_type: str) -> list[str]:
    """The forms of the target a finding may legitimately spell it with."""
    if target_type == "email":
        # A profile URL carries the local part, not the whole address.
        return [target, target.split("@", 1)[0]]
    return [target]


def is_full_match(
    artifact: dict[str, Any],
    target: str,
    target_type: str = "username",
) -> bool:
    """Whether a discovered artifact fully matches the target it came from.

    Only claims of the form "this account belongs to the target" are judged, and
    only when the target itself is a handle. A domain or full name legitimately
    yields handles and addresses that do not contain it (theHarvester emails, the
    username behind an address, name variants), and infrastructure findings
    (subdomains, ports, DNS records, breaches) are never identity claims.
    """
    if target_type not in HANDLE_TARGET_TYPES:
        return True

    artifact_type = artifact.get("type", "")
    handles = _target_handles(target, target_type)

    if artifact_type in ACCOUNT_ARTIFACT_TYPES:
        return any(
            contains_exact(artifact.get(key), handle)
            for key in ("value", "username", "url", "profile_url")
            for handle in handles
        )

    # A handle or address derived from another handle is only the same identity
    # when it is that handle; a neighbouring one belongs to somebody else.
    if artifact_type == target_type:
        value = (artifact.get("value") or "").lower()
        return any(value == handle.lower() for handle in handles)

    return True


def filter_full_matches(
    artifacts: list[dict[str, Any]],
    target: str,
    policy: Optional[MatchPolicy] = None,
    target_type: str = "username",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split artifacts into (kept, dropped) according to the match policy."""
    policy = policy or get_match_policy()
    if not policy.enabled:
        return list(artifacts), []

    kept, dropped = [], []
    for artifact in artifacts:
        (kept if is_full_match(artifact, target, target_type) else dropped).append(artifact)
    return kept, dropped

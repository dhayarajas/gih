"""Extra report data builders used by the standard HTML report."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any, Optional

from src.correlation.linker import IDENTITY_ARTIFACT_TYPES
from src.modules.external_tools import TOOL_ARTIFACT_TYPES
from src.storage import database as db

logger = logging.getLogger(__name__)

DEFAULT_SECTIONS = (
    "leaks",
    "identities",
    "summary",
    "tools",
    "platforms",
    "graph",
    "artifacts",
    "evidence",
    "orphans",
    "geo",
    "audit",
    "comments",
    "cross",
    "delta",
    "filters",
)

REDACT_TYPES = {"phone", "email", "image", "fullname", "gps_coordinates", "location"}
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


def load_reporting_config() -> dict:
    """Load reporting.* from YAML with safe defaults."""
    try:
        from src.config.loader import get_config
        cfg = get_config().get("reporting", {}) or {}
    except Exception:
        cfg = {}
    branding = cfg.get("branding") or {}
    watermark = cfg.get("watermark") or {}
    template = cfg.get("template") or "standard"
    if template in ("default", "html"):
        template = "standard"
    return {
        "auto_generate": bool(cfg.get("auto_generate", True)),
        "default_format": cfg.get("default_format") or "html",
        "output_dir": cfg.get("output_dir") or "./reports",
        "template": template,
        "include_execution_stats": bool(cfg.get("include_execution_stats", True)),
        "branding": {
            "enabled": bool(branding.get("enabled", True)),
            "organization_name": branding.get("organization_name") or "Ghost Identity Hunter",
            "logo_path": branding.get("logo_path"),
            "primary_color": branding.get("primary_color") or "#1e3a5f",
            "secondary_color": branding.get("secondary_color") or "#2c5282",
            "accent_color": branding.get("accent_color") or "#c53030",
            "text_color": branding.get("text_color") or "#ffffff",
            "background_color": branding.get("background_color") or "#f5f7fa",
            "font_family": branding.get("font_family") or "'Segoe UI', 'Roboto', Arial, sans-serif",
            "custom_css": branding.get("custom_css"),
        },
        "watermark": {
            "enabled": bool(watermark.get("enabled", False)),
            "text": watermark.get("text") or "CONFIDENTIAL",
            "opacity": float(watermark.get("opacity", 0.1)),
            "position": watermark.get("position") or "center",
        },
    }


def parse_sections(raw: Optional[str | list[str]]) -> set[str]:
    """Parse comma-separated section list; empty/None means all."""
    if not raw:
        return set(DEFAULT_SECTIONS)
    if isinstance(raw, (list, tuple, set)):
        items = [str(x).strip().lower() for x in raw if str(x).strip()]
    else:
        items = [p.strip().lower() for p in str(raw).split(",") if p.strip()]
    if not items or "all" in items:
        return set(DEFAULT_SECTIONS)
    return set(items) & set(DEFAULT_SECTIONS) or set(DEFAULT_SECTIONS)


# Event kinds shown on the timeline, with the reading each carries.
TIMELINE_KINDS: dict[str, str] = {
    "discovery": "Discovered by the investigation",
    "breach": "Credentials exposed in a breach",
    "indexed": "Breach published to a breach index",
    "registration": "Domain or account registered",
    "expiry": "Registration expires",
    "updated": "Registration record updated",
    "capture": "Photograph taken",
    "archive": "Page archived",
    "activity": "Account activity",
}

# Metadata keys that carry a date, mapped to the kind of event they describe.
_DATE_KEYS = {
    "breach_date": "breach",
    "breachdate": "breach",
    "added_date": "indexed",
    "addeddate": "indexed",
    "leak_date": "breach",
    "creation_date": "registration",
    "created_at": "registration",
    "created_date": "registration",
    "registered_on": "registration",
    "registration_date": "registration",
    "expiration_date": "expiry",
    "expiry_date": "expiry",
    "updated_date": "updated",
    "last_updated": "updated",
    "date_taken": "capture",
    "datetimeoriginal": "capture",
    "createdate": "capture",
    "timestamp": "archive",
    "first_capture": "archive",
    "last_capture": "archive",
    "last_activity": "activity",
    "last_seen": "activity",
    "joined": "activity",
    "join_date": "activity",
}

# Keys that name the same moment. A source often supplies several of them for
# one artifact -- EXIF carries CreateDate beside DateTimeOriginal, whois spells
# creation half a dozen ways -- and emitting each would plot one occurrence
# repeatedly, so only the first key present in a group is used.
_DATE_KEY_ALIASES = (
    ("breach_date", "breachdate", "leak_date"),
    ("added_date", "addeddate"),
    ("date_taken", "datetimeoriginal", "createdate"),
    ("creation_date", "created_at", "created_date", "registered_on", "registration_date"),
    ("expiration_date", "expiry_date"),
    ("updated_date", "last_updated"),
    ("last_activity", "last_seen"),
    ("joined", "join_date"),
)

_ALIAS_RANK = {
    key: (group_index, key_index)
    for group_index, group in enumerate(_DATE_KEY_ALIASES)
    for key_index, key in enumerate(group)
}

# Artifact types whose value is itself a date.
_DATE_VALUE_TYPES = {"creation_date": "capture"}

_WAYBACK_TS = re.compile(r"^\d{14}$")
_EXIF_TS = re.compile(r"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}:\d{2}:\d{2})")
_ISO_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def parse_event_date(value) -> Optional[str]:
    """Normalise a tool-supplied date to ISO 8601, or None if it isn't one.

    Dates arrive in whatever the source emits: EXIF colons, Wayback's packed
    timestamps, whois strings, HIBP ISO dates. Anything unrecognised is
    dropped rather than guessed, since a wrong date on a timeline is worse
    than a missing one.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        value = str(int(value))
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    if _WAYBACK_TS.match(text):
        return (f"{text[0:4]}-{text[4:6]}-{text[6:8]}"
                f"T{text[8:10]}:{text[10:12]}:{text[12:14]}")

    exif = _EXIF_TS.match(text)
    if exif:
        return f"{exif.group(1)}-{exif.group(2)}-{exif.group(3)}T{exif.group(4)}"

    iso = _ISO_DATE.search(text)
    if iso:
        rest = text[iso.end():]
        time_part = re.match(r"[ T](\d{2}:\d{2}(:\d{2})?)", rest)
        return f"{iso.group(0)}T{time_part.group(1)}" if time_part else iso.group(0)

    return None


def _preferred_date_keys(pairs) -> list:
    """Drop metadata keys that merely repeat a moment another key already names."""
    chosen: dict[int, tuple] = {}
    passthrough = []
    for key, raw in pairs:
        rank = _ALIAS_RANK.get(key.lower())
        if rank is None:
            passthrough.append((key, raw))
            continue
        group, position = rank
        if group not in chosen or position < chosen[group][0]:
            chosen[group] = (position, key, raw)
    return passthrough + [(key, raw) for _, key, raw in chosen.values()]


def build_timeline(artifacts: list) -> list[dict]:
    """Build a typed chronology from discovery times and artifact metadata.

    Discovery order says when the investigation looked, not when anything
    happened to the subject. Breach dates, EXIF capture times, archive
    snapshots and registration dates are already in artifact metadata but were
    never plotted; each becomes its own event so a persona's lifecycle is
    readable rather than implied.
    """
    events = []
    for artifact in artifacts:
        artifact_id = artifact.get("artifact_id")
        atype = artifact.get("artifact_type", "unknown")
        value = artifact.get("value", "")
        source = artifact.get("source", "unknown")

        discovered = parse_event_date(artifact.get("discovered_at"))
        if discovered:
            events.append({
                "when": discovered,
                "kind": "discovery",
                "artifact_id": artifact_id,
                "artifact_type": atype,
                "value": value,
                "source": source,
                "detail": f"depth {artifact.get('depth', 0)}",
            })

        if atype in _DATE_VALUE_TYPES:
            when = parse_event_date(value)
            if when:
                events.append({
                    "when": when,
                    "kind": _DATE_VALUE_TYPES[atype],
                    "artifact_id": artifact_id,
                    "artifact_type": atype,
                    "value": value,
                    "source": source,
                    "detail": atype.replace("_", " "),
                })

        preferred = _preferred_date_keys(
            _flatten_metadata(_parse_metadata_field(artifact.get("metadata")))
        )
        for key, raw in preferred:
            kind = _DATE_KEYS.get(key.lower())
            if not kind:
                continue
            when = parse_event_date(raw)
            if not when:
                continue
            events.append({
                "when": when,
                "kind": kind,
                "artifact_id": artifact_id,
                "artifact_type": atype,
                "value": value,
                "source": source,
                "detail": key.replace("_", " "),
            })

    seen = set()
    unique = []
    for event in sorted(events, key=lambda e: (e["when"], e["kind"], e["value"])):
        key = (event["when"], event["kind"], event["artifact_id"], event["detail"])
        if key in seen:
            continue
        seen.add(key)
        event["kind_label"] = TIMELINE_KINDS.get(event["kind"], event["kind"])
        unique.append(event)
    return unique


def _parse_metadata_field(raw) -> dict:
    """Parse an artifact metadata column into a dict, tolerating bad JSON."""
    if isinstance(raw, dict):
        return raw
    if not raw or not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _flatten_metadata(data, depth: int = 0):
    """Yield (key, value) pairs from nested metadata, bounded in depth."""
    if depth > 3:
        return
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                yield from _flatten_metadata(value, depth + 1)
            else:
                yield str(key), value
    elif isinstance(data, list):
        for item in data[:50]:
            yield from _flatten_metadata(item, depth + 1)


def build_preserved_evidence(
    conn: sqlite3.Connection,
    investigation_id: str,
    redact: bool = False,
) -> dict:
    """Summarise the preserved raw tool outputs and re-verify their digests.

    Each capture is re-hashed at report time, so the report states whether the
    stored file still matches what was collected instead of merely asserting a
    chain of custody. Under redaction the command line and target are dropped:
    both embed the seed value, while the digest and timing do not.
    """
    from src.storage import evidence as evidence_store

    try:
        rows = db.get_evidence(conn, investigation_id)
    except sqlite3.Error:
        rows = []

    items = evidence_store.verify(rows)
    for item in items:
        if redact:
            item["command"] = None
            item["target"] = None
    counts = Counter(item["status"] for item in items)
    return {
        "enabled": bool(items),
        "items": items,
        "total": len(items),
        "total_bytes": sum(int(item.get("byte_size") or 0) for item in items),
        "verified": counts.get("verified", 0),
        "modified": counts.get("modified", 0),
        "missing": counts.get("missing", 0),
        "intact": bool(items) and counts.get("verified", 0) == len(items),
    }


_URL_METADATA_KEYS = ("profile_url", "url", "source_url", "permalink", "archive_url")


def build_source_citations(
    conn: sqlite3.Connection,
    investigation_id: str,
    artifacts: list,
    redact: bool = False,
) -> dict[str, list[dict]]:
    """Cite, per artifact, the run that produced it: command, version, timing.

    A reader who cannot see the command, the tool version and when it ran
    cannot reproduce a finding or judge whether it has gone stale. Captures
    are matched to an artifact by the tool named in its ``source``, preferring
    a run whose target is the artifact's own value and otherwise the last run
    of that tool to finish before the artifact was recorded -- the run that
    could have produced it. Unmatched artifacts get no citation rather than a
    guessed one.

    Under redaction the command, target and URL are dropped: each embeds the
    seed value, while the tool, version, timing and digest do not.
    """
    try:
        rows = db.get_evidence(conn, investigation_id)
    except sqlite3.Error:
        return {}

    by_tool: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_tool[(row.get("tool") or "").lower()].append(row)
    for runs in by_tool.values():
        runs.sort(key=lambda r: r.get("captured_at") or "")

    citations: dict[str, list[dict]] = {}
    for artifact in artifacts:
        found = []
        run = _matching_run(by_tool.get((artifact.get("source") or "").lower(), []), artifact)
        if run:
            found.append(_tool_citation(run, redact))
        found.extend(_url_citations(artifact, redact))
        if found:
            citations[artifact["artifact_id"]] = found
    return citations


def _matching_run(runs: list[dict], artifact: dict) -> Optional[dict]:
    """The capture that best accounts for an artifact, or None."""
    if not runs:
        return None
    value = artifact.get("value")
    for run in runs:
        if run.get("target") and run["target"] == value:
            return run

    discovered_at = artifact.get("discovered_at") or ""
    earlier = [r for r in runs if (r.get("captured_at") or "") <= discovered_at]
    return earlier[-1] if earlier else None


def _tool_citation(run: dict, redact: bool) -> dict:
    return {
        "kind": "tool",
        "tool": run.get("tool"),
        "tool_version": _version_only(run.get("tool"), run.get("tool_version")),
        "command": None if redact else run.get("command"),
        "target": None if redact else run.get("target"),
        "captured_at": run.get("captured_at"),
        "duration_seconds": run.get("duration_seconds"),
        "exit_status": run.get("exit_status"),
        "sha256": run.get("sha256"),
    }


def _version_only(tool: Optional[str], version: Optional[str]) -> Optional[str]:
    """Drop the tool's own name from its version banner ("holehe 1.61" -> "1.61")."""
    if not version or not tool:
        return version
    stripped = version.strip()
    if stripped.lower().startswith(tool.lower()):
        remainder = stripped[len(tool):].lstrip(" :,-")
        # A leading "v" is only a version marker when a number follows it;
        # otherwise it is the first letter of a word such as "version 7.94".
        if remainder[:1].lower() == "v" and remainder[1:2].isdigit():
            remainder = remainder[1:]
        stripped = remainder
    return stripped or version


def _url_citations(artifact: dict, redact: bool) -> list[dict]:
    """URLs the artifact itself names as its origin."""
    if redact:
        return []
    metadata = _parse_metadata_field(artifact.get("metadata"))
    cited: list[dict] = []
    for key in _URL_METADATA_KEYS:
        url = metadata.get(key)
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        if any(item["url"] == url for item in cited):
            continue
        cited.append({"kind": "url", "url": url, "field": key})
    return cited


def build_evidence_chains(artifacts: list, links: list, max_chains: int = 40) -> list[dict]:
    """Build seed -> discovery paths using link evidence."""
    by_id = {a["artifact_id"]: a for a in artifacts}
    outgoing: dict[str, list] = defaultdict(list)
    for link in links:
        outgoing[link["source_artifact"]].append(link)

    seeds = [a for a in artifacts if (a.get("source") or "").lower() == "seed" or a.get("depth", 0) == 0]
    chains = []
    for seed in seeds:
        stack = [(seed["artifact_id"], [seed["artifact_id"]], [])]
        seen_paths = set()
        while stack and len(chains) < max_chains:
            current, path, evidence = stack.pop()
            children = outgoing.get(current, [])
            if not children and len(path) > 1:
                key = tuple(path)
                if key not in seen_paths:
                    seen_paths.add(key)
                    chains.append(_format_chain(by_id, path, evidence))
                continue
            for link in children:
                target = link["target_artifact"]
                if target in path:
                    continue
                new_path = path + [target]
                new_ev = evidence + [{
                    "link_type": link.get("link_type"),
                    "evidence": link.get("evidence") or "",
                    "confidence": link.get("confidence") or 0,
                }]
                if len(new_path) >= 5 or not outgoing.get(target):
                    key = tuple(new_path)
                    if key not in seen_paths:
                        seen_paths.add(key)
                        chains.append(_format_chain(by_id, new_path, new_ev))
                else:
                    stack.append((target, new_path, new_ev))
    return chains[:max_chains]


def _format_chain(by_id: dict, path: list[str], evidence: list[dict]) -> dict:
    steps = []
    for i, aid in enumerate(path):
        art = by_id.get(aid) or {}
        step = {
            "artifact_id": aid,
            "type": art.get("artifact_type", "?"),
            "value": art.get("value", aid),
            "source": art.get("source"),
            "confidence": art.get("confidence") or 0,
        }
        if i and i - 1 < len(evidence):
            step["via"] = evidence[i - 1]
        steps.append(step)
    narrative = " -> ".join(f"{s['type']}:{s['value']}" for s in steps)
    return {"steps": steps, "narrative": narrative, "length": len(steps)}


LEAK_ARTIFACT_TYPE = "leak_record"
# Fields worth surfacing first inside a leaked record; anything else follows in
# the order the API returned it.
_LEAK_FIELD_ORDER = (
    "FullName", "Name", "NickName", "Email", "Phone", "Password", "Passwordv2",
    "Address", "BirthDate", "Document",
)


def build_leak_findings(artifacts: list, redact: bool = False) -> dict:
    """Group LeakOSINT breach records by the database they came from.

    Returned separately from the generic artifact table because a leak hit is
    the strongest identity evidence an investigation can get: the report leads
    with it. Absent records the result is empty and the section is skipped.
    """
    def _sort_key(item: tuple) -> tuple:
        key = item[0]
        return (_LEAK_FIELD_ORDER.index(key) if key in _LEAK_FIELD_ORDER else len(_LEAK_FIELD_ORDER), key)

    groups: dict[str, dict] = {}
    for art in artifacts:
        if (art.get("artifact_type") or "") != LEAK_ARTIFACT_TYPE:
            continue
        raw_meta = art.get("metadata")
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except (ValueError, TypeError):
                meta = {}
        else:
            meta = raw_meta or {}
        if not isinstance(meta, dict):
            meta = {}

        database = str(meta.get("database") or "Unknown database")
        group = groups.setdefault(
            database,
            {"database": database, "info": str(meta.get("info") or ""), "queries": [], "records": []},
        )
        query = meta.get("query")
        if query and query not in group["queries"]:
            group["queries"].append(query)

        fields = meta.get("fields") if isinstance(meta.get("fields"), dict) else {}
        group["records"].append({
            "artifact_id": art.get("artifact_id"),
            "value": art.get("value"),
            "confidence": art.get("confidence") or 0,
            "query": query,
            "query_type": meta.get("query_type"),
            "fields": [
                {
                    "key": str(key).replace("_", " "),
                    "value": "[REDACTED]" if redact else ("-" if value in (None, "") else str(value)),
                }
                for key, value in sorted(fields.items(), key=_sort_key)
            ],
        })

    databases = sorted(groups.values(), key=lambda g: (-len(g["records"]), g["database"]))
    return {
        "databases": databases,
        "database_count": len(databases),
        "record_count": sum(len(g["records"]) for g in databases),
        "queries": sorted({q for g in databases for q in g["queries"]}),
    }


def build_orphan_findings(artifacts: list, correlation) -> list[dict]:
    """Tool / non-identity artifacts not attributed to any identity profile."""
    attributed_values: set[tuple[str, str]] = set()
    for identity in getattr(correlation, "identities", []) or []:
        for val in getattr(identity, "artifacts", []) or []:
            # IdentityProfile.artifacts is a flat list of values (strings)
            if isinstance(val, str):
                attributed_values.add(val)
        for field, atype in (
            ("phones", "phone"),
            ("emails", "email"),
            ("usernames", "username"),
            ("images", "image"),
        ):
            for val in getattr(identity, field, []) or []:
                attributed_values.add(val)
        for finding in getattr(identity, "tool_findings", []) or []:
            if finding.get("value"):
                attributed_values.add(finding["value"])

    orphans = []
    for art in artifacts:
        value = art.get("value")
        atype = art.get("artifact_type")
        if value in attributed_values:
            continue
        if (art.get("source") or "").lower() == "seed" and atype in IDENTITY_ARTIFACT_TYPES:
            continue
        orphans.append({
            "artifact_id": art.get("artifact_id"),
            "type": atype,
            "value": value,
            "source": art.get("source"),
            "confidence": art.get("confidence") or 0,
            "depth": art.get("depth") or 0,
            "reason": "No identity-anchor attribution",
        })
    return orphans


def build_actionable_recommendations(
    artifacts: list,
    links: list,
    presences: list,
    correlation,
    risk_levels: list,
    tool_metrics: dict,
    orphans: list,
) -> list[dict]:
    """Concrete next-step recommendations tied to specific findings."""
    recs: list[dict] = []

    for i, identity in enumerate(getattr(correlation, "identities", []) or []):
        level = risk_levels[i] if i < len(risk_levels) else "unknown"
        if level in ("critical", "high"):
            sample = (getattr(identity, "emails", None) or getattr(identity, "usernames", None) or ["(unnamed)"])[0]
            recs.append({
                "priority": "critical",
                "category": "High-Risk Identity",
                "action": f"Prioritize review of {identity.profile_id} ({sample})",
                "details": f"Risk={level}; indicators: {', '.join(identity.risk_indicators[:5]) or 'n/a'}",
                "artifact_ref": sample,
            })

    unverified = [p for p in presences if not p.get("is_verified")]
    for p in unverified[:5]:
        platform = p.get("platform_name") or "unknown"
        user = p.get("username") or ""
        recs.append({
            "priority": "medium",
            "category": "Presence Validation",
            "action": f"Manually verify {platform} account '{user}'",
            "details": "Presence rests on HTTP status only; confirm the profile page content.",
            "artifact_ref": p.get("profile_url") or user,
        })

    low_conf = [a for a in artifacts if (a.get("confidence") or 0) < 0.5 and (a.get("source") or "") != "seed"]
    for a in low_conf[:5]:
        recs.append({
            "priority": "medium",
            "category": "Low Confidence",
            "action": f"Re-check {a.get('artifact_type')}:{a.get('value')}",
            "details": f"Confidence {(a.get('confidence') or 0):.0%} from source {a.get('source')}",
            "artifact_ref": a.get("value"),
        })

    for silent in (tool_metrics.get("silent_tools") or [])[:8]:
        recs.append({
            "priority": "low",
            "category": "Silent Tool",
            "action": f"Confirm whether '{silent}' should have run",
            "details": "Integrated tool produced no artifacts (missing binary, not dispatched, or empty result).",
            "artifact_ref": silent,
        })

    for orphan in orphans[:5]:
        recs.append({
            "priority": "medium",
            "category": "Unattributed Finding",
            "action": f"Link or discard orphan {orphan['type']}:{orphan['value']}",
            "details": "Finding is not attached to an identity profile; seed an identity artifact if attribution is expected.",
            "artifact_ref": orphan["value"],
        })

    breach_like = [a for a in artifacts if "breach" in (a.get("artifact_type") or "").lower()
                   or (a.get("source") or "").lower() in ("breach", "hibp", "pwned", "email_breach")]
    for a in breach_like[:3]:
        recs.append({
            "priority": "high",
            "category": "Breach Follow-up",
            "action": f"Analyze breach exposure for {a.get('value')}",
            "details": "Look for credential reuse across attributed platforms.",
            "artifact_ref": a.get("value"),
        })

    # Deduplicate by action text
    seen = set()
    unique = []
    for rec in recs:
        if rec["action"] in seen:
            continue
        seen.add(rec["action"])
        unique.append(rec)
    return unique


def enrich_tool_status(tool_metrics: dict) -> dict:
    """Annotate silent tools with host availability when possible."""
    metrics = dict(tool_metrics)
    silent = list(metrics.get("silent_tools") or [])
    status_rows = []
    try:
        from src.utils.tool_checker import get_tool_checker
        checker = get_tool_checker()
        for tool in sorted(set(TOOL_ARTIFACT_TYPES)):
            available = checker.is_available(tool)
            produced = tool not in silent and any(
                t.get("tool") == tool and t.get("kind") == "tool"
                for t in metrics.get("tools") or []
            )
            if produced:
                state = "produced_output"
            elif not available:
                state = "not_installed"
            else:
                state = "silent_or_not_dispatched"
            status_rows.append({"tool": tool, "available": available, "state": state})
    except Exception as exc:
        logger.debug("Tool status enrichment skipped: %s", exc)
        for tool in silent:
            status_rows.append({"tool": tool, "available": None, "state": "silent_or_not_dispatched"})
    metrics["tool_status"] = status_rows
    metrics["not_installed"] = [r["tool"] for r in status_rows if r["state"] == "not_installed"]
    metrics["silent_installed"] = [r["tool"] for r in status_rows if r["state"] == "silent_or_not_dispatched"]
    return metrics


def build_cross_investigation(conn, investigation_id: str, artifacts: list, limit: int = 25) -> list[dict]:
    """Find the same artifact values in other investigations."""
    values = {
        (a.get("artifact_type"), a.get("value"))
        for a in artifacts
        if a.get("value") and (a.get("source") or "") != "seed" or a.get("artifact_type") in IDENTITY_ARTIFACT_TYPES
    }
    hits = []
    try:
        for atype, value in list(values)[:200]:
            rows = conn.execute(
                "SELECT investigation_id, artifact_type, value, source, confidence "
                "FROM artifacts WHERE artifact_type = ? AND value = ? AND investigation_id != ? "
                "LIMIT 5",
                (atype, value, investigation_id),
            ).fetchall()
            for row in rows:
                hits.append(dict(row) if hasattr(row, "keys") else {
                    "investigation_id": row[0],
                    "artifact_type": row[1],
                    "value": row[2],
                    "source": row[3],
                    "confidence": row[4],
                })
                if len(hits) >= limit:
                    return hits
    except Exception as exc:
        logger.debug("Cross-investigation lookup failed: %s", exc)
    return hits


def find_previous_investigation(conn, investigation_id: str) -> Optional[str]:
    """Most recent earlier investigation that started from the same seed(s).

    Re-running a seed is the common case for a diff, and requiring the analyst
    to look up the prior ID by hand is the reason the delta section is rarely
    used. Seeds are matched exactly; an investigation with different seeds is
    not a prior run of this one.
    """
    seeds = {
        (a.get("artifact_type"), a.get("value"))
        for a in db.get_artifacts(conn, investigation_id)
        if (a.get("source") or "") == "seed"
    }
    if not seeds:
        return None

    current = db.get_investigation(conn, investigation_id) or {}
    created_at = current.get("created_at") or ""

    candidates: dict[str, set] = defaultdict(set)
    try:
        rows = conn.execute(
            "SELECT a.investigation_id, a.artifact_type, a.value FROM artifacts a "
            "JOIN investigations i ON i.investigation_id = a.investigation_id "
            "WHERE a.source = 'seed' AND a.investigation_id != ? AND i.created_at < ? "
            "ORDER BY i.created_at DESC",
            (investigation_id, created_at),
        ).fetchall()
    except sqlite3.Error:
        return None

    order: list[str] = []
    for row in rows:
        inv_id = row[0]
        if inv_id not in candidates:
            order.append(inv_id)
        candidates[inv_id].add((row[1], row[2]))

    for inv_id in order:
        if candidates[inv_id] == seeds:
            return inv_id
    return None


# Artifact fields whose change between runs is worth reporting.
_DELTA_FIELDS = ("source", "confidence", "depth")


def build_delta_report(
    conn,
    investigation_id: str,
    compare_id: Optional[str],
    redact: bool = False,
) -> dict:
    """Compare two runs: added, removed, and changed artifacts and accounts.

    An artifact present in both runs is not necessarily unchanged — its
    confidence, the tool that reported it, or its metadata may all have moved,
    and that movement is often the finding. Pass compare_id="auto" to diff
    against the previous run of the same seeds.

    The comparison reads both runs straight from the database, so under
    redaction every value it emits is masked here: the diff must not become a
    second, unmasked view of what the rest of the report hides.
    """
    empty = {
        "compare_id": compare_id, "added": [], "removed": [], "changed": [],
        "platforms_added": [], "platforms_removed": [], "enabled": False,
    }
    if not compare_id:
        return empty

    if compare_id == "auto":
        compare_id = find_previous_investigation(conn, investigation_id)
        if not compare_id:
            return {**empty, "compare_id": None,
                    "error": "No earlier investigation with the same seeds"}

    other = db.get_investigation(conn, compare_id)
    if not other:
        return {**empty, "error": f"Investigation {compare_id} not found"}

    def _keyset(inv_id: str) -> dict[tuple, dict]:
        return {
            (a.get("artifact_type"), a.get("value")): a
            for a in db.get_artifacts(conn, inv_id)
        }

    current = _keyset(investigation_id)
    baseline = _keyset(compare_id)
    added_keys = sorted(set(current) - set(baseline))
    removed_keys = sorted(set(baseline) - set(current))
    shared_keys = sorted(set(current) & set(baseline))

    changed = []
    for key in shared_keys:
        changes = _artifact_changes(baseline[key], current[key], redact)
        if changes:
            changed.append({
                "type": key[0],
                "value": mask_value(key[1], key[0]) if redact else key[1],
                "artifact_id": current[key].get("artifact_id"),
                "changes": changes,
            })

    def _platforms(inv_id: str) -> dict[str, dict]:
        return {
            (p.get("profile_url") or f"{p.get('platform_name')}:{p.get('username')}"): p
            for p in db.get_platform_presences(conn, inv_id)
        }

    current_platforms = _platforms(investigation_id)
    baseline_platforms = _platforms(compare_id)

    return {
        "enabled": True,
        "compare_id": compare_id,
        "compare_title": other.get("title"),
        "compare_created_at": other.get("created_at"),
        "added": [_delta_item(current[k], redact) for k in added_keys[:50]],
        "removed": [_delta_item(baseline[k], redact) for k in removed_keys[:50]],
        "changed": changed[:50],
        "platforms_added": [
            _platform_item(current_platforms[k], redact)
            for k in sorted(set(current_platforms) - set(baseline_platforms))[:50]
        ],
        "platforms_removed": [
            _platform_item(baseline_platforms[k], redact)
            for k in sorted(set(baseline_platforms) - set(current_platforms))[:50]
        ],
        "shared_count": len(shared_keys),
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed),
        "unchanged_count": len(shared_keys) - len(changed),
    }


def _artifact_changes(before: dict, after: dict, redact: bool = False) -> list[dict]:
    """Field- and metadata-level differences between two runs of one artifact.

    Under redaction the fact that a metadata key changed is still reported --
    that is the finding -- but neither value is shown, since a metadata value
    can hold anything the tool returned.
    """
    changes = []
    for fieldname in _DELTA_FIELDS:
        old, new = before.get(fieldname), after.get(fieldname)
        if fieldname == "confidence":
            old, new = round(old or 0, 3), round(new or 0, 3)
        if old != new:
            changes.append({
                "field": fieldname,
                "before": "-" if old in (None, "") else str(old),
                "after": "-" if new in (None, "") else str(new),
            })

    old_meta = _parse_metadata_field(before.get("metadata"))
    new_meta = _parse_metadata_field(after.get("metadata"))
    for key in sorted(set(old_meta) | set(new_meta)):
        old_value = old_meta.get(key)
        new_value = new_meta.get(key)
        if old_value == new_value:
            continue
        changes.append({
            "field": f"metadata.{key}",
            "before": "absent" if key not in old_meta else _short(old_value, redact=redact),
            "after": "absent" if key not in new_meta else _short(new_value, redact=redact),
        })
    return changes


def _short(value, limit: int = 80, redact: bool = False) -> str:
    """Render a metadata value compactly enough for a diff row."""
    if redact:
        return "[REDACTED]"
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _delta_item(art: dict, redact: bool = False) -> dict:
    value = art.get("value")
    artifact_type = art.get("artifact_type")
    return {
        "type": artifact_type,
        "value": mask_value(value, artifact_type) if redact else value,
        "source": art.get("source"),
        "confidence": art.get("confidence") or 0,
    }


def _platform_item(presence: dict, redact: bool = False) -> dict:
    username = presence.get("username")
    return {
        "platform": presence.get("platform_name"),
        "username": mask_value(username, "username") if redact else username,
        "url": "[REDACTED_URL]" if redact else presence.get("profile_url"),
    }


def load_comments(conn, investigation_id: str) -> list[dict]:
    """Load investigator notes from the comments table on the active connection."""
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                comment_id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                artifact_id TEXT,
                author TEXT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                parent_id TEXT,
                comment_type TEXT DEFAULT 'note'
            )
            """
        )
        rows = conn.execute(
            "SELECT comment_id, investigation_id, artifact_id, author, content, "
            "created_at, comment_type, parent_id FROM comments "
            "WHERE investigation_id = ? ORDER BY created_at",
            (investigation_id,),
        ).fetchall()
        return [
            {
                "comment_id": r["comment_id"] if hasattr(r, "keys") else r[0],
                "investigation_id": r["investigation_id"] if hasattr(r, "keys") else r[1],
                "artifact_id": r["artifact_id"] if hasattr(r, "keys") else r[2],
                "author": r["author"] if hasattr(r, "keys") else r[3],
                "content": r["content"] if hasattr(r, "keys") else r[4],
                "created_at": r["created_at"] if hasattr(r, "keys") else r[5],
                "comment_type": r["comment_type"] if hasattr(r, "keys") else r[6],
                "parent_id": r["parent_id"] if hasattr(r, "keys") else r[7],
            }
            for r in rows
        ]
    except Exception as exc:
        logger.debug("Comments unavailable: %s", exc)
        return []


def _redact_leak_artifact(artifact: dict) -> None:
    """Mask a leaked record in place, keeping only its database and field names."""
    meta = artifact.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (ValueError, TypeError):
            meta = None
    if not isinstance(meta, dict):
        artifact["value"] = "[REDACTED]"
        artifact["metadata"] = None
        return

    database = str(meta.get("database") or "Unknown database")
    fields = meta.get("fields") if isinstance(meta.get("fields"), dict) else {}
    meta["fields"] = dict.fromkeys(fields, "[REDACTED]")
    if meta.get("query"):
        meta["query"] = "[REDACTED]"
    artifact["value"] = f"{database}: [REDACTED]"
    artifact["metadata"] = json.dumps(meta)


def mask_value(value: str, artifact_type: str = "") -> str:
    """Mask a value the way the report's redaction pass masks it."""
    if not value:
        return value
    value = str(value)
    atype = artifact_type or ""
    if atype in REDACT_TYPES or _EMAIL_RE.fullmatch(value) or _PHONE_RE.fullmatch(value.strip()):
        if "@" in value:
            local, _, domain = value.partition("@")
            return f"{local[:1]}***@{domain}"
        if len(value) <= 4:
            return "****"
        return value[:2] + "***" + value[-2:]
    return _EMAIL_RE.sub(lambda m: m.group(0)[:1] + "***@redacted",
                         _PHONE_RE.sub("***-****", value))


def redact_payload(
    artifacts: list,
    links: list,
    presences: list,
    correlation,
    enabled: bool,
) -> tuple[list, list, list, Any]:
    """Return redacted copies when enabled; otherwise originals."""
    if not enabled:
        return artifacts, links, presences, correlation

    _mask = mask_value

    arts = deepcopy(artifacts)
    for a in arts:
        if (a.get("artifact_type") or "") == LEAK_ARTIFACT_TYPE:
            # A leaked row is sensitive in full -- passwords and documents are
            # not patterns _mask recognizes -- so only the database name and the
            # field names survive, in the value and the drill-down alike.
            _redact_leak_artifact(a)
            continue
        a["value"] = _mask(str(a.get("value") or ""), a.get("artifact_type") or "")

    pres = deepcopy(presences)
    for p in pres:
        if p.get("username"):
            p["username"] = _mask(str(p["username"]), "username")
        if p.get("profile_url"):
            p["profile_url"] = "[REDACTED_URL]"
        if p.get("profile_image_url"):
            p["profile_image_url"] = None
        if p.get("display_name"):
            p["display_name"] = _mask(str(p["display_name"]), "fullname")

    corr = deepcopy(correlation)
    for identity in getattr(corr, "identities", []) or []:
        identity.phones = [_mask(v, "phone") for v in identity.phones]
        identity.emails = [_mask(v, "email") for v in identity.emails]
        identity.usernames = [_mask(v, "username") for v in identity.usernames]
        identity.images = ["[REDACTED_IMAGE]" for _ in identity.images]
        for platform in identity.platforms or []:
            if isinstance(platform, dict):
                if platform.get("username"):
                    platform["username"] = _mask(str(platform["username"]), "username")
                if platform.get("url"):
                    platform["url"] = "[REDACTED_URL]"
        for finding in getattr(identity, "tool_findings", []) or []:
            if finding.get("value"):
                finding["value"] = _mask(str(finding["value"]), finding.get("type") or "")

    return arts, links, pres, corr


def load_custom_css(path: Optional[str]) -> str:
    if not path:
        return ""
    try:
        return Path_read(path)
    except Exception:
        return ""


def Path_read(path: str) -> str:
    from pathlib import Path
    return Path(path).read_text(encoding="utf-8")


def _hex_luminance(color: Optional[str]) -> float:
    """Relative luminance of a #RRGGBB color (0=black, 1=white)."""
    if not color or not isinstance(color, str):
        return 1.0
    value = color.strip().lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    if len(value) != 6:
        return 1.0
    try:
        r, g, b = (int(value[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
    except ValueError:
        return 1.0
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def branding_css(branding: dict, watermark: dict) -> str:
    """Inline CSS variables + optional watermark overlay.

    When the configured page background is dark, force white headings and
    light body text so section titles stay readable.
    """
    bg = branding.get("background_color") or "#f5f7fa"
    text = branding.get("text_color") or "#ffffff"
    dark_bg = _hex_luminance(bg) < 0.45
    heading_color = text if dark_bg else "#1e3a5f"
    body_color = text if dark_bg else "#2c3e50"
    muted_color = "#cbd5e0" if dark_bg else "#4a5568"
    card_bg = "#1a1a2e" if dark_bg else "#ffffff"
    card_border = "#2d3748" if dark_bg else "#e2e8f0"
    banner_bg = "#16213e" if dark_bg else "#f7fafc"
    surface_bg = "#16213e" if dark_bg else "#ffffff"
    link_color = "#90cdf4" if dark_bg else "#2b6cb0"
    status_bad = "#feb2b2" if dark_bg else "#c53030"
    status_warn = "#f6e05e" if dark_bg else "#975a16"
    status_good = "#9ae6b4" if dark_bg else "#276749"

    css = f"""
:root {{
  --gih-primary: {branding.get('primary_color')};
  --gih-secondary: {branding.get('secondary_color')};
  --gih-accent: {branding.get('accent_color')};
  --gih-text: {text};
  --gih-bg: {bg};
  --gih-font: {branding.get('font_family')};
  --gih-heading: {heading_color};
  --gih-muted: {muted_color};
}}
body {{
  font-family: var(--gih-font);
  background: var(--gih-bg);
  color: {body_color};
}}
.header {{
  background: linear-gradient(135deg, var(--gih-primary) 0%, var(--gih-secondary) 100%) !important;
  color: var(--gih-text) !important;
  border-bottom-color: var(--gih-accent) !important;
}}
.header h1, .header .meta {{ color: var(--gih-text) !important; }}
.classification {{ background: var(--gih-accent) !important; color: #ffffff !important; }}
h1, h2, h3, h4, h5, h6 {{ color: var(--gih-heading) !important; }}
h2 {{ border-bottom-color: var(--gih-accent) !important; }}
.section-blurb, .subsection-blurb, .meta, .summary-meta, .empty-note, .silent-tools,
.tool-off, tr.tool-row-off td:not([class^="status-"]) {{
  color: var(--gih-muted) !important;
}}
.card, .stat-card, .report-banner, .filter-bar, .graph-container, details.drilldown {{
  background: {card_bg} !important;
  border-color: {card_border} !important;
  color: {body_color};
}}
.report-banner {{ background: {banner_bg} !important; }}
.stat-value, .summary-value {{ color: var(--gih-heading) !important; }}
.stat-label {{ color: var(--gih-muted) !important; }}
th {{
  background: {banner_bg} !important;
  color: var(--gih-heading) !important;
  border-bottom-color: {card_border} !important;
}}
td {{ color: {body_color}; border-bottom-color: {card_border} !important; }}
tr:hover {{ background: {banner_bg} !important; }}
a {{ color: {link_color} !important; }}
table, .collapsible, .collapsible-content, .drilldown-body, details.drilldown > summary,
.section-blurb, .evidence-chain, .avatar-frame {{
  background: {surface_bg} !important;
  color: {body_color};
}}
.collapsible-header, .collapsible-header h4, .drilldown-body h5, .tool-chart-name,
.tool-chart-count, .kv-table td, .kv-table td:first-child, .report-banner strong,
.filter-bar label, .avatar-caption, .summary-value, .leak-field, .leak-field-key, .leak-info {{
  color: {body_color} !important;
}}
.collapsible-header, .collapsible-header:hover, details.drilldown > summary:hover,
.tool-chart-track {{
  background: {banner_bg} !important;
}}
.filter-bar input, .filter-bar select {{
  background: {surface_bg} !important;
  color: {body_color} !important;
  border-color: {card_border} !important;
}}
.chain-step {{ background: {banner_bg} !important; color: {body_color} !important; }}
.timeline-when, .timeline-kind, .timeline-controls label {{ color: {body_color} !important; }}
details.provenance, .provenance-body {{ color: {body_color} !important; }}
code.citation-command {{ background: {banner_bg} !important; color: {body_color} !important; }}
.citation-version {{ color: {body_color} !important; }}
.citation-meta {{ color: var(--gih-muted) !important; }}
details.provenance > summary {{ color: {link_color} !important; }}
table.provenance-table td:last-child {{ color: var(--gih-muted) !important; }}
.timeline-detail {{ color: var(--gih-muted) !important; }}
.timeline-controls select {{
  background: {surface_bg} !important;
  color: {body_color} !important;
  border-color: {card_border} !important;
}}
ol.timeline {{ border-left-color: {card_border} !important; }}
.status-not_installed {{ color: {status_bad} !important; }}
.status-silent_or_not_dispatched {{ color: {status_warn} !important; }}
.status-produced_output {{ color: {status_good} !important; }}
.status-verified {{ color: {status_good} !important; }}
.status-modified {{ color: {status_bad} !important; }}
.status-missing {{ color: {status_warn} !important; }}
.leak-db {{ color: {status_bad} !important; }}
"""
    if watermark.get("enabled"):
        opacity = watermark.get("opacity", 0.1)
        wm_text = (watermark.get("text") or "CONFIDENTIAL").replace("\\", "\\\\").replace('"', '\\"')
        wm_color = f"rgba(255,255,255,{opacity})" if dark_bg else f"rgba(0,0,0,{opacity})"
        css += f"""
body::before {{
  content: "{wm_text}";
  position: fixed;
  top: 40%;
  left: 50%;
  transform: translate(-50%, -50%) rotate(-30deg);
  font-size: 5rem;
  font-weight: 800;
  color: {wm_color};
  pointer-events: none;
  z-index: 9999;
  white-space: nowrap;
}}
"""
    return css


def default_output_path(investigation_id: str, suffix: str, output_dir: Optional[str] = None) -> str:
    from pathlib import Path
    base = Path(output_dir or load_reporting_config()["output_dir"])
    base.mkdir(parents=True, exist_ok=True)
    return str(base / f"{investigation_id}_report{suffix}")

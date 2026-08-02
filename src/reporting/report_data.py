"""Extra report data builders used by the standard HTML report."""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from copy import deepcopy
from typing import Any, Optional

from src.correlation.linker import IDENTITY_ARTIFACT_TYPES
from src.modules.external_tools import TOOL_ARTIFACT_TYPES
from src.storage import database as db

logger = logging.getLogger(__name__)

DEFAULT_SECTIONS = (
    "identities",
    "summary",
    "tools",
    "platforms",
    "graph",
    "artifacts",
    "evidence",
    "recommendations",
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


def build_delta_report(conn, investigation_id: str, compare_id: Optional[str]) -> dict:
    """Compare two investigations: added / removed / shared artifacts."""
    empty = {"compare_id": compare_id, "added": [], "removed": [], "shared": [], "enabled": False}
    if not compare_id:
        return empty
    other = db.get_investigation(conn, compare_id)
    if not other:
        return {**empty, "error": f"Investigation {compare_id} not found"}

    def _keyset(inv_id: str) -> dict[tuple, dict]:
        arts = db.get_artifacts(conn, inv_id)
        return {(a.get("artifact_type"), a.get("value")): a for a in arts}

    current = _keyset(investigation_id)
    baseline = _keyset(compare_id)
    added_keys = set(current) - set(baseline)
    removed_keys = set(baseline) - set(current)
    shared_keys = set(current) & set(baseline)
    return {
        "enabled": True,
        "compare_id": compare_id,
        "added": [_delta_item(current[k]) for k in sorted(added_keys)[:50]],
        "removed": [_delta_item(baseline[k]) for k in sorted(removed_keys)[:50]],
        "shared_count": len(shared_keys),
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
    }


def _delta_item(art: dict) -> dict:
    return {
        "type": art.get("artifact_type"),
        "value": art.get("value"),
        "source": art.get("source"),
        "confidence": art.get("confidence") or 0,
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

    def _mask(value: str, atype: str) -> str:
        if not value:
            return value
        if atype in REDACT_TYPES or _EMAIL_RE.fullmatch(value) or _PHONE_RE.fullmatch(value.strip()):
            if "@" in value:
                local, _, domain = value.partition("@")
                return f"{local[:1]}***@{domain}"
            if len(value) <= 4:
                return "****"
            return value[:2] + "***" + value[-2:]
        return _EMAIL_RE.sub(lambda m: m.group(0)[:1] + "***@redacted",
                             _PHONE_RE.sub("***-****", value))

    arts = deepcopy(artifacts)
    for a in arts:
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


def branding_css(branding: dict, watermark: dict) -> str:
    """Inline CSS variables + optional watermark overlay."""
    css = f"""
:root {{
  --gih-primary: {branding.get('primary_color')};
  --gih-secondary: {branding.get('secondary_color')};
  --gih-accent: {branding.get('accent_color')};
  --gih-text: {branding.get('text_color')};
  --gih-bg: {branding.get('background_color')};
  --gih-font: {branding.get('font_family')};
}}
body {{ font-family: var(--gih-font); background: var(--gih-bg); }}
.header {{ background: linear-gradient(135deg, var(--gih-primary) 0%, var(--gih-secondary) 100%) !important; color: var(--gih-text) !important; border-bottom-color: var(--gih-accent) !important; }}
.classification {{ background: var(--gih-accent) !important; }}
"""
    if watermark.get("enabled"):
        opacity = watermark.get("opacity", 0.1)
        text = (watermark.get("text") or "CONFIDENTIAL").replace("\\", "\\\\").replace('"', '\\"')
        css += f"""
body::before {{
  content: "{text}";
  position: fixed;
  top: 40%;
  left: 50%;
  transform: translate(-50%, -50%) rotate(-30deg);
  font-size: 5rem;
  font-weight: 800;
  color: rgba(0,0,0,{opacity});
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

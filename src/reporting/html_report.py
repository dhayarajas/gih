"""
Ghost Identity Hunter - HTML Report Generation Module

PURPOSE:
--------
This module provides comprehensive report generation capabilities for Ghost Identity Hunter
investigations, creating professional HTML reports and structured JSON exports that
document findings, evidence chains, risk assessments, and identity correlation results.

FUNCTIONALITY:
--------------
- Professional HTML report generation with a light, print-friendly theme
- Structured JSON export for integration with SIEM/CTI systems
- Investigation summary with key metrics and statistics
- Identity profile documentation with confidence scores
- Platform presence matrix across discovered services
- Breach exposure analysis and risk assessment
- Evidence chain documentation with source attribution
- Interactive elements and responsive design

REPORT SECTIONS:
---------------
1. Summary: Investigation overview and key findings
2. Identity Profiles: Correlated personas with confidence scores
3. Platform Presence Matrix: Cross-platform account discovery
4. Relationship Graph: Visual identity network representation
5. Breach Exposure: Credential compromise analysis
6. Risk Assessment: Threat level classification and indicators
7. Evidence Chain: Source attribution and verification trail
8. Raw Data Appendix: Complete artifact and link database

HTML FEATURES:
--------------
- Light professional theme optimized for analyst review and printing
- Responsive design for desktop and mobile devices
- Color-coded risk indicators and confidence scores
- Native details/summary drill-downs on artifacts, platforms and identities
- Print-optimized CSS for physical report generation
- Accessibility compliance with semantic HTML structure

USAGE EXAMPLES:
--------------
# Generate HTML report
html_report = generate_html_report(conn, investigation_id)

# Generate JSON export
json_report = generate_json_report(conn, investigation_id)

# Save reports to files
Path("report.html").write_text(html_report)
Path("report.json").write_text(json_report)

DEPENDENCIES:
-------------
- jinja2: HTML template rendering engine
- sqlite3: Database connection for investigation data
- src.correlation: Identity analysis and risk scoring
- src.storage: Database operations and artifact retrieval
- datetime: Timestamp formatting for reports
- json: Structured data export serialization

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import base64
import json
import logging
import re
import sqlite3
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader

from src.correlation.linker import correlate_identities
from src.correlation.scorer import compute_identity_risk_score, classify_risk_level
from src.modules.external_tools import TOOL_ARTIFACT_TYPES
from src.storage import database as db

logger = logging.getLogger(__name__)

def _templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"

def _load_standard_template() -> str:
    """Load the standard report template from disk (editable without code changes)."""
    path = _templates_dir() / "standard.html"
    return path.read_text(encoding="utf-8")


HTML_TEMPLATE = _load_standard_template()


# Summary Template - High-level overview for management
EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Summary - {{ investigation.investigation_id }}</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; color: #333; margin: 0; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 0.5rem; }
        h2 { color: #34495e; margin-top: 2rem; }
        .summary-box { background: #ecf0f1; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 5px solid #3498db; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }
        .stat-card { background: #3498db; color: white; padding: 1rem; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { font-size: 0.9rem; opacity: 0.9; }
        .risk-critical { background: #e74c3c; }
        .risk-high { background: #e67e22; }
        .risk-medium { background: #f39c12; }
        .risk-low { background: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; overflow-wrap: anywhere; }
        th { background: #34495e; color: white; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .badge-risk { background: #e74c3c; color: white; }
        .tool-off { color: #9aa0a6; text-decoration: line-through; }
        .leak-box { background: #fdecea; color: #6b1d16; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 5px solid #c0392b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Summary</h1>
        <p><strong>Investigation ID:</strong> {{ investigation.investigation_id }}</p>
        <p><strong>Title:</strong> {{ investigation.title or 'Untitled Investigation' }}</p>
        <p><strong>Status:</strong> {{ (investigation.status or 'Unknown') | title }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>

        {% if leak_findings.record_count %}
        <div class="leak-box">
            <h2>Breach Records</h2>
            <p>{{ leak_findings.record_count }} leaked record{{ '' if leak_findings.record_count == 1 else 's' }}
               across {{ leak_findings.database_count }} database{{ '' if leak_findings.database_count == 1 else 's' }}
               matched this investigation's selectors. Per-record detail is in the standard and technical reports.</p>
            <ul>
                {% for database in leak_findings.databases %}
                <li>{{ database.database }}: {{ database.records | length }} record{{ '' if database.records | length == 1 else 's' }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <div class="summary-box">
            <h2>Key Findings</h2>
            <ul>
                {% for finding in key_findings %}
                <li>{{ finding }}</li>
                {% endfor %}
            </ul>
        </div>

        <h2>Summary Statistics</h2>
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-value">{{ artifacts | length }}</div>
                <div class="stat-label">Artifacts Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ links | length }}</div>
                <div class="stat-label">Connections</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ correlation.identities | length }}</div>
                <div class="stat-label">Identities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ presences | length }}</div>
                <div class="stat-label">Platforms</div>
            </div>
        </div>

        <h2>Risk Assessment</h2>
        <table>
            <thead>
                <tr><th>Identity</th><th>Risk Level</th><th>Confidence</th></tr>
            </thead>
            <tbody>
                {% for identity in correlation.identities %}
                <tr>
                    <td>{{ identity.name or 'Unknown Identity' }}</td>
                    <td><span class="badge badge-risk">{{ risk_levels[loop.index0] | upper }}</span></td>
                    <td>{{ "%.1f%%" | format(identity.confidence * 100) }}</td>
                </tr>
                {% else %}
                <tr><td colspan="3">No identity profiles were correlated for this investigation.</td></tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Infrastructure Attributed to Each Identity</h2>
        <table>
            <thead>
                <tr><th>Identity</th><th>Accounts</th><th>Domains</th><th>IPs</th><th>Open Ports</th><th>Tools</th></tr>
            </thead>
            <tbody>
                {% for identity in correlation.identities %}
                <tr>
                    <td>{{ identity.name or 'Unknown Identity' }}</td>
                    <td>{{ identity.platforms | length }}</td>
                    <td>{{ (identity.domains | length) + (identity.subdomains | length) }}</td>
                    <td>{{ identity.ip_addresses | length }}</td>
                    <td>{{ identity.open_ports | length }}</td>
                    <td>{{ identity.tools_used | join(', ') or '-' }}</td>
                </tr>
                {% else %}
                <tr><td colspan="6">No identity profiles were correlated for this investigation.</td></tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Platform Presence</h2>
        <table>
            <thead>
                <tr><th>Platform</th><th>Username</th><th>Profile URL</th><th>Validation</th></tr>
            </thead>
            <tbody>
                {% for p in presences[:10] %}
                <tr>
                    <td>{{ p.platform_name }}</td>
                    <td>{{ p.username or '-' }}</td>
                    <td>{% if p.profile_url %}<a href="{{ p.profile_url }}">Link</a>{% else %}-{% endif %}</td>
                    <td>{{ 'Content-validated' if p.is_verified else 'Unvalidated (status only)' }}</td>
                </tr>
                {% else %}
                <tr><td colspan="4">No platform presences were found.</td></tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Recommendations</h2>
        {% for rec in recommendations %}
        <div class="summary-box" style="border-left-color: #e74c3c;">
            <p><strong>{{ rec.priority | upper }}:</strong> {{ rec.action }}</p>
            <p style="font-size: 0.9rem;">{{ rec.details }}</p>
        </div>
        {% else %}
        <p>No recommendations were generated for this investigation.</p>
        {% endfor %}

        <p class="meta" style="margin-top: 3rem; text-align: center; color: #7f8c8d;">
            Confidential Summary | Generated by Ghost Identity Hunter
        </p>
    </div>
</body>
</html>
"""


# Technical Report Template - Detailed technical information
TECHNICAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Technical Report - {{ investigation.investigation_id }}</title>
    <style>
        body { font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e; color: #d4d4d4; margin: 0; padding: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; background: #252526; padding: 2rem; border-radius: 4px; }
        h1 { color: #569cd6; border-bottom: 2px solid #569cd6; padding-bottom: 0.5rem; }
        h2 { color: #4ec9b0; margin-top: 2rem; }
        .card { background: #2d2d30; padding: 1rem; border-radius: 4px; margin: 1rem 0; border: 1px solid #3e3e42; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { overflow-wrap: anywhere; }
        th { background: #3e3e42; color: #d4d4d4; }
        .tool-off { color: #808080; text-decoration: line-through; }
        .code { background: #1e1e1e; padding: 1rem; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Technical Report</h1>
        <p><strong>Investigation ID:</strong> {{ investigation.investigation_id }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>
        
        {% if leak_findings.record_count %}
        <h2>Breach Records</h2>
        {% for database in leak_findings.databases %}
        <div class="card">
            <h3>{{ database.database }} &mdash; {{ database.records | length }} record{{ '' if database.records | length == 1 else 's' }}</h3>
            {% if database.info %}<p>{{ database.info }}</p>{% endif %}
            <table>
                <thead>
                    <tr><th>Field</th><th>Value</th></tr>
                </thead>
                <tbody>
                    {% for record in database.records %}
                    {% for field in record.fields %}
                    <tr><td>{{ field.key }}</td><td>{{ field.value }}</td></tr>
                    {% endfor %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endfor %}
        {% endif %}

        <h2>Artifacts</h2>
        <div class="card">
            <table>
                <thead>
                    <tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th></tr>
                </thead>
                <tbody>
                    {% for a in artifacts %}
                    <tr>
                        <td>{{ a.artifact_type }}</td>
                        <td>{{ a.value }}</td>
                        <td>{{ a.source or '-' }}</td>
                        <td>{{ "%.2f" | format(a.confidence or 0) }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4">No artifacts were recorded for this investigation.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <h2>Tool Metrics</h2>
        <div class="card">
            {% if tool_metrics.tools %}
            <p>{{ tool_metrics.tool_count }} tools produced {{ tool_metrics.attributed }} artifacts
               across {{ tool_metrics.types | length }} artifact types.</p>
            <table>
                <thead>
                    <tr><th>Tool</th><th>Artifacts</th><th>Share</th><th>Avg. confidence</th><th>Identities reached</th><th>Artifact types</th></tr>
                </thead>
                <tbody>
                    {% for tool in tool_metrics.tools %}
                    <tr>
                        <td>{{ tool.tool }}</td>
                        <td>{{ tool.count }}</td>
                        <td>{{ tool.share }}%</td>
                        <td>{{ "%.2f" | format(tool.avg_confidence) }}</td>
                        <td>{{ tool.identities }}</td>
                        <td>{% if tool.kind == 'derivation' %}derived: {% endif %}{% for type in tool.types %}{{ type.type }} ({{ type.count }}){% if not loop.last %}, {% endif %}{% endfor %}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% if tool_metrics.silent_tools %}
            <p>Integrated but silent in this run: {% for tool in tool_metrics.silent_tools %}<span class="tool-off">{{ tool }}</span>{% if not loop.last %}, {% endif %}{% endfor %}.</p>
            {% endif %}
            {% else %}
            <p>No tool-derived artifacts in this investigation.</p>
            {% endif %}
        </div>

        <h2>External Tool Findings by Identity</h2>
        {% for identity in correlation.identities %}
        <div class="card">
            <p><strong>{{ identity.profile_id }}</strong> ({{ identity.name }}) &mdash;
               tools: {{ identity.tools_used | join(', ') or 'none' }}</p>
            {% if identity.tool_findings %}
            <table>
                <thead>
                    <tr><th>Tool</th><th>Artifact Type</th><th>Value</th><th>Confidence</th></tr>
                </thead>
                <tbody>
                    {% for finding in identity.tool_findings %}
                    <tr>
                        <td>{{ finding.source }}</td>
                        <td>{{ finding.type }}</td>
                        <td>{{ finding.value }}</td>
                        <td>{{ "%.2f" | format(finding.confidence or 0) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No external tool output correlated to this identity.</p>
            {% endif %}
        </div>
        {% else %}
        <div class="card"><p>No identity profiles were correlated for this investigation.</p></div>
        {% endfor %}

        <h2>Links</h2>
        <div class="card">
            <table>
                <thead>
                    <tr><th>Source</th><th>Target</th><th>Type</th><th>Confidence</th></tr>
                </thead>
                <tbody>
                    {% for l in links %}
                    <tr>
                        <td>{{ l.source_artifact }}</td>
                        <td>{{ l.target_artifact }}</td>
                        <td>{{ l.link_type }}</td>
                        <td>{{ "%.2f" | format(l.confidence or 0) }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4">No links were recorded for this investigation.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""


# Legal Report Template - For legal proceedings and documentation
LEGAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Legal Investigation Report - {{ investigation.investigation_id }}</title>
    <style>
        body { font-family: 'Times New Roman', Times, serif; background: #ffffff; color: #000000; margin: 0; padding: 2rem; line-height: 1.6; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 2rem; border: 1px solid #000; }
        h1 { color: #000; border-bottom: 2px solid #000; padding-bottom: 0.5rem; text-align: center; }
        h2 { color: #000; margin-top: 2rem; border-bottom: 1px solid #ccc; }
        .header-section { text-align: center; margin-bottom: 2rem; }
        .disclaimer { background: #f0f0f0; padding: 1rem; margin: 1rem 0; border-left: 4px solid #000; font-size: 0.9rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem; text-align: left; border: 1px solid #000; overflow-wrap: anywhere; }
        th { background: #f0f0f0; font-weight: bold; }
        .signature-block { margin-top: 3rem; border-top: 1px solid #000; padding-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-section">
            <h1>Legal Investigation Report</h1>
            <p><strong>Case Reference:</strong> {{ investigation.investigation_id }}</p>
            <p><strong>Date of Report:</strong> {{ generated_at }}</p>
            <p><strong>Investigation Status:</strong> {{ (investigation.status or 'Unknown') | upper }}</p>
        </div>

        <div class="disclaimer">
            <strong>CONFIDENTIAL - LEGAL PRIVILEGED DOCUMENT</strong><br>
            This report contains sensitive information and is intended solely for authorized legal personnel. 
            Unauthorized distribution is prohibited.
        </div>

        <h2>Summary</h2>
        <p>This report documents the findings of OSINT investigation {{ investigation.investigation_id }} 
        conducted on {{ investigation.created_at }}. The investigation focused on digital identity correlation 
        and evidence gathering in accordance with applicable laws and regulations.</p>

        <h2>Evidence Summary</h2>
        <table>
            <thead>
                <tr><th>Evidence Type</th><th>Count</th><th>Source</th></tr>
            </thead>
            <tbody>
                <tr><td>Digital Artifacts</td><td>{{ artifacts | length }}</td><td>OSINT Collection</td></tr>
                <tr><td>Identity Links</td><td>{{ links | length }}</td><td>Correlation Analysis</td></tr>
                <tr><td>Platform Presences</td><td>{{ presences | length }}</td><td>Social Media Analysis</td></tr>
                {% if leak_findings.record_count %}
                <tr><td>Breach Records</td><td>{{ leak_findings.record_count }}</td><td>Leaked Database Search ({{ leak_findings.database_count }} database{{ '' if leak_findings.database_count == 1 else 's' }})</td></tr>
                {% endif %}
            </tbody>
        </table>

        <h2>Key Findings</h2>
        {% for finding in key_findings %}
        <div style="margin-bottom: 1rem;">
            <p><strong>Finding {{ loop.index }}:</strong> {{ finding }}</p>
        </div>
        {% else %}
        <p>No findings were recorded for this investigation.</p>
        {% endfor %}

        <h2>Risk Assessment</h2>
        <p>Based on the collected evidence, the following risk levels have been assigned:</p>
        <table>
            <thead>
                <tr><th>Identity</th><th>Risk Level</th><th>Evidence Basis</th></tr>
            </thead>
            <tbody>
                {% for identity in correlation.identities %}
                <tr>
                    <td>{{ identity.name or 'Unknown Identity' }}</td>
                    <td>{{ risk_levels[loop.index0] | upper }}</td>
                    <td>{{ identity.artifacts | length }} correlated artifacts</td>
                </tr>
                {% else %}
                <tr><td colspan="3">No identity profiles were correlated for this investigation.</td></tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Evidence Attributed to Each Identity</h2>
        <table>
            <thead>
                <tr><th>Identity</th><th>Evidence Item</th><th>Type</th><th>Collection Tool</th></tr>
            </thead>
            <tbody>
                {% for identity in correlation.identities %}
                {% for finding in identity.tool_findings %}
                <tr>
                    <td>{{ identity.name or 'Unknown Identity' }}</td>
                    <td>{{ finding.value }}</td>
                    <td>{{ finding.type }}</td>
                    <td>{{ finding.source }}</td>
                </tr>
                {% endfor %}
                {% else %}
                <tr><td colspan="4">No identity profiles were correlated for this investigation.</td></tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Chain of Custody</h2>
        {% if preserved_evidence.enabled %}
        <p>The verbatim output of each collection step was written to disk at collection time and
        named after the SHA-256 digest of its bytes. Every digest below was recomputed when this
        report was produced: {{ preserved_evidence.verified }} of {{ preserved_evidence.total }}
        capture(s) still match their recorded digest{% if not preserved_evidence.intact %},
        {{ preserved_evidence.modified }} no longer match and {{ preserved_evidence.missing }}
        could not be located{% endif %}.</p>
        <table>
            <thead>
                <tr><th>Collected (UTC)</th><th>Tool</th><th>Collection Command</th><th>Result</th><th>Bytes</th><th>SHA-256</th><th>Integrity</th></tr>
            </thead>
            <tbody>
                {% for item in preserved_evidence['items'] %}
                <tr>
                    <td>{{ item.captured_at[:19] }}</td>
                    <td>{{ item.tool }}</td>
                    <td style="font-family: monospace; font-size: 0.8rem;">{{ item.command or 'withheld' }}</td>
                    <td>{{ item.exit_status or '-' }}</td>
                    <td>{{ item.byte_size }}</td>
                    <td style="font-family: monospace; font-size: 0.75rem;">{{ item.sha256 }}</td>
                    <td>{{ item.status | upper }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No raw collection output was preserved for this investigation, so the findings below
        cannot be re-verified against the material they were derived from.</p>
        {% endif %}

        <h2>Data Sources</h2>
        <p>The following data sources were utilized in this investigation:</p>
        <ul>
            <li>Publicly available social media platforms</li>
            <li>Public domain registration records</li>
            <li>Breach data repositories (where legally permissible)</li>
            <li>Open source intelligence gathering</li>
        </ul>

        <h2>Legal Compliance</h2>
        <p>This investigation was conducted in compliance with applicable laws including but not limited to:</p>
        <ul>
            <li>Computer Fraud and Abuse Act (CFAA)</li>
            <li>Stored Communications Act (SCA)</li>
            <li>General Data Protection Regulation (GDPR) - where applicable</li>
            <li>California Consumer Privacy Act (CCPA) - where applicable</li>
        </ul>
        <p>All data collection was limited to publicly available information. No unauthorized access to private systems was attempted.</p>

        <div class="signature-block">
            <p><strong>Report Prepared By:</strong> Ghost Identity Hunter Automated System</p>
            <p><strong>Verification Status:</strong> Automated Analysis - Requires Human Review</p>
            <p><strong>Classification:</strong> CONFIDENTIAL - LEGAL PRIVILEGED</p>
        </div>
    </div>
</body>
</html>
"""


def _select_template(template_type: str) -> str:
    """Select the appropriate HTML template based on report type.

    The standard template is always reloaded from disk so edits to
    ``templates/standard.html`` take effect without restarting the process.
    """
    normalized = (template_type or "standard").strip().lower()
    if normalized in ("default", "html", ""):
        normalized = "standard"
    if normalized == "standard":
        try:
            return _load_standard_template()
        except OSError:
            return HTML_TEMPLATE
    templates = {
        "executive": EXECUTIVE_TEMPLATE,
        "technical": TECHNICAL_TEMPLATE,
        "legal": LEGAL_TEMPLATE,
    }
    return templates.get(normalized, HTML_TEMPLATE)


def _parse_metadata(raw) -> dict:
    """Parse an artifact metadata field into a dict, tolerating null/invalid JSON."""
    if isinstance(raw, dict):
        return raw
    if not raw or not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {'raw': raw}
    if isinstance(parsed, dict):
        return parsed
    return {'value': parsed}


def _format_metadata_value(value) -> str:
    """Render a metadata value as a compact, human-readable string.

    Tool metadata is arbitrary JSON, so containers are unwrapped rather than
    dumped verbatim: an empty one carries no information and a flat list reads
    better as a comma-separated line than as a JSON array.
    """
    if value is None or value == '' or value == [] or value == {}:
        return '-'
    if isinstance(value, float):
        return f'{value:.4f}'.rstrip('0').rstrip('.')
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            return ', '.join('-' if item is None else str(item) for item in value)
        return json.dumps(value, default=str)
    if isinstance(value, dict):
        if all(not isinstance(item, (dict, list)) for item in value.values()):
            return '; '.join(f'{key}: {item}' for key, item in value.items())
        return json.dumps(value, default=str)
    return str(value)


def _metadata_table(value) -> Optional[dict]:
    """Turn a list of record dicts into columns/rows for a nested table.

    Several tools (sherlock, maigret, holehe, image search) store their per-
    platform results as a list of records; rendering that as one JSON blob is
    unreadable. Records nested more than one level deep keep the JSON fallback.
    Columns that are empty for every record are dropped.
    """
    if not isinstance(value, list) or not value:
        return None
    if not all(isinstance(item, dict) for item in value):
        return None
    for item in value:
        for cell in item.values():
            nested = cell.values() if isinstance(cell, dict) else cell if isinstance(cell, list) else ()
            if any(isinstance(inner, (dict, list)) for inner in nested):
                return None

    columns = []
    for item in value:
        for key in item:
            if key not in columns:
                columns.append(str(key))
    columns = [
        column for column in columns
        if any(item.get(column) not in (None, '', [], {}) for item in value)
    ]
    if not columns:
        return None
    rows = [
        [_format_metadata_value(item.get(column)) for column in columns]
        for item in value
    ]
    return {'columns': columns, 'rows': rows}


def _build_artifact_views(artifacts: list, links: list, correlation) -> list:
    """
    Build per-artifact drill-down views for the HTML template.

    Each view carries the original artifact fields plus parsed metadata, the
    identity it was attributed to, and its incoming/outgoing links resolved to
    the artifact on the other end.
    """
    by_id = {a.get('artifact_id'): a for a in artifacts}

    identity_by_value = {}
    for index, identity in enumerate(getattr(correlation, 'identities', None) or [], start=1):
        label = f"Identity Profile #{index} ({identity.name})"
        for value in identity.artifacts:
            identity_by_value.setdefault(
                value, {'profile_id': identity.profile_id, 'label': label}
            )

    views = []
    for artifact in artifacts:
        artifact_id = artifact.get('artifact_id')
        metadata = _parse_metadata(artifact.get('metadata'))

        connections = []
        for link in links:
            source_id = link.get('source_artifact')
            target_id = link.get('target_artifact')
            if artifact_id not in (source_id, target_id):
                continue
            outgoing = source_id == artifact_id
            other_id = target_id if outgoing else source_id
            other = by_id.get(other_id) or {}
            connections.append({
                'direction': 'outgoing' if outgoing else 'incoming',
                'link_type': link.get('link_type') or '-',
                'confidence': link.get('confidence') or 0,
                'evidence': link.get('evidence') or '',
                'other_id': other_id or '-',
                'other_value': other.get('value') or other_id or '-',
                'other_type': other.get('artifact_type') or 'unknown',
            })

        identity = identity_by_value.get(artifact.get('value')) or {}
        views.append({
            **artifact,
            'metadata_parsed': metadata,
            'metadata_items': [
                {
                    'key': str(key),
                    'value': _format_metadata_value(value),
                    'table': _metadata_table(value),
                }
                for key, value in sorted(metadata.items(), key=lambda item: str(item[0]))
            ],
            'connections': connections,
            'identity_profile_id': identity.get('profile_id'),
            'identity_label': identity.get('label'),
        })

    return views


def _build_identity_artifacts(artifact_views: list, correlation) -> dict:
    """Map each identity profile_id to the full artifact views attributed to it."""
    identity_artifacts = {}
    for identity in getattr(correlation, 'identities', None) or []:
        values = set(identity.artifacts)
        identity_artifacts[identity.profile_id] = [
            view for view in artifact_views if view.get('value') in values
        ]
    return identity_artifacts


def generate_html_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
    template_type: str = "standard",
    *,
    sections: Optional[str] = None,
    redact: bool = False,
    compare_id: Optional[str] = None,
) -> str:
    """
    Generate a comprehensive HTML report.

    Args:
        conn: Database connection
        investigation_id: Investigation ID
        output_path: Optional output file path
        template_type: standard | executive | technical | legal
        sections: Optional comma-separated section filter (standard template)
        redact: Mask phones/emails/images for shareable exports
        compare_id: Optional prior investigation ID for a delta section
    """
    from src.reporting.report_data import (
        branding_css,
        build_cross_investigation,
        build_delta_report,
        build_evidence_chains,
        build_leak_findings,
        build_orphan_findings,
        build_preserved_evidence,
        default_output_path,
        enrich_tool_status,
        load_comments,
        load_custom_css,
        load_reporting_config,
        parse_sections,
        redact_payload,
    )

    reporting_cfg = load_reporting_config()
    if not template_type or template_type in ("default", "html"):
        template_type = reporting_cfg.get("template") or "standard"

    investigation = db.get_investigation(conn, investigation_id)
    if not investigation:
        raise ValueError(f"Investigation {investigation_id} not found")

    artifacts = db.get_artifacts(conn, investigation_id)
    links = db.get_links(conn, investigation_id)
    presences = db.get_platform_presences(conn, investigation_id)
    correlation = correlate_identities(conn, investigation_id)

    artifacts, links, presences, correlation = redact_payload(
        artifacts, links, presences, correlation, redact
    )

    risk_levels = []
    for identity in correlation.identities:
        risk_score = compute_identity_risk_score(identity.risk_indicators)
        risk_levels.append(classify_risk_level(risk_score))

    timeline = _generate_timeline(artifacts)
    key_findings = _generate_key_findings(artifacts, links, presences, correlation)
    confidence_metrics = _generate_confidence_metrics(artifacts, links)
    risk_matrix = _generate_risk_matrix(correlation, risk_levels)
    graph_html = ""
    graph_iframe_src = ""
    if not redact:
        graph_html = _generate_embedded_graph(conn, investigation_id)

    tool_metrics = enrich_tool_status(_generate_tool_metrics(artifacts, correlation))
    leak_findings = build_leak_findings(artifacts, redact=redact)
    orphan_findings = build_orphan_findings(artifacts, correlation)
    recommendations: list = []

    priority_queue = _generate_priority_queue(artifacts, links, correlation)
    geographic_data = _generate_geographic_data(artifacts, presences)
    platform_heatmap = _generate_platform_heatmap(presences)
    correlation_strength = _generate_correlation_strength(links)
    verification_status = _generate_verification_status(artifacts)
    anomaly_detection = _generate_anomaly_detection(artifacts, links)
    auto_escalation = _generate_auto_escalation(artifacts, links, risk_levels, correlation)
    audit_trail = db.get_audit_trail(conn, investigation_id)
    comments = load_comments(conn, investigation_id)
    evidence_chains = build_evidence_chains(artifacts, links)
    preserved_evidence = build_preserved_evidence(conn, investigation_id, redact)
    cross_hits = build_cross_investigation(conn, investigation_id, artifacts)
    delta = build_delta_report(conn, investigation_id, compare_id)


    # Ranked, renderable profile pictures per identity
    identity_images = _generate_identity_images(correlation, presences, artifacts)

    # Build drill-down views (parsed metadata, connected links, identity attribution)
    artifact_views = _build_artifact_views(artifacts, links, correlation)
    identity_artifacts = _build_identity_artifacts(artifact_views, correlation)

    branding = dict(reporting_cfg["branding"])
    branding["custom_css_content"] = load_custom_css(branding.get("custom_css"))
    watermark = reporting_cfg["watermark"]
    section_set = parse_sections(sections)

    template_content = _select_template(template_type)
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(template_content)

    if output_path is None:
        output_path = default_output_path(
            investigation_id, ".html", reporting_cfg.get("output_dir")
        )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write the pyvis graph as a sibling HTML file and iframe it. Using src=
    # (not srcdoc) avoids double-escaping and lets CDN scripts resolve under
    # file://; the iframe still isolates Bootstrap CSS from the parent report.
    if graph_html and not redact:
        embed_name = f"{investigation_id}_graph_embed.html"
        embed_path = output_file.parent / embed_name
        embed_path.write_text(_prepare_graph_embed_html(graph_html), encoding="utf-8")
        graph_iframe_src = embed_name

    html = template.render(
        investigation=investigation,
        artifacts=artifacts,
        artifact_views=artifact_views,
        identity_artifacts=identity_artifacts,
        links=links,
        presences=presences,
        correlation=correlation,
        risk_levels=risk_levels,
        timeline=timeline,
        key_findings=key_findings,
        confidence_metrics=confidence_metrics,
        risk_matrix=risk_matrix,
        graph_html=graph_html,
        graph_iframe_src=graph_iframe_src,
        recommendations=recommendations,
        priority_queue=priority_queue,
        geographic_data=geographic_data,
        platform_heatmap=platform_heatmap,
        correlation_strength=correlation_strength,
        verification_status=verification_status,
        anomaly_detection=anomaly_detection,
        auto_escalation=auto_escalation,
        audit_trail=audit_trail,
        tool_metrics=tool_metrics,
        identity_images=identity_images,
        evidence_chains=evidence_chains,
        preserved_evidence=preserved_evidence,
        leak_findings=leak_findings,
        orphan_findings=orphan_findings,
        comments=comments,
        cross_hits=cross_hits,
        delta=delta,
        sections=section_set,
        branding=branding,
        branding_css=branding_css(branding, watermark) if branding.get("enabled") else "",
        watermark=watermark,
        redacted=redact,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )

    output_file.write_text(html, encoding="utf-8")

    try:
        db.add_audit_log(
            conn,
            investigation_id,
            action="report_generated",
            entity_type="report",
            entity_id=str(output_file),
            details=json.dumps({
                "template": template_type,
                "redacted": redact,
                "sections": sorted(section_set),
                "compare_id": compare_id,
            }),
        )
    except Exception as exc:
        logger.debug("Could not write report audit log: %s", exc)

    logger.info("HTML report saved to %s", output_file)
    return str(output_file)


def _generate_timeline(artifacts: list) -> list:
    """Generate investigation timeline from artifact discovery times."""
    timeline = []
    for artifact in artifacts:
        timeline.append({
            'time': artifact.get('discovered_at', ''),
            'type': artifact.get('artifact_type', 'unknown'),
            'value': artifact.get('value', ''),
            'source': artifact.get('source', 'unknown'),
            'depth': artifact.get('depth', 0)
        })
    
    # Sort by discovery time
    timeline.sort(key=lambda x: x['time'])
    return timeline


def _generate_key_findings(artifacts: list, links: list, presences: list, correlation) -> list:
    """Generate key findings summary for executive summary."""
    findings = []
    
    # Top artifacts by confidence
    high_confidence_artifacts = [a for a in artifacts if a.get('confidence', 0) >= 0.8]
    if high_confidence_artifacts:
        findings.append(f"Found {len(high_confidence_artifacts)} high-confidence artifacts")
    
    # Platform presence summary
    if presences:
        platforms = list(set(p.get('platform_name') for p in presences))
        findings.append(f"Detected presence on {len(platforms)} platforms: {', '.join(platforms[:5])}")
    
    # Identity profiles with high risk
    high_risk_identities = []
    for i, identity in enumerate(correlation.identities):
        risk_score = compute_identity_risk_score(identity.risk_indicators)
        risk_level = classify_risk_level(risk_score)
        if risk_level in ['critical', 'high']:
            high_risk_identities.append({
                'profile_id': identity.profile_id,
                'risk_level': risk_level,
                'artifact_count': identity.artifact_count
            })
    
    if high_risk_identities:
        findings.append(f"Identified {len(high_risk_identities)} high-risk identity profiles requiring attention")
    
    # Total artifacts and connections
    findings.append(f"Total of {len(artifacts)} artifacts discovered with {len(links)} connections")
    
    return findings


def _generate_confidence_metrics(artifacts: list, links: list) -> dict:
    """Generate confidence metrics breakdown."""
    if not artifacts:
        return {'overall': 0.0, 'by_type': {}, 'by_source': {}}
    
    # Overall confidence
    overall_confidence = sum(a.get('confidence', 0) for a in artifacts) / len(artifacts)
    
    # Confidence by artifact type
    by_type = {}
    for artifact in artifacts:
        artifact_type = artifact.get('artifact_type', 'unknown')
        if artifact_type not in by_type:
            by_type[artifact_type] = []
        by_type[artifact_type].append(artifact.get('confidence', 0))
    
    by_type_avg = {k: sum(v)/len(v) for k, v in by_type.items()}
    
    # Confidence by source
    by_source = {}
    for artifact in artifacts:
        source = artifact.get('source', 'unknown')
        if source not in by_source:
            by_source[source] = []
        by_source[source].append(artifact.get('confidence', 0))
    
    by_source_avg = {k: sum(v)/len(v) for k, v in by_source.items()}
    
    return {
        'overall': round(overall_confidence, 2),
        'by_type': {k: round(v, 2) for k, v in by_type_avg.items()},
        'by_source': {k: round(v, 2) for k, v in by_source_avg.items()}
    }


def _generate_risk_matrix(correlation, risk_levels: list) -> dict:
    """Generate risk assessment matrix."""
    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'minimal': 0}
    
    for level in risk_levels:
        risk_counts[level] = risk_counts.get(level, 0) + 1
    
    # Calculate risk distribution percentages
    total = sum(risk_counts.values()) or 1
    risk_distribution = {k: round(v/total * 100, 1) for k, v in risk_counts.items()}
    
    return {
        'counts': risk_counts,
        'distribution': risk_distribution,
        'total_identities': len(correlation.identities)
    }


def _prepare_graph_embed_html(graph_html: str) -> str:
    """Normalize pyvis HTML for reliable iframe embedding under file://."""
    import re

    # pyvis injects a local helper that does not ship with the report; CDN
    # vis-network is enough for the interactive canvas.
    cleaned = re.sub(
        r'<script[^>]+src=["\']lib/bindings/utils\.js["\'][^>]*>\s*</script>\s*',
        "",
        graph_html,
        flags=re.I,
    )
    # Give the network a usable viewport inside the iframe.
    if "<style>" in cleaned.lower():
        cleaned = re.sub(
            r"(</head>)",
            '<style>html,body{margin:0;height:100%;overflow:hidden;}'
            '#mynetwork,#mynetworkid{width:100%!important;height:100vh!important;}</style>\\1',
            cleaned,
            count=1,
            flags=re.I,
        )
    else:
        cleaned = cleaned.replace(
            "<head>",
            "<head><style>html,body{margin:0;height:100%;overflow:hidden;}"
            "#mynetwork,#mynetworkid{width:100%!important;height:100vh!important;}</style>",
            1,
        )
    return cleaned


def _generate_embedded_graph(conn: sqlite3.Connection, investigation_id: str) -> str:
    """Generate embedded interactive graph HTML."""
    try:
        from src.graph.visualizer import generate_interactive_graph
        import tempfile
        
        # Generate graph to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_path = f.name
        
        graph_path = generate_interactive_graph(conn, investigation_id, temp_path)
        
        if graph_path and Path(graph_path).exists():
            # Read the generated HTML and extract the body content
            with open(graph_path, 'r') as f:
                graph_content = f.read()
            
            # Clean up temp file
            Path(graph_path).unlink(missing_ok=True)
            
            return graph_content
        else:
            return ""
    except Exception as e:
        logger.warning("Failed to generate embedded graph: %s", e)
        return ""


def _generate_recommendations(artifacts: list, links: list, presences: list, correlation, risk_levels: list) -> list:
    """Generate investigative recommendations based on findings."""
    recommendations = []
    
    # High-risk identity follow-up
    high_risk_count = sum(1 for level in risk_levels if level in ['critical', 'high'])
    if high_risk_count > 0:
        recommendations.append({
            'priority': 'critical',
            'category': 'High-Risk Identities',
            'action': f'Immediate investigation required for {high_risk_count} high-risk identity profile(s)',
            'details': 'Focus on critical and high-risk profiles for further investigation and verification'
        })
    
    # Platform expansion
    if presences:
        platforms = list(set(p.get('platform_name') for p in presences))
        if len(platforms) < 10:
            recommendations.append({
                'priority': 'medium',
                'category': 'Platform Expansion',
                'action': 'Expand platform search coverage',
                'details': f'Currently found on {len(platforms)} platforms. Consider additional platform searches for broader coverage'
            })
    
    # Low confidence artifacts verification
    low_confidence = [a for a in artifacts if a.get('confidence', 0) < 0.5]
    if len(low_confidence) > len(artifacts) * 0.3:  # More than 30% low confidence
        recommendations.append({
            'priority': 'medium',
            'category': 'Data Verification',
            'action': 'Verify low-confidence findings',
            'details': f'{len(low_confidence)} artifacts have confidence below 50%. Manual verification recommended'
        })
    
    # Breach data analysis
    breach_artifacts = [a for a in artifacts if (a.get('source') or '').lower() in ['breach', 'hibp', 'pwned']]
    if breach_artifacts:
        recommendations.append({
            'priority': 'high',
            'category': 'Breach Analysis',
            'action': 'Analyze breach exposure patterns',
            'details': f'{len(breach_artifacts)} artifacts from breach sources. Analyze for credential reuse patterns'
        })
    
    # Cross-platform correlation
    if len(correlation.identities) > 1:
        recommendations.append({
            'priority': 'medium',
            'category': 'Identity Correlation',
            'action': 'Deep dive into identity relationships',
            'details': f'{len(correlation.identities)} identity profiles detected. Investigate potential connections between profiles'
        })
    
    # Depth expansion
    max_depth = max((a.get('depth', 0) for a in artifacts), default=0)
    if max_depth < 2:
        recommendations.append({
            'priority': 'low',
            'category': 'Investigation Depth',
            'action': 'Consider deeper investigation',
            'details': f'Current investigation depth: {max_depth}. Consider increasing depth for more comprehensive results'
        })
    
    return recommendations


def _generate_priority_queue(artifacts: list, links: list, correlation) -> list:
    """Generate priority queue for artifact ranking based on investigation value."""
    scored_artifacts = []
    
    for artifact in artifacts:
        score = 0
        factors = []
        
        # Confidence score (0-40 points)
        confidence = artifact.get('confidence', 0)
        score += confidence * 40
        factors.append(f"Confidence: {confidence:.0%}")
        
        # Artifact type priority (0-30 points)
        artifact_type = artifact.get('artifact_type', 'unknown')
        type_priority = {
            'email': 30,
            'phone': 28,
            'username': 25,
            'image': 20,
            'platform_presence': 15,
            'location': 18,
            'breach_data': 35,
            'risk_indicator': 40
        }
        score += type_priority.get(artifact_type, 10)
        factors.append(f"Type: {artifact_type}")
        
        # Depth priority (0-15 points) - deeper artifacts often more valuable
        depth = artifact.get('depth', 0)
        score += min(depth * 5, 15)
        factors.append(f"Depth: {depth}")
        
        # Connection count (0-15 points) - highly connected artifacts more valuable
        artifact_id = artifact.get('artifact_id')
        connection_count = sum(1 for link in links if link.get('source_artifact') == artifact_id or link.get('target_artifact') == artifact_id)
        score += min(connection_count * 3, 15)
        factors.append(f"Connections: {connection_count}")
        
        scored_artifacts.append({
            'artifact': artifact,
            'score': score,
            'factors': factors,
            'priority': 'critical' if score >= 70 else 'high' if score >= 50 else 'medium' if score >= 30 else 'low'
        })
    
    # Sort by score descending
    scored_artifacts.sort(key=lambda x: x['score'], reverse=True)
    
    return scored_artifacts[:20]  # Return top 20 priority artifacts


def _generate_geographic_data(artifacts: list, presences: list) -> dict:
    """Generate geographic data from artifacts and platform presences."""
    locations = []

    for artifact in artifacts:
        atype = artifact.get("artifact_type")
        if atype in ("location", "gps_coordinates", "geolocation"):
            locations.append({
                "type": atype,
                "value": artifact.get("value", ""),
                "source": artifact.get("source", "unknown"),
                "confidence": artifact.get("confidence", 0),
            })
        # Phone OSINT often stores country in metadata
        meta_raw = artifact.get("metadata")
        if meta_raw and atype == "phone":
            try:
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
            except (ValueError, TypeError):
                meta = {}
            if isinstance(meta, dict):
                country = meta.get("country") or meta.get("region")
                if country:
                    locations.append({
                        "type": "phone_region",
                        "value": str(country),
                        "source": artifact.get("source", "phone_osint"),
                        "confidence": artifact.get("confidence", 0),
                    })

    for presence in presences:
        bio = (presence.get("bio") or "").lower()
        if any(loc in bio for loc in ["usa", "us", "uk", "india", "germany", "france", "canada", "australia"]):
            locations.append({
                "type": "platform",
                "value": presence.get("platform_name", ""),
                "source": "platform_bio",
                "confidence": 0.5,
            })

    map_url = None
    for loc in locations:
        value = str(loc.get("value") or "")
        # Prefer explicit lat,lon pairs
        if "," in value and any(ch.isdigit() for ch in value):
            parts = [p.strip() for p in value.split(",")]
            if len(parts) >= 2:
                map_url = f"https://www.openstreetmap.org/search?query={parts[0]}%2C{parts[1]}"
                break
    if not map_url and locations:
        from urllib.parse import quote
        map_url = f"https://www.openstreetmap.org/search?query={quote(str(locations[0]['value']))}"

    return {
        "has_location_data": len(locations) > 0,
        "location_count": len(locations),
        "locations": locations[:20],
        "map_url": map_url,
    }


def _generate_platform_heatmap(presences: list) -> dict:
    """Generate platform heat map data showing platform distribution."""
    if not presences:
        return {'has_platform_data': False, 'platforms': []}
    
    platform_counts = {}
    for presence in presences:
        platform = presence.get('platform_name', 'unknown')
        platform_counts[platform] = platform_counts.get(platform, 0) + 1
    
    # Calculate percentages
    total = sum(platform_counts.values()) or 1
    platform_data = []
    for platform, count in sorted(platform_counts.items(), key=lambda x: x[1], reverse=True):
        platform_data.append({
            'platform': platform,
            'count': count,
            'percentage': round(count / total * 100, 1)
        })
    
    return {
        'has_platform_data': len(platform_data) > 0,
        'total_platforms': len(platform_data),
        'platforms': platform_data[:15]  # Limit to top 15
    }


def _generate_correlation_strength(links: list) -> dict:
    """Generate correlation strength indicators for artifact connections."""
    if not links:
        return {'has_correlation_data': False, 'strength_distribution': {}}
    
    strength_distribution = {
        'very_strong': 0,  # >= 0.9
        'strong': 0,        # >= 0.7
        'moderate': 0,     # >= 0.5
        'weak': 0,          # >= 0.3
        'very_weak': 0      # < 0.3
    }
    
    for link in links:
        confidence = link.get('confidence', 0)
        if confidence >= 0.9:
            strength_distribution['very_strong'] += 1
        elif confidence >= 0.7:
            strength_distribution['strong'] += 1
        elif confidence >= 0.5:
            strength_distribution['moderate'] += 1
        elif confidence >= 0.3:
            strength_distribution['weak'] += 1
        else:
            strength_distribution['very_weak'] += 1
    
    total = sum(strength_distribution.values()) or 1
    
    return {
        'has_correlation_data': True,
        'total_links': len(links),
        'strength_distribution': strength_distribution,
        'strength_percentages': {k: round(v/total * 100, 1) for k, v in strength_distribution.items()},
        'average_confidence': round(sum(link.get('confidence', 0) for link in links) / len(links), 2) if links else 0
    }


def _generate_verification_status(artifacts: list) -> dict:
    """Generate verification status tracking for artifacts."""
    if not artifacts:
        return {'has_verification_data': False, 'status_distribution': {}}
    
    status_distribution = {
        'verified': 0,      # confidence >= 0.8
        'likely': 0,        # confidence >= 0.6
        'possible': 0,      # confidence >= 0.4
        'unverified': 0,    # confidence < 0.4
        'needs_review': 0   # confidence between 0.4 and 0.6
    }
    
    for artifact in artifacts:
        confidence = artifact.get('confidence', 0)
        if confidence >= 0.8:
            status_distribution['verified'] += 1
        elif confidence >= 0.6:
            status_distribution['likely'] += 1
        elif confidence >= 0.4:
            status_distribution['possible'] += 1
        else:
            status_distribution['unverified'] += 1
    
    # Calculate needs_review (possible artifacts that need manual verification)
    status_distribution['needs_review'] = status_distribution['possible']
    
    total = sum(status_distribution.values()) or 1
    
    return {
        'has_verification_data': True,
        'total_artifacts': len(artifacts),
        'status_distribution': status_distribution,
        'status_percentages': {k: round(v/total * 100, 1) for k, v in status_distribution.items()},
        'verification_rate': round(status_distribution['verified'] / total * 100, 1) if total > 0 else 0
    }


def _generate_anomaly_detection(artifacts: list, links: list) -> dict:
    """Generate anomaly detection for unusual artifacts."""
    if not artifacts:
        return {'has_anomalies': False, 'anomalies': []}
    
    anomalies = []
    
    # Calculate average confidence
    avg_confidence = sum(a.get('confidence', 0) for a in artifacts) / len(artifacts) if artifacts else 0
    
    # Detect artifacts with unusually low confidence
    for artifact in artifacts:
        confidence = artifact.get('confidence', 0)
        if confidence < avg_confidence * 0.5 and confidence < 0.3:
            anomalies.append({
                'type': 'low_confidence',
                'artifact': artifact,
                'reason': f'Confidence ({confidence:.0%}) significantly below average ({avg_confidence:.0%})'
            })
    
    # Detect artifacts with unusual depth (too deep or too shallow)
    depths = [a.get('depth', 0) for a in artifacts]
    avg_depth = sum(depths) / len(depths) if depths else 0
    for artifact in artifacts:
        depth = artifact.get('depth', 0)
        if depth > avg_depth * 3 and depth > 2:
            anomalies.append({
                'type': 'deep_artifact',
                'artifact': artifact,
                'reason': f'Depth ({depth}) unusually deep compared to average ({avg_depth:.1f})'
            })
    
    # Detect orphaned artifacts (no connections)
    artifact_ids = {a.get('artifact_id') for a in artifacts}
    connected_ids = set()
    for link in links:
        connected_ids.add(link.get('source_artifact'))
        connected_ids.add(link.get('target_artifact'))
    
    orphaned = artifact_ids - connected_ids
    for artifact in artifacts:
        if artifact.get('artifact_id') in orphaned:
            anomalies.append({
                'type': 'orphaned',
                'artifact': artifact,
                'reason': 'No connections to other artifacts'
            })
    
    return {
        'has_anomalies': len(anomalies) > 0,
        'anomaly_count': len(anomalies),
        'anomalies': anomalies[:15]  # Limit to top 15
    }


def _generate_auto_escalation(artifacts: list, links: list, risk_levels: list, correlation) -> dict:
    """Generate auto-escalation alerts for high-risk findings."""
    escalations = []
    
    # Critical risk identities
    critical_count = sum(1 for level in risk_levels if level == 'critical')
    if critical_count > 0:
        escalations.append({
            'severity': 'critical',
            'type': 'high_risk_identity',
            'message': f'{critical_count} critical-risk identity profile(s) detected',
            'action': 'Immediate investigation and verification required'
        })
    
    # High-risk artifacts (breach data, risk indicators)
    high_risk_artifacts = [a for a in artifacts if a.get('artifact_type') in ['breach_data', 'risk_indicator']]
    if len(high_risk_artifacts) > 0:
        escalations.append({
            'severity': 'high',
            'type': 'risk_indicators',
            'message': f'{len(high_risk_artifacts)} high-risk artifact(s) found',
            'action': 'Review breach data and risk indicators for potential impact'
        })
    
    # Strong correlations (multiple identities with high confidence)
    high_confidence_identities = [id for id in correlation.identities if id.confidence >= 0.8]
    if len(high_confidence_identities) > 1:
        escalations.append({
            'severity': 'medium',
            'type': 'strong_correlation',
            'message': f'{len(high_confidence_identities)} high-confidence identity profiles linked',
            'action': 'Investigate potential identity theft or impersonation'
        })
    
    # Large number of connections (potential bot or fake account)
    if len(links) > 50:
        escalations.append({
            'severity': 'medium',
            'type': 'excessive_connections',
            'message': f'{len(links)} artifact connections detected',
            'action': 'Review for potential automated or synthetic identity patterns'
        })
    
    return {
        'has_escalations': len(escalations) > 0,
        'escalation_count': len(escalations),
        'escalations': escalations
    }


# Substrings that mark a scraped "profile image" as the platform's stock avatar
# rather than the target's own picture. Platforms serve these with HTTP 200 for
# accounts that never uploaded one, so they are indistinguishable by status.
_PLACEHOLDER_IMAGE_MARKERS = (
    "no-photo",
    "placeholder",
    "default_profile",
    "default-profile",
    "default_open_graph",
    "default_avatar",
    "missing.png",
    "steam_share_image",
    "anonymous",
    "/no_avatar",
    "avatar_default",
)

# Local files are inlined so a report stays viewable off the machine that made
# it. Anything larger is left as a path rather than bloating the HTML.
_MAX_INLINE_IMAGE_BYTES = 512 * 1024

_IMAGE_MIME_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
}


def _is_placeholder_image(url: str) -> bool:
    """Whether a profile image URL is the platform's stock avatar."""
    lowered = url.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_IMAGE_MARKERS)


def _inline_local_image(path: str) -> Optional[str]:
    """Turn a local image path into a data URI, or None if it cannot be inlined.

    Seeded and downloaded images are stored as filesystem paths, which a browser
    resolves against the report's own location — so the avatar silently fails to
    load as soon as the report is opened anywhere else. Callers keep the path as
    a candidate regardless: on the machine that ran the investigation an absolute
    path still resolves, and a camera photo is routinely too big to inline.
    """
    file = Path(path)
    mime = _IMAGE_MIME_TYPES.get(file.suffix.lower())
    if not mime:
        return None
    try:
        if file.stat().st_size > _MAX_INLINE_IMAGE_BYTES:
            logger.debug("Profile image %s is too large to inline", path)
            return None
        encoded = base64.b64encode(file.read_bytes()).decode("ascii")
    except OSError:
        logger.debug("Could not read profile image %s", path)
        return None
    return f"data:{mime};base64,{encoded}"


def _label_for_image(url: str, presence_platforms: dict, artifact_sources: dict) -> str:
    """Where an identity's profile image came from, for the caption."""
    platform = presence_platforms.get(url)
    if platform:
        return platform
    source = artifact_sources.get(url)
    if not source:
        return "Unknown source"
    if source == "seed":
        return "Seed image"
    tool = _normalize_tool_source(source)
    if source.startswith(("profile_image_", "image_search_", "face_match_")):
        return source.split("_", 2)[-1].replace("_", " ").title()
    return (tool or source).replace("_", " ").title()


@lru_cache(maxsize=256)
def _inline_remote_image(url: str) -> Optional[str]:
    """Download a remote image and return a data URI, or None on failure.

    Reports are often opened as file:// pages; many CDNs (GitHub avatars,
    etc.) refuse or fail those requests, so the <img> fires onerror and the
    avatar disappears. Embedding the bytes keeps the picture visible offline.

    Cached per URL: correlated identities routinely share the same avatar, and
    every miss costs a request with an eight-second timeout.
    """
    if not url or not url.lower().startswith(("http://", "https://")):
        return None
    try:
        from src.utils.http_client import get_http_session
        session = get_http_session()
        resp = session.get(url, timeout=8, stream=True)
        if resp.status_code != 200:
            return None
        content_type = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type not in (
            "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/bmp",
        ):
            # GitHub sometimes omits/varies Content-Type; sniff from magic bytes.
            content_type = ""
        # Cap download size
        chunks = []
        total = 0
        for chunk in resp.iter_content(8192):
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_INLINE_IMAGE_BYTES:
                return None
            chunks.append(chunk)
        data = b"".join(chunks)
        if not data:
            return None
        if not content_type:
            if data.startswith(b"\x89PNG"):
                content_type = "image/png"
            elif data.startswith(b"\xff\xd8"):
                content_type = "image/jpeg"
            elif data.startswith(b"GIF8"):
                content_type = "image/gif"
            elif data.startswith(b"RIFF") and b"WEBP" in data[:16]:
                content_type = "image/webp"
            else:
                return None
        encoded = base64.b64encode(data).decode("ascii")
        return f"data:{content_type};base64,{encoded}"
    except Exception as exc:
        logger.debug("Could not inline remote profile image %s: %s", url, exc)
        return None


def _resolve_image_src(url: str) -> tuple[Optional[str], bool]:
    """A browser-loadable src for an image, and whether it stayed a local path.

    A local file that is too big, unreadable or of an unrecognised type cannot be
    embedded, but the path itself still resolves for the investigator who ran the
    case — dropping the candidate outright is how a seeded camera photo ends up
    invisible.
    """
    if not url:
        return None, False
    lowered = url.lower()
    if lowered.startswith("data:"):
        return url, False
    if lowered.startswith(("http://", "https://")):
        return _inline_remote_image(url) or url, False
    inlined = _inline_local_image(url)
    return (inlined, False) if inlined else (url, True)


def _image_caption(label: str, placeholder: bool, local_reference: bool) -> str:
    """Caption naming the image's origin and any caveat about it."""
    if placeholder:
        return f"{label} (stock avatar)"
    if local_reference:
        return f"{label} (local file)"
    return label


def _generate_identity_images(correlation, presences: list, artifacts: list) -> dict:
    """Renderable profile images per identity, best candidate first.

    The correlation engine hands over a bare, alphabetically sorted list of URLs,
    which routinely puts a platform's stock avatar or an unreachable local path
    first — and the template only ever showed the first one, hiding it on error.
    Ranking real pictures ahead of stock ones and keeping the rest as fallbacks
    is what makes an actual face show up.

    Remote HTTP(S) avatars are inlined as data URIs so they still render when the
    report is opened from disk (file://) without network/hotlink access.
    """
    presence_platforms = {
        p["profile_image_url"]: p.get("platform_name") or "Unknown platform"
        for p in presences
        if p.get("profile_image_url")
    }
    artifact_sources = {
        a["value"]: a.get("source", "")
        for a in artifacts
        if a.get("artifact_type") in ("image", "image_url") and a.get("value")
    }

    # Index presence avatars by username for identities that only have the URL
    # on the platform_presence row (not yet copied onto IdentityProfile.images).
    presence_by_username: dict[str, list] = {}
    for p in presences:
        user = (p.get("username") or "").lower()
        url = p.get("profile_image_url")
        if user and url:
            presence_by_username.setdefault(user, []).append(p)

    per_identity: dict = {}
    for identity in getattr(correlation, "identities", []):
        seen = set()
        urls: list[str] = []
        for url in list(getattr(identity, "images", []) or []):
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        for username in getattr(identity, "usernames", []) or []:
            for presence in presence_by_username.get(username.lower(), []):
                url = presence.get("profile_image_url")
                if url and url not in seen:
                    seen.add(url)
                    urls.append(url)

        candidates = []
        for url in urls:
            src, local = _resolve_image_src(url)
            if not src:
                continue
            label = _label_for_image(url, presence_platforms, artifact_sources)
            placeholder = _is_placeholder_image(url)
            candidates.append({
                "src": src,
                "label": label,
                "placeholder": placeholder,
                "local": local,
                "caption": _image_caption(label, placeholder, local),
            })

        # Stock avatars stay in the list — they are evidence the account exists —
        # but never outrank a real picture.
        candidates.sort(key=lambda c: c["placeholder"])
        per_identity[identity.profile_id] = candidates

    return per_identity


# Slice colours for the artifact-type mix bar, cycled in rank order.
_TYPE_COLORS = (
    "#3182ce", "#38a169", "#dd6b20", "#805ad5", "#319795",
    "#d53f8c", "#718096", "#b7791f", "#2b6cb0", "#c53030",
)


# Sources that are pipeline steps rather than OSINT tools: the orchestrator
# deriving one artifact from another (a username out of an email local part).
# They are reported separately so the tool counts stay honest.
_DERIVED_SOURCES = frozenset({
    "name_username_candidate",
    "email_local_part",
    "email_domain_extraction",
    "correlation_analysis",
    "neo4j_correlation",
    "orchestrator",
    "external_tool",
})

# Built-in scrapers append the platform they scraped to their source.
_PLATFORM_SUFFIXED_SOURCES = (
    "username_search", "profile_image", "image_match", "image_search",
    "google_dorks", "email_osint", "face_match",
)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Human-readable labels for report tiles / charts (raw source keys stay in `tool`).
_TOOL_LABELS = {
    "profile_image": "Profile images",
    "username_search": "Username search",
    "image_match": "Image match",
    "image_search": "Image search",
    "google_dorks": "Google dorks",
    "email_osint": "Email OSINT",
    "face_match": "Face match",
    "email_local_part": "Email local-part",
    "email_domain_extraction": "Email domain",
    "name_username_candidate": "Name → username",
    "correlation_analysis": "Correlation",
    "neo4j_correlation": "Neo4j correlation",
    "orchestrator": "Orchestrator",
    "external_tool": "External tool",
    "phone_osint": "Phone OSINT",
    "wayback_machine": "Wayback Machine",
    "leakosint": "LeakOSINT",
}


def _tool_label(name: Optional[str]) -> str:
    """Readable caption for a normalized tool / scraper source name."""
    if not name:
        return "—"
    if name in _TOOL_LABELS:
        return _TOOL_LABELS[name]
    return name.replace("_", " ").strip().title()


def _normalize_tool_source(source: Optional[str]) -> Optional[str]:
    """Reduce an artifact's `source` to the tool that produced it.

    Sources are written by three different layers and none of them agree on a
    format: the external-tool path writes the bare tool name (`wayback_machine`),
    the plugin path prefixes `plugin:` and uses the class name
    (`plugin:WaybackMachinePlugin`), and the built-in scrapers append the
    platform they scraped (`username_search_github`). All three are folded onto
    the external-tool spelling, otherwise one tool occupies several rows and can
    even be reported as silent while its plugin is producing artifacts.
    """
    if not source:
        return None

    name = source.strip()
    if name in ("seed", "manual", "user"):
        return None

    if name.startswith("plugin:"):
        class_name = name[len("plugin:"):].removesuffix("Plugin")
        return _CAMEL_BOUNDARY.sub("_", class_name).lower()

    for prefix in _PLATFORM_SUFFIXED_SOURCES:
        if name.startswith(prefix + "_"):
            return prefix

    return name.lower()


def _generate_tool_metrics(artifacts: list, correlation) -> dict:
    """Per-tool contribution metrics: what each tool actually produced."""
    per_tool: dict = {}
    per_type: dict = {}
    attributed = 0

    for artifact in artifacts:
        tool = _normalize_tool_source(artifact.get("source"))
        if not tool:
            continue

        attributed += 1
        artifact_type = artifact.get("artifact_type") or "unknown"
        entry = per_tool.setdefault(
            tool,
            {"tool": tool, "count": 0, "types": {}, "confidence_sum": 0.0, "identities": set()},
        )
        entry["count"] += 1
        entry["types"][artifact_type] = entry["types"].get(artifact_type, 0) + 1
        entry["confidence_sum"] += artifact.get("confidence") or 0.0
        per_type[artifact_type] = per_type.get(artifact_type, 0) + 1

    for identity in correlation.identities:
        for finding in getattr(identity, "tool_findings", []) or []:
            tool = _normalize_tool_source(finding.get("source"))
            if tool in per_tool:
                per_tool[tool]["identities"].add(identity.profile_id)

    def _share(count: int, total: int) -> float:
        return round(count * 100.0 / total, 1) if total else 0.0

    tools = []
    for entry in per_tool.values():
        count = entry["count"]
        tool_name = entry["tool"]
        tools.append({
            "tool": tool_name,
            "label": _tool_label(tool_name),
            "count": count,
            "share": _share(count, attributed),
            "avg_confidence": round(entry["confidence_sum"] / count, 2) if count else 0.0,
            "identities": len(entry["identities"]),
            "kind": "derivation" if tool_name in _DERIVED_SOURCES else "tool",
            "types": [
                {"type": t, "count": c}
                for t, c in sorted(entry["types"].items(), key=lambda kv: (-kv[1], kv[0]))
            ],
        })
    tools.sort(key=lambda t: (-t["count"], t["tool"]))

    types = [
        {
            "type": t,
            "label": _tool_label(t) if "_" in t else t.replace("_", " ").title(),
            "count": c,
            "share": _share(c, attributed),
            "color": _TYPE_COLORS[i % len(_TYPE_COLORS)],
        }
        for i, (t, c) in enumerate(sorted(per_type.items(), key=lambda kv: (-kv[1], kv[0])))
    ]
    # Summary tile uses overall highest yield, but with a readable label and
    # the count as the primary figure (raw keys like profile_image are not useful
    # as a large caption).
    top = tools[0] if tools else None

    produced = {t["tool"] for t in tools if t["kind"] == "tool"}
    # An integrated tool missing here either was not installed, was not dispatched
    # for any artifact type in this run, or ran and found nothing -- the report
    # cannot tell those apart, so it only names them.
    silent = sorted(set(TOOL_ARTIFACT_TYPES) - produced)

    return {
        "tools": tools,
        "types": types,
        "attributed": attributed,
        "unattributed": len(artifacts) - attributed,
        "tool_count": len(produced),
        "derivation_count": len(tools) - len(produced),
        "max_count": tools[0]["count"] if tools else 0,
        "top_tool": top["tool"] if top else None,
        "top_tool_label": top["label"] if top else None,
        "top_tool_count": top["count"] if top else 0,
        "integrated_count": len(TOOL_ARTIFACT_TYPES),
        "silent_tools": silent,
    }


def generate_json_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
    *,
    redact: bool = False,
    compare_id: Optional[str] = None,
) -> str:
    """Generate a machine-readable JSON report (SIEM/CTI-friendly)."""
    from src.reporting.report_data import (
        build_cross_investigation,
        build_delta_report,
        build_evidence_chains,
        build_leak_findings,
        build_orphan_findings,
        build_preserved_evidence,
        default_output_path,
        enrich_tool_status,
        load_comments,
        load_reporting_config,
        redact_payload,
    )

    reporting_cfg = load_reporting_config()
    investigation = db.get_investigation(conn, investigation_id)
    if not investigation:
        raise ValueError(f"Investigation {investigation_id} not found")

    artifacts = db.get_artifacts(conn, investigation_id)
    links = db.get_links(conn, investigation_id)
    presences = db.get_platform_presences(conn, investigation_id)
    correlation = correlate_identities(conn, investigation_id)
    artifacts, links, presences, correlation = redact_payload(
        artifacts, links, presences, correlation, redact
    )

    tool_metrics = enrich_tool_status(_generate_tool_metrics(artifacts, correlation))
    orphans = build_orphan_findings(artifacts, correlation)
    leak_findings = build_leak_findings(artifacts, redact=redact)

    report = {
        "meta": {
            "tool": "Ghost Identity Hunter",
            "version": "0.1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "redacted": redact,
        },
        "investigation": investigation,
        "summary": {
            "total_artifacts": len(artifacts),
            "total_links": len(links),
            "total_platforms": len(presences),
            "identity_count": len(correlation.identities),
            "orphan_count": len(orphans),
            "leak_record_count": leak_findings["record_count"],
        },
        "leak_findings": leak_findings,
        "tool_metrics": tool_metrics,
        "identities": [i.to_dict() for i in correlation.identities],
        "artifacts": artifacts,
        "links": links,
        "platform_presences": presences,
        "evidence_chains": build_evidence_chains(artifacts, links),
        "preserved_evidence": build_preserved_evidence(conn, investigation_id, redact),
        "orphan_findings": orphans,
        "cross_investigation": build_cross_investigation(conn, investigation_id, artifacts),
        "delta": build_delta_report(conn, investigation_id, compare_id),
        "comments": load_comments(conn, investigation_id),
        "audit_trail": db.get_audit_trail(conn, investigation_id),
        "graph": {
            "nodes": correlation.graph_nodes,
            "edges": correlation.graph_edges,
            "components": correlation.connected_components,
        },
    }

    if output_path is None:
        output_path = default_output_path(
            investigation_id, ".json", reporting_cfg.get("output_dir")
        )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    logger.info("JSON report saved to %s", output_file)
    return str(output_file)

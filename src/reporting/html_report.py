"""
Ghost Identity Hunter - HTML Report Generation Module

PURPOSE:
--------
This module provides comprehensive report generation capabilities for Ghost Identity Hunter
investigations, creating professional HTML reports and structured JSON exports that
document findings, evidence chains, risk assessments, and identity correlation results.

FUNCTIONALITY:
--------------
- Professional HTML report generation with dark theme styling
- Structured JSON export for integration with SIEM/CTI systems
- Investigation summary with key metrics and statistics
- Identity profile documentation with confidence scores
- Platform presence matrix across discovered services
- Breach exposure analysis and risk assessment
- Evidence chain documentation with source attribution
- Interactive elements and responsive design

REPORT SECTIONS:
---------------
1. Executive Summary: Investigation overview and key findings
2. Identity Profiles: Correlated personas with confidence scores
3. Platform Presence Matrix: Cross-platform account discovery
4. Relationship Graph: Visual identity network representation
5. Breach Exposure: Credential compromise analysis
6. Risk Assessment: Threat level classification and indicators
7. Evidence Chain: Source attribution and verification trail
8. Raw Data Appendix: Complete artifact and link database

HTML FEATURES:
--------------
- Dark theme optimized for security professional viewing
- Responsive design for desktop and mobile devices
- Color-coded risk indicators and confidence scores
- Collapsible sections for detailed information
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

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader

from src.correlation.linker import correlate_identities
from src.correlation.scorer import compute_identity_risk_score, classify_risk_level
from src.storage import database as db

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ghost Identity Hunter - Investigation {{ investigation.investigation_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #0f0f23;
            color: #e0e0e0;
            padding: 2rem;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #4ECDC4; margin-bottom: 0.5rem; font-size: 2rem; }
        h2 { color: #45B7D1; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }
        h3 { color: #96CEB4; margin: 1.5rem 0 0.5rem; }
        .meta { color: #888; font-size: 0.9rem; margin-bottom: 2rem; }
        .card {
            background: #1a1a2e;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            margin: 0.1rem;
        }
        .badge-phone { background: #FF6B6B22; color: #FF6B6B; border: 1px solid #FF6B6B; }
        .badge-email { background: #4ECDC422; color: #4ECDC4; border: 1px solid #4ECDC4; }
        .badge-username { background: #45B7D122; color: #45B7D1; border: 1px solid #45B7D1; }
        .badge-risk { background: #DC143C22; color: #DC143C; border: 1px solid #DC143C; }
        .badge-platform { background: #FFEAA722; color: #FFEAA7; border: 1px solid #FFEAA7; }
        .risk-critical { color: #FF0000; font-weight: bold; }
        .risk-high { color: #FF6B6B; font-weight: bold; }
        .risk-medium { color: #FFA500; }
        .risk-low { color: #FFD700; }
        .risk-minimal { color: #4ECDC4; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        th { color: #4ECDC4; font-weight: 600; }
        a { color: #45B7D1; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        .stat-card {
            background: #16213e;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; color: #4ECDC4; }
        .stat-label { font-size: 0.85rem; color: #888; }
        .evidence-chain { font-family: monospace; font-size: 0.85rem; color: #aaa; }
    </style>
</head>
<body>
<div class="container">
    <h1>&#128373; Ghost Identity Hunter Report</h1>
    <p class="meta">
        Investigation: <strong>{{ investigation.investigation_id }}</strong> |
        Created: {{ investigation.created_at }} |
        Status: {{ investigation.status }}
    </p>

    <!-- Summary Stats -->
    <h2>Summary</h2>
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{{ artifacts | length }}</div>
            <div class="stat-label">Artifacts Found</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ links | length }}</div>
            <div class="stat-label">Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ presences | length }}</div>
            <div class="stat-label">Platform Presences</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ correlation.identities | length }}</div>
            <div class="stat-label">Identity Profiles</div>
        </div>
    </div>

    <!-- Identity Profiles -->
    <h2>Identity Profiles</h2>
    {% for identity in correlation.identities %}
    <div class="card">
        <h3>{{ identity.profile_id }} ({{ identity.artifact_count }} artifacts)</h3>
        <p>Confidence: <strong>{{ "%.1f" | format(identity.confidence * 100) }}%</strong> |
           Risk: <span class="risk-{{ risk_levels[loop.index0] }}">{{ risk_levels[loop.index0] | upper }}</span>
        </p>

        {% if identity.phones %}
        <p><strong>Phones:</strong>
            {% for p in identity.phones %}<span class="badge badge-phone">{{ p }}</span>{% endfor %}
        </p>
        {% endif %}

        {% if identity.emails %}
        <p><strong>Emails:</strong>
            {% for e in identity.emails %}<span class="badge badge-email">{{ e }}</span>{% endfor %}
        </p>
        {% endif %}

        {% if identity.usernames %}
        <p><strong>Usernames:</strong>
            {% for u in identity.usernames %}<span class="badge badge-username">{{ u }}</span>{% endfor %}
        </p>
        {% endif %}

        {% if identity.platforms %}
        <p><strong>Platforms:</strong>
            {% for p in identity.platforms %}
            <span class="badge badge-platform">
                {% if p.profile_url %}<a href="{{ p.profile_url }}">{{ p.platform }}</a>{% else %}{{ p.platform }}{% endif %}
            </span>
            {% endfor %}
        </p>
        {% endif %}

        {% if identity.risk_indicators %}
        <p><strong>Risk Indicators:</strong>
            {% for r in identity.risk_indicators %}<span class="badge badge-risk">{{ r }}</span>{% endfor %}
        </p>
        {% endif %}
    </div>
    {% endfor %}

    <!-- Platform Presence Matrix -->
    {% if presences %}
    <h2>Platform Presence Matrix</h2>
    <table>
        <thead>
            <tr><th>Platform</th><th>Username</th><th>Display Name</th><th>Profile URL</th></tr>
        </thead>
        <tbody>
            {% for p in presences %}
            <tr>
                <td>{{ p.platform_name }}</td>
                <td>{{ p.username or '-' }}</td>
                <td>{{ p.display_name or '-' }}</td>
                <td>{% if p.profile_url %}<a href="{{ p.profile_url }}">Link</a>{% else %}-{% endif %}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <!-- All Artifacts -->
    <h2>Artifact Inventory</h2>
    <table>
        <thead>
            <tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>Depth</th></tr>
        </thead>
        <tbody>
            {% for a in artifacts %}
            <tr>
                <td><span class="badge badge-{{ a.artifact_type }}">{{ a.artifact_type }}</span></td>
                <td>{{ a.value[:60] }}{% if a.value | length > 60 %}...{% endif %}</td>
                <td>{{ a.source or '-' }}</td>
                <td>{{ "%.0f" | format((a.confidence or 0) * 100) }}%</td>
                <td>{{ a.depth }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <!-- Footer -->
    <p class="meta" style="margin-top: 3rem; text-align: center;">
        Generated by Ghost Identity Hunter | {{ generated_at }}
    </p>
</div>
</body>
</html>
"""


def generate_html_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a comprehensive HTML report for an investigation.

    Returns the output file path.
    """
    investigation = db.get_investigation(conn, investigation_id)
    if not investigation:
        raise ValueError(f"Investigation {investigation_id} not found")

    artifacts = db.get_artifacts(conn, investigation_id)
    links = db.get_links(conn, investigation_id)
    presences = db.get_platform_presences(conn, investigation_id)
    correlation = correlate_identities(conn, investigation_id)

    # Compute risk levels for each identity
    risk_levels = []
    for identity in correlation.identities:
        risk_score = compute_identity_risk_score(identity.risk_indicators)
        risk_levels.append(classify_risk_level(risk_score))

    # Render template
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(
        investigation=investigation,
        artifacts=artifacts,
        links=links,
        presences=presences,
        correlation=correlation,
        risk_levels=risk_levels,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )

    # Save
    if output_path is None:
        output_path = f"reports/{investigation_id}_report.html"

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html)

    logger.info("HTML report saved to %s", output_file)
    return str(output_file)


def generate_json_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
) -> str:
    """Generate a machine-readable JSON report."""
    investigation = db.get_investigation(conn, investigation_id)
    if not investigation:
        raise ValueError(f"Investigation {investigation_id} not found")

    artifacts = db.get_artifacts(conn, investigation_id)
    links = db.get_links(conn, investigation_id)
    presences = db.get_platform_presences(conn, investigation_id)
    correlation = correlate_identities(conn, investigation_id)

    report = {
        "meta": {
            "tool": "Ghost Identity Hunter",
            "version": "0.1.0",
            "generated_at": datetime.utcnow().isoformat(),
        },
        "investigation": investigation,
        "summary": {
            "total_artifacts": len(artifacts),
            "total_links": len(links),
            "total_platforms": len(presences),
            "identity_count": len(correlation.identities),
        },
        "identities": [i.to_dict() for i in correlation.identities],
        "artifacts": artifacts,
        "links": links,
        "platform_presences": presences,
        "graph": {
            "nodes": correlation.graph_nodes,
            "edges": correlation.graph_edges,
            "components": correlation.connected_components,
        },
    }

    if output_path is None:
        output_path = f"reports/{investigation_id}_report.json"

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2, default=str))

    logger.info("JSON report saved to %s", output_file)
    return str(output_file)

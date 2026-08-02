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

import json
import logging
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader

from src.correlation.linker import correlate_identities
from src.correlation.scorer import compute_identity_risk_score, classify_risk_level
from src.modules.external_tools import TOOL_ARTIFACT_TYPES
from src.storage import database as db

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Investigation Report - {{ investigation.investigation_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            padding: 0;
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        
        /* Professional Header */
        .header {
            background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
            color: white;
            padding: 2rem;
            margin: -2rem -2rem 2rem -2rem;
            border-bottom: 4px solid #c53030;
        }
        .header h1 { color: white; margin: 0; font-size: 1.8rem; font-weight: 600; }
        .header .meta { color: #cbd5e0; font-size: 0.9rem; margin-top: 0.5rem; }
        .classification {
            display: inline-block;
            background: #c53030;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 1rem;
        }
        
        /* Content Styling */
        h2 { 
            color: #1e3a5f; 
            border-bottom: 2px solid #3182ce; 
            padding-bottom: 0.5rem; 
            margin-top: 2rem; 
            margin-bottom: 1rem;
        }
        
        .section-blurb {
            color: #4a5568;
            font-size: 0.9rem;
            margin-bottom: 1rem;
            padding: 0.75rem;
            background: #f7fafc;
            border-left: 4px solid #3182ce;
            border-radius: 4px;
            line-height: 1.5;
        }
        
        .subsection-blurb {
            color: #718096;
            font-size: 0.85rem;
            margin-bottom: 0.75rem;
            font-style: italic;
        }
        
        h3 { 
            color: #2d3748; 
            margin-top: 1.5rem; 
            margin-bottom: 0.75rem;
        }
        
        .meta { color: #718096; font-size: 0.85rem; margin-bottom: 1rem; }
        
        /* Professional Cards */
        .card {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        /* Professional Badges.
           Qualified with the element name so the Bootstrap bundled inside the
           embedded pyvis graph (".badge { color: #fff }") cannot win and render
           these white on white. */
        span.badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin: 0.1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: #e2e8f0;
            color: #2d3748;
            border: 1px solid #cbd5e0;
        }
        span.badge-phone { background: #fed7d7; color: #c53030; border: 1px solid #feb2b2; }
        span.badge-email { background: #bee3f8; color: #2b6cb0; border: 1px solid #90cdf4; }
        span.badge-username { background: #c6f6d5; color: #276749; border: 1px solid #9ae6b4; }
        span.badge-domain { background: #feebc8; color: #9c4221; border: 1px solid #fbd38d; }
        /* Class names come from the artifact type verbatim (badge-{{ type }}). */
        span.badge-ip_address { background: #e9d8fd; color: #553c9a; border: 1px solid #d6bcfa; }
        span.badge-platform_presence { background: #e2e8f0; color: #4a5568; border: 1px solid #cbd5e0; }
        span.badge-risk { background: #c53030; color: white; border: 1px solid #9b2c2c; }
        span.badge-validated { background: #c6f6d5; color: #22543d; border: 1px solid #9ae6b4; }
        span.badge-unvalidated { background: #fefcbf; color: #744210; border: 1px solid #f6e05e; }
        
        /* Risk Levels */
        .risk-critical { color: #c53030; font-weight: bold; background: #fed7d7; padding: 0.2rem 0.5rem; border-radius: 4px; }
        .risk-high { color: #dd6b20; font-weight: bold; background: #feebc8; padding: 0.2rem 0.5rem; border-radius: 4px; }
        .risk-medium { color: #d69e2e; background: #faf089; padding: 0.2rem 0.5rem; border-radius: 4px; }
        .risk-low { color: #38a169; background: #c6f6d5; padding: 0.2rem 0.5rem; border-radius: 4px; }
        .risk-minimal { color: #3182ce; background: #bee3f8; padding: 0.2rem 0.5rem; border-radius: 4px; }
        
        /* Professional Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: white;
        }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th { 
            background: #f7fafc; 
            color: #2d3748; 
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #cbd5e0;
            position: sticky;
            top: 0;
            z-index: 1;
        }
        tr:hover { background: #f7fafc; }
        
        /* Links */
        a { color: #3182ce; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; color: #2c5282; }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        .stat-card {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 1.25rem;
            text-align: center;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        .stat-value { font-size: 2rem; font-weight: 700; color: #1e3a5f; }
        .stat-label { font-size: 0.8rem; color: #718096; text-transform: uppercase; letter-spacing: 0.5px; }

        /* Tool metrics infographic. Bars are plain divs sized with an inline
           width percentage so the report stays a single self-contained file
           with no chart library and prints correctly. */
        .tool-chart { display: grid; grid-template-columns: 11rem 1fr 4rem; gap: 0.5rem 0.75rem; align-items: center; }
        .tool-chart-name { font-size: 0.85rem; font-weight: 600; color: #2d3748; word-break: break-all; }
        .tool-chart-track { background: #edf2f7; border-radius: 3px; height: 1.4rem; overflow: hidden; }
        .tool-chart-bar { background: #3182ce; height: 100%; border-radius: 3px; min-width: 2px; }
        .tool-chart-count { font-size: 0.85rem; color: #4a5568; text-align: right; font-variant-numeric: tabular-nums; }
        .type-bar { display: flex; width: 100%; height: 1.6rem; border-radius: 3px; overflow: hidden; border: 1px solid #e2e8f0; margin-bottom: 0.75rem; }
        .type-bar-slice { height: 100%; }
        .type-legend { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; font-size: 0.8rem; color: #4a5568; }
        .type-legend-swatch { display: inline-block; width: 0.7rem; height: 0.7rem; border-radius: 2px; margin-right: 0.35rem; }
        .silent-tools { font-size: 0.85rem; color: #718096; }

        /* Evidence Chain */
        .evidence-chain { 
            font-family: 'Courier New', monospace; 
            font-size: 0.85rem; 
            color: #4a5568; 
            background: #f7fafc;
            padding: 1rem;
            border-radius: 4px;
            border-left: 3px solid #3182ce;
        }
        
        /* Collapsible Sections */
        .collapsible {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        .collapsible-header {
            background: #f7fafc;
            padding: 1rem 1.5rem;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            border-bottom: 1px solid #e2e8f0;
        }
        .collapsible-header:hover { background: #edf2f7; }
        .collapsible-header h4 { margin: 0; color: #2d3748; font-size: 0.95rem; font-weight: 600; }
        .collapsible-content { padding: 1.5rem; display: none; }
        .collapsible.active .collapsible-content { display: block; }
        .collapsible-icon { color: #718096; font-size: 1.2rem; transition: transform 0.2s; }
        .collapsible.active .collapsible-icon { transform: rotate(180deg); }

        /* Drill-down (native details/summary) */
        details.drilldown {
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            background: white;
            margin-bottom: 0.5rem;
        }
        details.drilldown > summary {
            list-style: none;
            cursor: pointer;
            padding: 0.65rem 1rem;
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            align-items: center;
            background: #fbfdff;
            border-radius: 6px;
        }
        details.drilldown > summary::-webkit-details-marker { display: none; }
        details.drilldown > summary::before {
            content: '\\25B8';
            color: #718096;
            font-size: 0.8rem;
            width: 0.8rem;
        }
        details.drilldown[open] > summary::before { content: '\\25BE'; }
        details.drilldown > summary:hover { background: #edf2f7; }
        details.drilldown[open] > summary { border-bottom: 1px solid #e2e8f0; }
        .drilldown-body { padding: 1rem 1.5rem; }
        .drilldown-body h5 {
            margin: 1rem 0 0.4rem 0;
            color: #2d3748;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .drilldown-body h5:first-child { margin-top: 0; }
        .summary-value { font-weight: 600; color: #1e3a5f; }
        .summary-meta { color: #718096; font-size: 0.85rem; }
        .kv-table td:first-child {
            width: 30%;
            color: #4a5568;
            font-weight: 600;
            vertical-align: top;
            word-break: break-word;
        }
        .kv-table td { font-size: 0.85rem; word-break: break-word; }
        .empty-note { color: #718096; font-size: 0.85rem; font-style: italic; }
        .thumb {
            width: 72px;
            height: 72px;
            object-fit: cover;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }

        /* Report metadata banner */
        .report-banner {
            background: white;
            border: 1px solid #e2e8f0;
            border-left: 4px solid #1e3a5f;
            border-radius: 6px;
            padding: 1rem 1.5rem;
            margin-bottom: 1.5rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem 1.5rem;
            font-size: 0.85rem;
            color: #4a5568;
        }
        .report-banner strong { color: #2d3748; }

        /* Expand / collapse controls */
        .drilldown-controls { margin: 0.5rem 0 1rem 0; }
        .drilldown-controls button {
            font: inherit;
            font-size: 0.8rem;
            font-weight: 600;
            color: #2c5282;
            background: white;
            border: 1px solid #cbd5e0;
            border-radius: 4px;
            padding: 0.35rem 0.9rem;
            margin-right: 0.5rem;
            cursor: pointer;
        }
        .drilldown-controls button:hover { background: #edf2f7; }

        /* Print */
        @media print {
            body { background: white; }
            .drilldown-controls { display: none; }
            details.drilldown > summary { background: white; }
            details.drilldown, .card { break-inside: avoid; }
            th { position: static; }
        }
        
        /* Footer */
        .footer {
            background: #2d3748;
            color: #cbd5e0;
            padding: 1.5rem;
            margin: 2rem -2rem -2rem -2rem;
            text-align: center;
            font-size: 0.85rem;
        }
        .footer a { color: #90cdf4; }
        
        /* Graph Container */
        .graph-container {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
            min-height: 400px;
        }
        
        /* Priority Queue */
        .priority-critical { border-left: 4px solid #c53030; }
        .priority-high { border-left: 4px solid #dd6b20; }
        .priority-medium { border-left: 4px solid #d69e2e; }
        .priority-low { border-left: 4px solid #38a169; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Professional Header -->
        <div class="header">
            <h1>Ghost Identity Hunter - OSINT Investigation Report</h1>
            <div class="meta">
                <strong>Investigation ID:</strong> {{ investigation.investigation_id }} | 
                <strong>Title:</strong> {{ investigation.title or 'Untitled Investigation' }} | 
                <strong>Status:</strong> {{ (investigation.status or 'Unknown') | title }} | 
                <strong>Generated:</strong> {{ generated_at }}
            </div>
            <div class="classification">Confidential &mdash; Investigative Use Only</div>
        </div>

    <!-- Report Metadata -->
    <div class="report-banner">
        <div><strong>Case reference:</strong> {{ investigation.investigation_id }}</div>
        <div><strong>Opened:</strong> {{ (investigation.created_at or '-')[:19] }}</div>
        <div><strong>Report generated:</strong> {{ generated_at }}</div>
        <div><strong>Artifacts / links:</strong> {{ artifacts | length }} / {{ links | length }}</div>
        <div><strong>Identity profiles:</strong> {{ correlation.identities | length }}</div>
        <div><strong>Handling:</strong> Automated analysis &mdash; requires analyst review</div>
    </div>

    <div class="drilldown-controls">
        <button type="button" id="expand-all">Expand all details</button>
        <button type="button" id="collapse-all">Collapse all details</button>
    </div>

    <!-- Identity Profiles -->
    <h2>1. Identity Profiles</h2>
    <p class="section-blurb">Correlated personas that link multiple artifacts to single identities, showing confidence scores, associated risk indicators, and profile images for understanding the target's digital footprint. Expand a profile to review its complete evidence basis.</p>
    {% for identity in correlation.identities %}
    <div class="card">
        <h3>Identity Profile #{{ loop.index }}</h3>
        <div style="display: flex; gap: 1.5rem; align-items: flex-start;">
            {% if identity.images and identity.images | length > 0 %}
            <div style="flex-shrink: 0;">
                <div style="width: 120px; height: 120px; border-radius: 8px; overflow: hidden; border: 2px solid #e2e8f0; background: #f7fafc;">
                    <img src="{{ identity.images[0] }}" alt="Profile Image" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.style.display='none'; this.parentElement.style.display='none';">
                </div>
            </div>
            {% endif %}
            <div style="flex: 1;">
                <p><strong>Profile ID:</strong> {{ identity.profile_id }}</p>
                <p><strong>Confidence:</strong> {{ "%.1f%%" | format(identity.confidence * 100) }}</p>
                <p><strong>Artifacts:</strong> {{ identity.artifacts | length }}</p>
                <p><strong>Risk Indicators:</strong> {{ identity.risk_indicators | join(', ') if identity.risk_indicators else 'None' }}</p>
                {% if identity.phones %}
                <p><strong>Phone Numbers:</strong> {{ identity.phones | join(', ') }}</p>
                {% endif %}
                {% if identity.emails %}
                <p><strong>Emails:</strong> {{ identity.emails | join(', ') }}</p>
                {% endif %}
                {% if identity.usernames %}
                <p><strong>Usernames:</strong> {{ identity.usernames | join(', ') }}</p>
                {% endif %}
                {% if identity.platforms %}
                <p><strong>Accounts Found:</strong> {{ identity.platforms | length }}
                   ({{ identity.platforms | map(attribute='platform') | join(', ') }})</p>
                {% endif %}
                {% if identity.domains %}
                <p><strong>Domains:</strong> {{ identity.domains | join(', ') }}</p>
                {% endif %}
                {% if identity.subdomains %}
                <p><strong>Subdomains:</strong> {{ identity.subdomains | join(', ') }}</p>
                {% endif %}
                {% if identity.ip_addresses %}
                <p><strong>IP Addresses:</strong> {{ identity.ip_addresses | join(', ') }}</p>
                {% endif %}
                {% if identity.open_ports %}
                <p><strong>Open Ports:</strong> {{ identity.open_ports | join(', ') }}</p>
                {% endif %}
                {% if identity.hosts %}
                <p><strong>Hosts:</strong> {{ identity.hosts | join(', ') }}</p>
                {% endif %}
                {% if identity.dns_records %}
                <p><strong>DNS Records:</strong> {{ identity.dns_records | join(', ') }}</p>
                {% endif %}
                {% if identity.web_technologies %}
                <p><strong>Web Technologies:</strong> {{ identity.web_technologies | join(', ') }}</p>
                {% endif %}
                {% if identity.geolocations %}
                <p><strong>Geolocation:</strong> {{ identity.geolocations | join(', ') }}</p>
                {% endif %}
                {% if identity.device_info %}
                <p><strong>Device / Capture Metadata:</strong> {{ identity.device_info | join(', ') }}</p>
                {% endif %}
                {% if identity.historical_urls %}
                <p><strong>Historical URLs:</strong> {{ identity.historical_urls | length }} archived
                   (e.g. {{ identity.historical_urls[:3] | join(', ') }})</p>
                {% endif %}
            </div>
        </div>
        {% set profile_artifacts = identity_artifacts.get(identity.profile_id) or [] %}
        <details class="drilldown" style="margin-top: 1rem;">
            <summary><strong>Complete Evidence Basis ({{ profile_artifacts | length }} artifacts)</strong></summary>
            <div class="drilldown-body">
                {% if profile_artifacts %}
                <table>
                    <thead>
                        <tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>Depth</th><th>Discovered</th></tr>
                    </thead>
                    <tbody>
                        {% for a in profile_artifacts %}
                        <tr>
                            <td><span class="badge badge-{{ a.artifact_type }}">{{ a.artifact_type }}</span></td>
                            <td>{{ a.value }}</td>
                            <td>{{ a.source or '-' }}</td>
                            <td>{{ "%.0f%%" | format((a.confidence or 0) * 100) }}</td>
                            <td>{{ a.depth }}</td>
                            <td>{{ a.discovered_at[:19] if a.discovered_at else '-' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="empty-note">No artifacts attributed to this profile.</p>
                {% endif %}
            </div>
        </details>
        {% if identity.tool_findings %}
        <details class="drilldown">
            <summary><strong>External Tool Findings ({{ identity.tool_findings | length }})</strong>
                     &mdash; tools: {{ identity.tools_used | join(', ') }}</summary>
            <div class="drilldown-body">
            <table>
                <thead>
                    <tr><th>Tool</th><th>Artifact Type</th><th>Value</th><th>Confidence</th></tr>
                </thead>
                <tbody>
                    {% for finding in identity.tool_findings %}
                    <tr>
                        <td>{{ finding.source }}</td>
                        <td><span class="badge">{{ finding.type }}</span></td>
                        <td>{{ finding.value[:80] }}{% if finding.value | length > 80 %}...{% endif %}</td>
                        <td>{{ "%.0f%%" | format((finding.confidence or 0) * 100) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            </div>
        </details>
        {% endif %}
    </div>
    {% endfor %}

    <!-- Summary -->
    <h2>2. Summary</h2>
    <p class="section-blurb">Investigation overview including timeline of discoveries, key findings, statistical metrics, confidence scores, and risk assessment matrix.</p>
    <div class="card">
        <h3>Investigation Timeline</h3>
        <p class="subsection-blurb">Chronological sequence showing when each artifact was discovered during the investigation process.</p>
        <table>
            <thead>
                <tr><th>Time</th><th>Type</th><th>Value</th><th>Source</th><th>Depth</th></tr>
            </thead>
            <tbody>
                {% for event in timeline[:10] %}
                <tr>
                    <td>{{ event.time[:19] if event.time else '-' }}</td>
                    <td><span class="badge badge-{{ event.type }}">{{ event.type }}</span></td>
                    <td>{{ event.value[:40] }}{% if event.value | length > 40 %}...{% endif %}</td>
                    <td>{{ event.source or '-' }}</td>
                    <td>{{ event.depth }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h3>Key Findings</h3>
        <p class="subsection-blurb">Most significant discoveries from the investigation including high-value targets, security risks, and important connections.</p>
        <ul>
            {% for finding in key_findings %}
            <li>{{ finding }}</li>
            {% endfor %}
        </ul>
    </div>

    <div class="card">
        <h3>Summary Statistics</h3>
        <p class="subsection-blurb">Aggregate metrics showing total artifacts, connections, identities, and platforms discovered during the investigation.</p>
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
                <div class="stat-value">{{ correlation.identities | length }}</div>
                <div class="stat-label">Identities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ presences | length }}</div>
                <div class="stat-label">Platforms</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h3>Confidence Metrics</h3>
        <p class="subsection-blurb">Overall reliability score of findings broken down by data type, indicating how trustworthy the discovered information is based on source reliability and verification.</p>
        <table>
            <thead>
                <tr><th>Metric</th><th>Value</th></tr>
            </thead>
            <tbody>
                <tr><td>Overall Confidence</td><td>{{ "%.1f%%" | format(confidence_metrics.overall * 100) }}</td></tr>
                {% for type, conf in confidence_metrics.by_type.items() %}
                <tr><td>{{ type | title }}</td><td>{{ "%.1f%%" | format(conf * 100) }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h3>Risk Assessment Matrix</h3>
        <p class="subsection-blurb">Categorizes findings by risk level (Critical, High, Medium, Low) with counts and percentages, providing immediate visual representation of threat exposure.</p>
        <table>
            <thead>
                <tr><th>Risk Level</th><th>Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>
                {% for level, count in risk_matrix.counts.items() %}
                <tr>
                    <td><span class="risk-{{ level }}">{{ level | title }}</span></td>
                    <td>{{ count }}</td>
                    <td>{{ risk_matrix.distribution[level] }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- Tool Metrics -->
    <h2>3. Tool Metrics</h2>
    <p class="section-blurb">What each OSINT tool actually contributed to this investigation: how many artifacts it produced, of which types, at what average confidence, and how many identity profiles its output reached. Seeded artifacts are excluded, so the totals here count only discovered evidence. Rows marked <em>derived</em> are pipeline steps rather than tools &mdash; the orchestrator pivoting one artifact into another &mdash; and are excluded from the tool count.</p>
    <div class="card">
        {% if tool_metrics.tools %}
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ tool_metrics.tool_count }}</div>
                <div class="stat-label">Tools Producing Output</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ tool_metrics.attributed }}</div>
                <div class="stat-label">Tool-Derived Artifacts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ tool_metrics.top_tool }}</div>
                <div class="stat-label">Highest Yield</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ tool_metrics.types | length }}</div>
                <div class="stat-label">Artifact Types Covered</div>
            </div>
        </div>

        <h3>Artifacts per Tool</h3>
        <p class="subsection-blurb">Bar length is relative to the highest-yielding tool. Volume is not quality &mdash; a single domain_info record can outweigh fifty profile hits.</p>
        <div class="tool-chart">
            {% for tool in tool_metrics.tools %}
            <div class="tool-chart-name">{{ tool.tool }}</div>
            <div class="tool-chart-track">
                <div class="tool-chart-bar" style="width: {{ (tool.count * 100 // tool_metrics.max_count) if tool_metrics.max_count else 0 }}%;"></div>
            </div>
            <div class="tool-chart-count">{{ tool.count }}</div>
            {% endfor %}
        </div>

        <h3>Artifact Type Mix</h3>
        <p class="subsection-blurb">Share of tool-derived artifacts by type across the whole investigation.</p>
        <div class="type-bar">
            {% for type in tool_metrics.types %}
            <div class="type-bar-slice" style="width: {{ type.share }}%; background: {{ type.color }};"
                 title="{{ type.type }}: {{ type.count }}"></div>
            {% endfor %}
        </div>
        <div class="type-legend">
            {% for type in tool_metrics.types %}
            <span>
                <span class="type-legend-swatch" style="background: {{ type.color }};"></span>
                {{ type.type }} &mdash; {{ type.count }} ({{ type.share }}%)
            </span>
            {% endfor %}
        </div>

        <h3>Per-Tool Breakdown</h3>
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
                    <td>
                        {% if tool.kind == 'derivation' %}<span class="badge">derived</span>{% endif %}
                        {% for type in tool.types %}
                        <span class="badge badge-{{ type.type }}">{{ type.type }} {{ type.count }}</span>
                        {% endfor %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if tool_metrics.silent_tools %}
        <p class="silent-tools">Integrated but silent in this run ({{ tool_metrics.silent_tools | length }} of {{ tool_metrics.integrated_count }}):
           {{ tool_metrics.silent_tools | join(', ') }}. A tool is silent when it is not installed, was never dispatched for the artifact types seen here, or ran and found nothing.</p>
        {% endif %}
        {% else %}
        <p class="empty-note">No tool-derived artifacts in this investigation &mdash; every artifact came from the seeds.</p>
        {% endif %}
    </div>

    <!-- Platform Presence -->
    <h2>4. Platform Presence</h2>
    <p class="section-blurb">All discovered social media and online platform accounts with direct profile links for verification and understanding the target's online behavior and communication channels. Expand a platform to review the captured profile details.
    <strong>Content-validated</strong> entries were confirmed by inspecting the profile page or API response; <strong>unvalidated (status only)</strong> entries rest on an HTTP 200 alone and may be soft 404s, login walls or app shells &mdash; treat them as leads, not findings.</p>
    <div class="card">
        {% if presences %}
        <p class="section-blurb">{{ presences | selectattr('is_verified') | list | length }} of {{ presences | length }} platform presences are content-validated.</p>
        {% for presence in presences %}
        <details class="drilldown">
            <summary>
                <span class="summary-value">{{ presence.platform_name or 'Unknown platform' }}</span>
                <span class="summary-meta">{{ presence.username or 'no username' }}</span>
                {% if presence.is_verified %}<span class="badge badge-validated">Content-validated</span>
                {% else %}<span class="badge badge-unvalidated">Unvalidated (status only)</span>{% endif %}
                {% if presence.profile_url %}
                <span class="summary-meta">{{ presence.profile_url }}</span>
                {% endif %}
            </summary>
            <div class="drilldown-body">
                <div style="display: flex; gap: 1.5rem; align-items: flex-start;">
                    {% if presence.profile_image_url %}
                    <img class="thumb" src="{{ presence.profile_image_url }}" alt="{{ presence.platform_name }} profile image"
                         onerror="this.style.display='none';">
                    {% endif %}
                    <table class="kv-table">
                        <tbody>
                            <tr><td>Platform</td><td>{{ presence.platform_name or '-' }}</td></tr>
                            <tr><td>Username</td><td>{{ presence.username or '-' }}</td></tr>
                            <tr><td>Display name</td><td>{{ presence.display_name or '-' }}</td></tr>
                            <tr>
                                <td>Profile URL</td>
                                <td>
                                    {% if presence.profile_url %}
                                    <a href="{{ presence.profile_url }}" target="_blank" rel="noopener">{{ presence.profile_url }}</a>
                                    {% else %}-{% endif %}
                                </td>
                            </tr>
                            <tr>
                                <td>Validation</td>
                                <td>{{ 'Content-validated (profile page or API confirmed the account)'
                                       if presence.is_verified else
                                       'Unvalidated - HTTP status only, existence not confirmed' }}</td>
                            </tr>
                            <tr><td>Followers</td><td>{{ presence.follower_count if presence.follower_count is not none else '-' }}</td></tr>
                            <tr><td>Account created</td><td>{{ presence.account_created or '-' }}</td></tr>
                            <tr><td>Last active</td><td>{{ presence.last_active or '-' }}</td></tr>
                            <tr><td>Bio</td><td>{{ presence.bio or '-' }}</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </details>
        {% endfor %}
        {% else %}
        <p class="empty-note">No platform presence recorded for this investigation.</p>
        {% endif %}
    </div>

    <!-- Relationship Graph -->
    <h2>5. Relationship Graph</h2>
    <p class="section-blurb">Visual network diagram showing connections between artifacts and identities, helping identify clusters, central nodes, and relationship patterns for understanding social connections and potential attack vectors.</p>
    <div class="card">
        <div class="graph-container">
            {{ graph_html | safe }}
        </div>
    </div>

    <!-- Artifacts -->
    <h2>6. Discovered Artifacts</h2>
    <p class="section-blurb">Complete inventory of all data points found (emails, usernames, phone numbers, domains, etc.) with source attribution, confidence scores, and discovery depth. Expand an artifact to review its full metadata and the links that connect it to the rest of the investigation.</p>
    <div class="card">
        {% if artifact_views %}
        {% for a in artifact_views %}
        <details class="drilldown">
            <summary>
                <span class="badge badge-{{ a.artifact_type }}">{{ a.artifact_type }}</span>
                <span class="summary-value">{{ a.value }}</span>
                <span class="summary-meta">Source: {{ a.source or '-' }}</span>
                <span class="summary-meta">Confidence: {{ "%.0f%%" | format((a.confidence or 0) * 100) }}</span>
                <span class="summary-meta">Depth: {{ a.depth }}</span>
                <span class="summary-meta">{{ a.connections | length }} link(s)</span>
            </summary>
            <div class="drilldown-body">
                <h5>Artifact Detail</h5>
                <table class="kv-table">
                    <tbody>
                        <tr><td>Artifact ID</td><td>{{ a.artifact_id }}</td></tr>
                        <tr><td>Type</td><td>{{ a.artifact_type }}</td></tr>
                        <tr><td>Value</td><td>{{ a.value }}</td></tr>
                        <tr><td>Source</td><td>{{ a.source or '-' }}</td></tr>
                        <tr><td>Confidence</td><td>{{ "%.0f%%" | format((a.confidence or 0) * 100) }}</td></tr>
                        <tr><td>Discovery depth</td><td>{{ a.depth }}</td></tr>
                        <tr><td>Discovered at</td><td>{{ a.discovered_at[:19] if a.discovered_at else '-' }}</td></tr>
                        <tr><td>Attributed identity</td><td>{{ a.identity_label or 'Not attributed' }}</td></tr>
                    </tbody>
                </table>

                <h5>Metadata</h5>
                {% if a.metadata_items %}
                <table class="kv-table">
                    <tbody>
                        {% for item in a.metadata_items %}
                        <tr><td>{{ item.key }}</td><td>{{ item.value }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="empty-note">No metadata recorded for this artifact.</p>
                {% endif %}

                <h5>Connected Artifacts</h5>
                {% if a.connections %}
                <table>
                    <thead>
                        <tr><th>Direction</th><th>Link Type</th><th>Connected Artifact</th><th>Confidence</th><th>Evidence</th></tr>
                    </thead>
                    <tbody>
                        {% for c in a.connections %}
                        <tr>
                            <td>{{ c.direction }}</td>
                            <td>{{ c.link_type }}</td>
                            <td><span class="badge badge-{{ c.other_type }}">{{ c.other_type }}</span> {{ c.other_value }}</td>
                            <td>{{ "%.0f%%" | format(c.confidence * 100) }}</td>
                            <td>{{ c.evidence or '-' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="empty-note">No links connect this artifact to other findings.</p>
                {% endif %}
            </div>
        </details>
        {% endfor %}
        {% else %}
        <p class="empty-note">No artifacts were discovered in this investigation.</p>
        {% endif %}
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>Ghost Identity Hunter - OSINT Investigation Report | Generated {{ generated_at }}</p>
    </div>
</div>

<script>
    function toggleCollapsible(element) {
        element.classList.toggle('active');
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('.collapsible-header').forEach(function (header) {
            header.addEventListener('click', function () {
                toggleCollapsible(header.parentElement);
            });
        });

        function setAllDetails(open) {
            document.querySelectorAll('details.drilldown').forEach(function (item) {
                item.open = open;
            });
        }

        var expandAll = document.getElementById('expand-all');
        var collapseAll = document.getElementById('collapse-all');
        if (expandAll) { expandAll.addEventListener('click', function () { setAllDetails(true); }); }
        if (collapseAll) { collapseAll.addEventListener('click', function () { setAllDetails(false); }); }
    });
</script>
</body>
</html>
"""

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
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .badge-risk { background: #e74c3c; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Summary</h1>
        <p><strong>Investigation ID:</strong> {{ investigation.investigation_id }}</p>
        <p><strong>Title:</strong> {{ investigation.title or 'Untitled Investigation' }}</p>
        <p><strong>Status:</strong> {{ (investigation.status or 'Unknown') | title }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>

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
                {% endfor %}
            </tbody>
        </table>

        <h2>Recommendations</h2>
        {% for rec in recommendations %}
        <div class="summary-box" style="border-left-color: #e74c3c;">
            <p><strong>{{ rec.priority | upper }}:</strong> {{ rec.action }}</p>
            <p style="font-size: 0.9rem;">{{ rec.details }}</p>
        </div>
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
        th { background: #3e3e42; color: #d4d4d4; }
        .code { background: #1e1e1e; padding: 1rem; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Technical Report</h1>
        <p><strong>Investigation ID:</strong> {{ investigation.investigation_id }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>
        
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
            <p>Integrated but silent in this run: {{ tool_metrics.silent_tools | join(', ') }}.</p>
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
        th, td { padding: 0.75rem; text-align: left; border: 1px solid #000; }
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
            </tbody>
        </table>

        <h2>Key Findings</h2>
        {% for finding in key_findings %}
        <div style="margin-bottom: 1rem;">
            <p><strong>Finding {{ loop.index }}:</strong> {{ finding }}</p>
        </div>
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
                {% endfor %}
            </tbody>
        </table>

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
    """Select the appropriate HTML template based on report type."""
    templates = {
        'standard': HTML_TEMPLATE,
        'html': HTML_TEMPLATE,
        'executive': EXECUTIVE_TEMPLATE,
        'technical': TECHNICAL_TEMPLATE,
        'legal': LEGAL_TEMPLATE,
    }
    return templates.get(template_type, HTML_TEMPLATE)


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
    """Render a metadata value as a compact, human-readable string."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    if value is None:
        return '-'
    return str(value)


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
                {'key': str(key), 'value': _format_metadata_value(value)}
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
) -> str:
    """
    Generate a comprehensive HTML report with optional template type.
    
    Args:
        conn: Database connection
        investigation_id: Investigation ID
        output_path: Optional output file path
        template_type: Type of report template (standard, executive, technical, legal)
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

    # Generate investigation timeline
    timeline = _generate_timeline(artifacts)
    
    # Generate key findings summary
    key_findings = _generate_key_findings(artifacts, links, presences, correlation)
    
    # Generate confidence metrics breakdown
    confidence_metrics = _generate_confidence_metrics(artifacts, links)
    
    # Generate risk assessment matrix
    risk_matrix = _generate_risk_matrix(correlation, risk_levels)

    # Generate interactive graph HTML
    graph_html = _generate_embedded_graph(conn, investigation_id)

    # Generate recommendations
    recommendations = _generate_recommendations(artifacts, links, presences, correlation, risk_levels)
    
    # Log recommendations
    if recommendations:
        logger.info("=" * 60)
        logger.info("INVESTIGATION RECOMMENDATIONS")
        logger.info("=" * 60)
        for rec in recommendations:
            logger.info("[%s Priority - %s]", rec['priority'].upper(), rec['category'])
            logger.info("  Action: %s", rec['action'])
            logger.info("  Details: %s", rec['details'])
            logger.info("-" * 60)
    else:
        logger.info("No recommendations generated for this investigation")

    # Generate priority queue for artifact ranking
    priority_queue = _generate_priority_queue(artifacts, links, correlation)

    # Generate geographic data
    geographic_data = _generate_geographic_data(artifacts, presences)

    # Generate platform heat map data
    platform_heatmap = _generate_platform_heatmap(presences)

    # Generate correlation strength indicators
    correlation_strength = _generate_correlation_strength(links)

    # Generate verification status tracking
    verification_status = _generate_verification_status(artifacts)

    # Generate anomaly detection
    anomaly_detection = _generate_anomaly_detection(artifacts, links)

    # Generate auto-escalation alerts
    auto_escalation = _generate_auto_escalation(artifacts, links, risk_levels, correlation)

    # Generate audit trail
    audit_trail = db.get_audit_trail(conn, investigation_id)

    # Per-tool contribution metrics for the infographic
    tool_metrics = _generate_tool_metrics(artifacts, correlation)

    # Build drill-down views (parsed metadata, connected links, identity attribution)
    artifact_views = _build_artifact_views(artifacts, links, correlation)
    identity_artifacts = _build_identity_artifacts(artifact_views, correlation)

    # Select template based on type
    template_content = _select_template(template_type)

    # Render template
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(template_content)
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
    
    # Extract location data from artifacts
    for artifact in artifacts:
        if artifact.get('artifact_type') == 'location':
            locations.append({
                'type': 'artifact',
                'value': artifact.get('value', ''),
                'source': artifact.get('source', 'unknown'),
                'confidence': artifact.get('confidence', 0)
            })
    
    # Extract location data from platform presences (if available)
    for presence in presences:
        # Check for location in bio or other fields
        bio = (presence.get('bio') or '').lower()
        if any(loc in bio for loc in ['usa', 'us', 'uk', 'india', 'germany', 'france', 'canada', 'australia']):
            locations.append({
                'type': 'platform',
                'value': presence.get('platform_name', ''),
                'source': 'platform_bio',
                'confidence': 0.5
            })
    
    return {
        'has_location_data': len(locations) > 0,
        'location_count': len(locations),
        'locations': locations[:10]  # Limit to top 10
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
        tools.append({
            "tool": entry["tool"],
            "count": count,
            "share": _share(count, attributed),
            "avg_confidence": round(entry["confidence_sum"] / count, 2) if count else 0.0,
            "identities": len(entry["identities"]),
            "kind": "derivation" if entry["tool"] in _DERIVED_SOURCES else "tool",
            "types": [
                {"type": t, "count": c}
                for t, c in sorted(entry["types"].items(), key=lambda kv: (-kv[1], kv[0]))
            ],
        })
    tools.sort(key=lambda t: (-t["count"], t["tool"]))

    types = [
        {
            "type": t,
            "count": c,
            "share": _share(c, attributed),
            "color": _TYPE_COLORS[i % len(_TYPE_COLORS)],
        }
        for i, (t, c) in enumerate(sorted(per_type.items(), key=lambda kv: (-kv[1], kv[0])))
    ]

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
        "top_tool": tools[0]["tool"] if tools else None,
        "integrated_count": len(TOOL_ARTIFACT_TYPES),
        "silent_tools": silent,
    }


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
        "tool_metrics": _generate_tool_metrics(artifacts, correlation),
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

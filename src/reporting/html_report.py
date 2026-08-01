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
        .collapsible {
            background: #1a1a2e;
            border: 1px solid #333;
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .collapsible-header {
            background: #16213e;
            padding: 1rem 1.5rem;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }
        .collapsible-header:hover {
            background: #1a2a4a;
        }
        .collapsible-content {
            padding: 1.5rem;
            display: none;
        }
        .collapsible.active .collapsible-content {
            display: block;
        }
        .collapsible-toggle {
            font-size: 1.2rem;
            transition: transform 0.3s;
        }
        .collapsible.active .collapsible-toggle {
            transform: rotate(180deg);
        }
        .search-box {
            background: #16213e;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 2rem;
        }
        .search-input {
            width: 100%;
            padding: 0.75rem;
            background: #1a1a2e;
            border: 1px solid #333;
            border-radius: 4px;
            color: #e0e0e0;
            font-size: 1rem;
        }
        .search-input:focus {
            outline: none;
            border-color: #4ECDC4;
        }
        .highlight {
            background-color: #FFD700;
            color: #000;
            padding: 2px 4px;
            border-radius: 2px;
        }
        .export-buttons {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
        }
        .export-btn {
            background: #4ECDC4;
            color: #0f0f23;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.3s;
        }
        .export-btn:hover {
            background: #45B7D1;
        }
    </style>
    <script>
        function toggleCollapsible(element) {
            element.classList.toggle('active');
        }
        
        function searchReport() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const content = document.querySelector('.container');
            
            // Remove previous highlights
            const highlights = document.querySelectorAll('.highlight');
            highlights.forEach(h => {
                const parent = h.parentNode;
                parent.replaceChild(document.createTextNode(h.textContent), h);
                parent.normalize();
            });
            
            if (searchTerm.length < 2) return;
            
            // Find and highlight matches
            const walker = document.createTreeWalker(content, NodeFilter.SHOW_TEXT, null, false);
            const textNodes = [];
            let node;
            while (node = walker.nextNode()) {
                if (node.textContent.toLowerCase().includes(searchTerm) && node.parentNode.tagName !== 'SCRIPT') {
                    textNodes.push(node);
                }
            }
            
            textNodes.forEach(node => {
                const text = node.textContent;
                const regex = new RegExp(`(${searchTerm})`, 'gi');
                const highlighted = text.replace(regex, '<span class="highlight">$1</span>');
                
                const span = document.createElement('span');
                span.innerHTML = highlighted;
                node.parentNode.replaceChild(span, node);
            });
            
            // Expand collapsibles that contain matches
            document.querySelectorAll('.collapsible').forEach(collapsible => {
                if (collapsible.textContent.toLowerCase().includes(searchTerm)) {
                    collapsible.classList.add('active');
                }
            });
        }
        
        function exportToCSV() {
            const investigationId = '{{ investigation.investigation_id }}';
            const artifacts = {{ artifacts | tojson }};
            
            if (!artifacts || artifacts.length === 0) {
                alert('No artifacts to export');
                return;
            }
            
            const headers = ['Type', 'Value', 'Source', 'Confidence', 'Depth', 'Discovered At'];
            const rows = artifacts.map(a => [
                a.artifact_type,
                a.value,
                a.source || '',
                (a.confidence || 0).toFixed(2),
                a.depth || 0,
                a.discovered_at || ''
            ]);
            
            const csvContent = [headers, ...rows].map(row => row.join(',')).join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `${investigationId}_artifacts.csv`;
            document?.body?.appendChild(a);
            a.click();
            document?.body?.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        function printReport() {
            window.print();
        }
        
        // Initialize all collapsibles
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.collapsible-header').forEach(header => {
                header.addEventListener('click', function() {
                    toggleCollapsible(this.parentElement);
                });
            });
            
            // Add search functionality
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.addEventListener('input', searchReport);
                searchInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        searchReport();
                    }
                });
            }
        });
    </script>
</head>
<body>
<div class="container">
    <h1>&#128373; Ghost Identity Hunter Report</h1>
    <p class="meta">
        Investigation: <strong>{{ investigation.investigation_id }}</strong> |
        Created: {{ investigation.created_at }} |
        Status: {{ investigation.status }}
    </p>

    <!-- Search Box -->
    <div class="search-box">
        <input type="text" id="searchInput" class="search-input" placeholder="Search report... (type to search, Enter to execute)">
        <div class="export-buttons">
            <button class="export-btn" onclick="exportToCSV()">Export Artifacts (CSV)</button>
            <button class="export-btn" onclick="printReport()">Print / Save as PDF</button>
        </div>
    </div>

    <!-- Executive Summary -->
    <h2>Executive Summary</h2>
    <div class="card">
        <h3>Investigation Timeline</h3>
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
        {% for finding in key_findings %}
        <div style="margin-bottom: 1rem;">
            <strong>{{ finding.category }}</strong> ({{ finding.count }} items)
            <ul>
                {% for item in finding.items %}
                <li>
                    {% if finding.category == 'High-Confidence Artifacts' %}
                    {{ item.value[:50] }}{% if item.value | length > 50 %}...{% endif %} ({{ "%.0f" | format((item.confidence or 0) * 100) }}% confidence)
                    {% elif finding.category == 'Platform Presence' %}
                    {{ item.platform }}
                    {% elif finding.category == 'High-Risk Identity Profiles' %}
                    {{ item.profile_id }} - {{ item.risk_level | upper }} risk ({{ item.artifact_count }} artifacts)
                    {% endif %}
                </li>
                {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>

    <div class="card">
        <h3>Confidence Metrics</h3>
        <p><strong>Overall Confidence:</strong> {{ "%.0f" | format(confidence_metrics.overall * 100) }}%</p>
        
        {% if confidence_metrics.by_type %}
        <h4>By Artifact Type</h4>
        <table>
            <thead>
                <tr><th>Type</th><th>Average Confidence</th></tr>
            </thead>
            <tbody>
                {% for type, conf in confidence_metrics.by_type.items() %}
                <tr>
                    <td>{{ type }}</td>
                    <td>{{ "%.0f" | format(conf * 100) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
        
        {% if confidence_metrics.by_source %}
        <h4>By Data Source</h4>
        <table>
            <thead>
                <tr><th>Source</th><th>Average Confidence</th></tr>
            </thead>
            <tbody>
                {% for source, conf in confidence_metrics.by_source.items() %}
                <tr>
                    <td>{{ source }}</td>
                    <td>{{ "%.0f" | format(conf * 100) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>

    <div class="card">
        <h3>Risk Assessment Matrix</h3>
        <p><strong>Total Identity Profiles:</strong> {{ risk_matrix.total_identities }}</p>
        
        <table>
            <thead>
                <tr><th>Risk Level</th><th>Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>
                {% for level in ['critical', 'high', 'medium', 'low', 'minimal'] %}
                <tr>
                    <td><span class="risk-{{ level }}">{{ level | upper }}</span></td>
                    <td>{{ risk_matrix.counts.get(level, 0) }}</td>
                    <td>{{ risk_matrix.distribution.get(level, 0) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- Recommendations -->
    {% if recommendations %}
    <h2>Investigative Recommendations</h2>
    {% for rec in recommendations %}
    <div class="card" style="border-left: 4px solid {% if rec.priority == 'critical' %}#FF0000{% elif rec.priority == 'high' %}#FF6B6B{% elif rec.priority == 'medium' %}#FFA500{% else %}#4ECDC4{% endif %};">
        <h3>
            <span class="badge badge-risk">{{ rec.priority | upper }}</span>
            {{ rec.category }}
        </h3>
        <p><strong>{{ rec.action }}</strong></p>
        <p style="color: #888; font-size: 0.9rem;">{{ rec.details }}</p>
    </div>
    {% endfor %}
    {% endif %}

    <!-- Priority Queue -->
    {% if priority_queue %}
    <h2>Priority Artifact Queue</h2>
    <div class="card">
        <p>Artifacts ranked by investigation value and priority for follow-up.</p>
        <table>
            <thead>
                <tr><th>Rank</th><th>Priority</th><th>Type</th><th>Value</th><th>Score</th><th>Factors</th></tr>
            </thead>
            <tbody>
                {% for item in priority_queue[:10] %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td><span class="badge badge-risk">{{ item.priority | upper }}</span></td>
                    <td><span class="badge badge-{{ item.artifact.artifact_type }}">{{ item.artifact.artifact_type }}</span></td>
                    <td>{{ item.artifact.value[:40] }}{% if item.artifact.value | length > 40 %}...{% endif %}</td>
                    <td>{{ "%.0f" | format(item.score) }}</td>
                    <td style="font-size: 0.8rem; color: #888;">{{ ', '.join(item.factors) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Geographic Data -->
    {% if geographic_data.has_location_data %}
    <h2>Geographic Analysis</h2>
    <div class="card">
        <p><strong>Locations Identified:</strong> {{ geographic_data.location_count }}</p>
        <table>
            <thead>
                <tr><th>Type</th><th>Location/Platform</th><th>Source</th><th>Confidence</th></tr>
            </thead>
            <tbody>
                {% for loc in geographic_data.locations %}
                <tr>
                    <td>{{ loc.type }}</td>
                    <td>{{ loc.value }}</td>
                    <td>{{ loc.source }}</td>
                    <td>{{ "%.0f" | format(loc.confidence * 100) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Platform Heat Map -->
    {% if platform_heatmap.has_platform_data %}
    <h2>Platform Distribution Heat Map</h2>
    <div class="card">
        <p><strong>Total Platforms:</strong> {{ platform_heatmap.total_platforms }}</p>
        <table>
            <thead>
                <tr><th>Platform</th><th>Presence Count</th><th>Distribution</th><th>Heat Bar</th></tr>
            </thead>
            <tbody>
                {% for platform in platform_heatmap.platforms %}
                <tr>
                    <td>{{ platform.platform }}</td>
                    <td>{{ platform.count }}</td>
                    <td>{{ platform.percentage }}%</td>
                    <td>
                        <div style="background: #333; border-radius: 4px; width: 100px; height: 20px; overflow: hidden;">
                            <div style="background: linear-gradient(90deg, #4ECDC4, #FF6B6B); height: 100%; width: {{ platform.percentage }}%;"></div>
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Correlation Strength -->
    {% if correlation_strength.has_correlation_data %}
    <h2>Correlation Strength Analysis</h2>
    <div class="card">
        <p><strong>Total Connections:</strong> {{ correlation_strength.total_links }} |
           <strong>Average Confidence:</strong> {{ "%.1f" | format(correlation_strength.average_confidence * 100) }}%</p>
        <table>
            <thead>
                <tr><th>Strength Level</th><th>Count</th><th>Distribution</th><th>Visual</th></tr>
            </thead>
            <tbody>
                {% for level in ['very_strong', 'strong', 'moderate', 'weak', 'very_weak'] %}
                <tr>
                    <td><span class="badge badge-risk">{{ level | replace('_', ' ') | title }}</span></td>
                    <td>{{ correlation_strength.strength_distribution[level] }}</td>
                    <td>{{ correlation_strength.strength_percentages[level] }}%</td>
                    <td>
                        <div style="background: #333; border-radius: 4px; width: 100px; height: 20px; overflow: hidden;">
                            <div style="background: {% if level == 'very_strong' %}#FF0000{% elif level == 'strong' %}#FF6B6B{% elif level == 'moderate' %}#FFA500{% elif level == 'weak' %}#4ECDC4{% else %}#888888{% endif %}; height: 100%; width: {{ correlation_strength.strength_percentages[level] }}%;"></div>
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Verification Status -->
    {% if verification_status.has_verification_data %}
    <h2>Verification Status Tracking</h2>
    <div class="card">
        <p><strong>Total Artifacts:</strong> {{ verification_status.total_artifacts }} |
           <strong>Verification Rate:</strong> {{ verification_status.verification_rate }}%</p>
        <table>
            <thead>
                <tr><th>Status</th><th>Count</th><th>Distribution</th><th>Visual</th></tr>
            </thead>
            <tbody>
                {% for status in ['verified', 'likely', 'possible', 'unverified', 'needs_review'] %}
                <tr>
                    <td><span class="badge badge-risk">{{ status | replace('_', ' ') | title }}</span></td>
                    <td>{{ verification_status.status_distribution[status] }}</td>
                    <td>{{ verification_status.status_percentages[status] }}%</td>
                    <td>
                        <div style="background: #333; border-radius: 4px; width: 100px; height: 20px; overflow: hidden;">
                            <div style="background: {% if status == 'verified' %}#4ECDC4{% elif status == 'likely' %}#45B7D1{% elif status == 'possible' %}#FFA500{% elif status == 'needs_review' %}#FF6B6B{% else %}#888888{% endif %}; height: 100%; width: {{ verification_status.status_percentages[status] }}%;"></div>
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Anomaly Detection -->
    {% if anomaly_detection.has_anomalies %}
    <h2>Anomaly Detection</h2>
    <div class="card">
        <p><strong>Anomalies Detected:</strong> {{ anomaly_detection.anomaly_count }}</p>
        <table>
            <thead>
                <tr><th>Type</th><th>Artifact</th><th>Reason</th></tr>
            </thead>
            <tbody>
                {% for anomaly in anomaly_detection.anomalies %}
                <tr>
                    <td><span class="badge badge-risk">{{ anomaly.type | replace('_', ' ') | title }}</span></td>
                    <td>{{ anomaly.artifact.value[:50] }}{% if anomaly.artifact.value | length > 50 %}...{% endif %}</td>
                    <td style="font-size: 0.9rem; color: #888;">{{ anomaly.reason }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Auto-Escalation Alerts -->
    {% if auto_escalation.has_escalations %}
    <h2>Auto-Escalation Alerts</h2>
    {% for escalation in auto_escalation.escalations %}
    <div class="card" style="border-left: 4px solid {% if escalation.severity == 'critical' %}#FF0000{% elif escalation.severity == 'high' %}#FF6B6B{% elif escalation.severity == 'medium' %}#FFA500{% else %}#4ECDC4{% endif %}; border-right: 4px solid {% if escalation.severity == 'critical' %}#FF0000{% elif escalation.severity == 'high' %}#FF6B6B{% elif escalation.severity == 'medium' %}#FFA500{% else %}#4ECDC4{% endif %};">
        <h3>
            <span class="badge badge-risk">{{ escalation.severity | upper }}</span>
            {{ escalation.type | replace('_', ' ') | title }}
        </h3>
        <p><strong>{{ escalation.message }}</strong></p>
        <p style="color: #888; font-size: 0.9rem;">Recommended Action: {{ escalation.action }}</p>
    </div>
    {% endfor %}
    {% endif %}

    <!-- Summary Statistics -->
    <h2>Summary Statistics</h2>
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

    <!-- Interactive Identity Graph -->
    {% if graph_html %}
    <h2>Interactive Identity Graph</h2>
    <div class="card" style="padding: 0; overflow: hidden;">
        <div style="height: 700px; width: 100%;">
            {{ graph_html | safe }}
        </div>
    </div>
    {% endif %}

    <!-- Identity Profiles -->
    <h2>Identity Profiles</h2>
    {% for identity in correlation.identities %}
    <div class="collapsible">
        <div class="collapsible-header">
            <h3>{{ identity.profile_id }} ({{ identity.artifact_count }} artifacts)</h3>
            <span class="collapsible-toggle">▼</span>
        </div>
        <div class="collapsible-content">
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
    </div>
    {% endfor %}

    <!-- Platform Presence Matrix -->
    {% if presences %}
    <div class="collapsible">
        <div class="collapsible-header">
            <h2>Platform Presence Matrix</h2>
            <span class="collapsible-toggle">▼</span>
        </div>
        <div class="collapsible-content">
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
        </div>
    </div>
    {% endif %}

    <!-- All Artifacts -->
    <div class="collapsible">
        <div class="collapsible-header">
            <h2>Artifact Inventory</h2>
            <span class="collapsible-toggle">▼</span>
        </div>
        <div class="collapsible-content">
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
        </div>
    </div>

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
        findings.append({
            'category': 'High-Confidence Artifacts',
            'count': len(high_confidence_artifacts),
            'items': high_confidence_artifacts[:5]
        })
    
    # Platform presence summary
    if presences:
        platforms = list(set(p.get('platform_name') for p in presences))
        findings.append({
            'category': 'Platform Presence',
            'count': len(platforms),
            'items': [{'platform': p} for p in platforms[:5]]
        })
    
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
        findings.append({
            'category': 'High-Risk Identity Profiles',
            'count': len(high_risk_identities),
            'items': high_risk_identities[:3]
        })
    
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
    breach_artifacts = [a for a in artifacts if a.get('source', '').lower() in ['breach', 'hibp', 'pwned']]
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
        bio = presence.get('bio', '').lower()
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

"""
Ghost Identity Hunter - API Integration Module

PURPOSE:
--------
Provide REST API endpoints for automated workflow integration,
allowing external systems to trigger investigations, retrieve results,
and manage the OSINT platform programmatically.

FUNCTIONALITY:
--------------
- REST API endpoints for investigation management
- Webhook support for event notifications
- API key authentication
- Batch investigation processing
- Result retrieval in multiple formats

USAGE EXAMPLES:
--------------
# Start investigation via API
POST /api/v1/investigations
{
    "seeds": [{"type": "email", "value": "user@example.com"}],
    "config": {"max_depth": 2}
}

# Get investigation results
GET /api/v1/investigations/{id}

DEPENDENCIES:
-------------
- flask: Web framework for REST API
- flask_cors: CORS support
- typing: Type hints
- logging: Logging

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
1.0 - Initial implementation
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from src.orchestrator import run_investigation, InvestigationConfig
from src.storage.database import get_connection, get_investigation, list_investigations
from src.reporting.html_report import generate_html_report, generate_json_report

logger = logging.getLogger(__name__)


class WorkflowAPI:
    """REST API for automated workflow integration."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
        """Initialize the API server."""
        self.host = host
        self.port = port
        self.debug = debug
        self.app = Flask(__name__)
        CORS(self.app)
        self._setup_routes()
        self.api_keys = set()  # In production, load from secure storage
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.app.route('/api/v1/health', methods=['GET'])
        def health_check():
            """Health check endpoint."""
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0"
            })
        
        @self.app.route('/api/v1/investigations', methods=['POST'])
        def create_investigation():
            """Create a new investigation."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            data = request.get_json()
            
            if not data or 'seeds' not in data:
                return jsonify({"error": "Missing seeds"}), 400
            
            seeds = data['seeds']
            config_data = data.get('config', {})
            title = data.get('title')
            
            # Build investigation config
            config = InvestigationConfig(
                max_depth=config_data.get('max_depth', 2),
                check_breaches=config_data.get('check_breaches', True),
                search_usernames=config_data.get('search_usernames', True),
                check_images=config_data.get('check_images', True),
                check_external_tools=config_data.get(
                    'check_external_tools',
                    config_data.get('use_external_tools', True),
                ),
                use_google_dorks=config_data.get('use_google_dorks', False),
                search_engine=config_data.get('search_engine', 'auto')
            )
            
            try:
                conn = get_connection()
                result = run_investigation(conn, seeds, config, title)
                conn.close()
                
                return jsonify({
                    "investigation_id": result.investigation_id,
                    "total_artifacts": result.total_artifacts,
                    "total_links": result.total_links,
                    "total_platforms": result.total_platforms,
                    "risk_indicators": result.risk_indicators
                }), 201
                
            except Exception as e:
                logger.error(f"Error creating investigation: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/investigations', methods=['GET'])
        def list_investigations_api():
            """List all investigations."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            try:
                conn = get_connection()
                investigations = list_investigations(conn)
                conn.close()
                
                return jsonify({
                    "investigations": investigations,
                    "count": len(investigations)
                })
                
            except Exception as e:
                logger.error(f"Error listing investigations: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/investigations/<investigation_id>', methods=['GET'])
        def get_investigation(investigation_id: str):
            """Get investigation details."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            try:
                conn = get_connection()
                inv = get_investigation(conn, investigation_id)
                conn.close()
                
                if not inv:
                    return jsonify({"error": "Investigation not found"}), 404
                
                return jsonify(inv)
                
            except Exception as e:
                logger.error(f"Error getting investigation: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/investigations/<investigation_id>/report', methods=['GET'])
        def get_report(investigation_id: str):
            """Generate investigation report.

            Query params:
              format=html|json|pdf|csv (default json)
              template=standard|executive|technical|legal
              sections=comma list
              redact=true|false
              compare=<investigation_id>
            """
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401

            format_type = (request.args.get('format') or 'json').lower()
            template_type = request.args.get('template') or 'standard'
            sections = request.args.get('sections')
            redact = (request.args.get('redact') or '').lower() in ('1', 'true', 'yes')
            compare_id = request.args.get('compare')

            try:
                conn = get_connection()
                try:
                    inv = get_investigation(conn, investigation_id)
                    if not inv:
                        return jsonify({"error": "Investigation not found"}), 404

                    if format_type == 'json':
                        path = generate_json_report(
                            conn, investigation_id, redact=redact, compare_id=compare_id
                        )
                        with open(path, encoding='utf-8') as fh:
                            return jsonify(json.loads(fh.read()))

                    if format_type in ('html', 'pdf'):
                        path = generate_html_report(
                            conn,
                            investigation_id,
                            template_type=template_type,
                            sections=sections,
                            redact=redact,
                            compare_id=compare_id,
                        )
                        if format_type == 'html':
                            html = Path(path).read_text(encoding='utf-8')
                            return html, 200, {'Content-Type': 'text/html; charset=utf-8'}
                        from src.reporting.exports import generate_pdf_from_html
                        pdf_path = generate_pdf_from_html(path)
                        return send_file(pdf_path, mimetype='application/pdf', as_attachment=True)

                    if format_type == 'csv':
                        from src.reporting.exports import export_artifacts_csv
                        from src.storage import database as dbmod
                        arts = dbmod.get_artifacts(conn, investigation_id)
                        csv_path = f"/tmp/{investigation_id}_artifacts.csv"
                        export_artifacts_csv(arts, csv_path)
                        return send_file(csv_path, mimetype='text/csv', as_attachment=True)

                    return jsonify({"error": f"Unsupported format: {format_type}"}), 400
                finally:
                    conn.close()

            except Exception as e:
                logger.error(f"Error generating report: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/investigations/<investigation_id>/artifacts', methods=['GET'])
        def get_artifacts(investigation_id: str):
            """Get artifacts for an investigation."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401

            try:
                from src.storage.database import get_artifacts as db_get_artifacts
                conn = get_connection()
                try:
                    artifacts = db_get_artifacts(conn, investigation_id)
                    return jsonify({
                        "investigation_id": investigation_id,
                        "artifacts": artifacts,
                        "count": len(artifacts),
                    })
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Error getting artifacts: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/investigations/<investigation_id>/links', methods=['GET'])
        def get_links(investigation_id: str):
            """Get artifact links for an investigation."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401

            try:
                from src.storage.database import get_links as db_get_links
                conn = get_connection()
                try:
                    links = db_get_links(conn, investigation_id)
                    return jsonify({
                        "investigation_id": investigation_id,
                        "links": links,
                        "count": len(links),
                    })
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Error getting links: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/investigations/<investigation_id>/risk', methods=['GET'])
        def get_risk_indicators(investigation_id: str):
            """Get risk indicators derived from artifact metadata."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401

            try:
                from src.storage.database import get_artifacts as db_get_artifacts
                conn = get_connection()
                try:
                    artifacts = db_get_artifacts(conn, investigation_id)
                    risks = []
                    for art in artifacts:
                        meta_raw = art.get("metadata")
                        if not meta_raw:
                            continue
                        try:
                            meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
                        except (ValueError, TypeError):
                            continue
                        if isinstance(meta, dict):
                            for indicator in meta.get("risk_indicators") or []:
                                risks.append({
                                    "risk_indicator": indicator,
                                    "severity": "unknown",
                                    "source": art.get("source"),
                                    "artifact_id": art.get("artifact_id"),
                                    "metadata": meta,
                                })
                    return jsonify({
                        "investigation_id": investigation_id,
                        "risk_indicators": risks,
                        "count": len(risks),
                    })
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Error getting risk indicators: {e}")
                return jsonify({"error": str(e)}), 500
    
    def _authenticate(self) -> bool:
        """
        Authenticate API request using API key.
        
        In production, implement proper authentication with JWT or OAuth.
        """
        api_key = request.headers.get('X-API-Key')
        
        # For now, accept any non-empty key (implement proper auth in production)
        if not api_key:
            return False
        
        # Check if key is in allowed set
        if self.api_keys and api_key not in self.api_keys:
            return False
        
        return True
    
    def add_api_key(self, api_key: str):
        """Add an API key to the allowed set."""
        self.api_keys.add(api_key)
    
    def run(self):
        """Run the API server."""
        logger.info(f"Starting API server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=self.debug)


def create_api_server(host: str = "0.0.0.0", port: int = 5000, debug: bool = False) -> WorkflowAPI:
    """
    Create and return an API server instance.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
        
    Returns:
        WorkflowAPI instance
    """
    return WorkflowAPI(host=host, port=port, debug=debug)

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

import logging
from datetime import datetime
from typing import Dict, List, Optional

from flask import Flask, jsonify, request
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
                use_external_tools=config_data.get('use_external_tools', True),
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
            """Generate investigation report."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            format_type = request.args.get('format', 'json')
            
            try:
                conn = get_connection()
                inv = get_investigation(conn, investigation_id)
                conn.close()
                
                if not inv:
                    return jsonify({"error": "Investigation not found"}), 404
                
                if format_type == 'json':
                    report = generate_json_report(conn, investigation_id)
                    return jsonify(report)
                else:
                    html_report = generate_html_report(conn, investigation_id)
                    return html_report, 200, {'Content-Type': 'text/html'}
                    
            except Exception as e:
                logger.error(f"Error generating report: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/investigations/<investigation_id>/artifacts', methods=['GET'])
        def get_artifacts(investigation_id: str):
            """Get artifacts for an investigation."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            try:
                conn = get_connection()
                cursor = conn.execute("""
                    SELECT artifact_id, artifact_type, value, source, depth, metadata
                    FROM artifacts
                    WHERE investigation_id = ?
                    ORDER BY depth, artifact_id
                """, (investigation_id,))
                
                artifacts = []
                for row in cursor.fetchall():
                    artifacts.append({
                        "artifact_id": row[0],
                        "type": row[1],
                        "value": row[2],
                        "source": row[3],
                        "depth": row[4],
                        "metadata": row[5]
                    })
                
                conn.close()
                
                return jsonify({
                    "investigation_id": investigation_id,
                    "artifacts": artifacts,
                    "count": len(artifacts)
                })
                
            except Exception as e:
                logger.error(f"Error getting artifacts: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/investigations/<investigation_id>/links', methods=['GET'])
        def get_links(investigation_id: str):
            """Get artifact links for an investigation."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            try:
                conn = get_connection()
                cursor = conn.execute("""
                    SELECT source_artifact_id, target_artifact_id, link_type, confidence, metadata
                    FROM artifact_links
                    WHERE investigation_id = ?
                """, (investigation_id,))
                
                links = []
                for row in cursor.fetchall():
                    links.append({
                        "source_artifact_id": row[0],
                        "target_artifact_id": row[1],
                        "link_type": row[2],
                        "confidence": row[3],
                        "metadata": row[4]
                    })
                
                conn.close()
                
                return jsonify({
                    "investigation_id": investigation_id,
                    "links": links,
                    "count": len(links)
                })
                
            except Exception as e:
                logger.error(f"Error getting links: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/investigations/<investigation_id>/risk', methods=['GET'])
        def get_risk_indicators(investigation_id: str):
            """Get risk indicators for an investigation."""
            if not self._authenticate():
                return jsonify({"error": "Unauthorized"}), 401
            
            try:
                conn = get_connection()
                cursor = conn.execute("""
                    SELECT risk_indicator, severity, source, metadata
                    FROM risk_indicators
                    WHERE investigation_id = ?
                    ORDER BY severity DESC
                """, (investigation_id,))
                
                risks = []
                for row in cursor.fetchall():
                    risks.append({
                        "risk_indicator": row[0],
                        "severity": row[1],
                        "source": row[2],
                        "metadata": row[3]
                    })
                
                conn.close()
                
                return jsonify({
                    "investigation_id": investigation_id,
                    "risk_indicators": risks,
                    "count": len(risks)
                })
                
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

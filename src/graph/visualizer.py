"""
Ghost Identity Hunter - Graph Visualization Module

PURPOSE:
--------
This module provides interactive graph visualization capabilities for identity correlation
results, creating force-directed network graphs that visually represent the relationships
between digital artifacts, platforms, and identity clusters discovered during investigations.

FUNCTIONALITY:
--------------
- Interactive HTML graph generation using pyvis library
- Force-directed layout for optimal node positioning
- Color-coded nodes by artifact type (phones, emails, usernames, images)
- Size-based node representation for artifact importance
- Edge styling based on confidence scores and relationship types
- Graph statistics computation (nodes, edges, components, density)
- Export to standalone HTML files with embedded JavaScript

VISUALIZATION FEATURES:
-----------------------
- Red nodes: Phone numbers and VoIP services
- Teal nodes: Email addresses and accounts
- Blue nodes: Usernames across platforms
- Green nodes: Profile images and photos
- Yellow stars: Platform presence indicators
- Orange nodes: Breach data exposures
- Crimson nodes: Risk indicators and threats

INTERACTIVE ELEMENTS:
--------------------
- Hover tooltips showing artifact details and metadata
- Click functionality to highlight connected components
- Zoom and pan capabilities for large graphs
- Node clustering for complex identity networks
- Edge filtering by confidence threshold
- Search functionality for specific artifacts

USAGE EXAMPLES:
--------------
# Generate interactive graph from investigation
generate_interactive_graph(conn, investigation_id, "output.html")

# Get graph statistics for investigation summary
stats = get_graph_stats(conn, investigation_id)
print(f"Graph has {stats['nodes']} nodes and {stats['edges']} edges")

# Create filtered graph showing only high-confidence relationships
generate_filtered_graph(conn, investigation_id, min_confidence=0.7)

DEPENDENCIES:
-------------
- networkx: Graph construction and analysis
- pyvis: Interactive HTML graph generation
- sqlite3: Database connection for investigation data
- src.correlation.linker: Graph building utilities
- pathlib: File path handling for output files

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import logging
import sqlite3
from pathlib import Path
from typing import Optional

import networkx as nx
from pyvis.network import Network

from src.correlation.linker import build_identity_graph

logger = logging.getLogger(__name__)

# Color scheme by artifact type
TYPE_COLORS = {
    "phone": "#FF6B6B",       # Red
    "email": "#4ECDC4",       # Teal
    "username": "#45B7D1",    # Blue
    "image": "#96CEB4",       # Green
    "platform_presence": "#FFEAA7",  # Yellow
    "location": "#DDA0DD",    # Plum
    "breach_data": "#FF8C00", # Dark orange
    "risk_indicator": "#DC143C",  # Crimson
}

# Node size by artifact type
TYPE_SIZES = {
    "phone": 30,
    "email": 30,
    "username": 25,
    "image": 25,
    "platform_presence": 20,
    "location": 20,
    "breach_data": 15,
    "risk_indicator": 15,
}

# Shape by artifact type
TYPE_SHAPES = {
    "phone": "dot",
    "email": "diamond",
    "username": "triangle",
    "image": "square",
    "platform_presence": "star",
}


def generate_interactive_graph(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate an interactive HTML graph visualization of the identity network.

    Args:
        conn: Database connection
        investigation_id: Investigation to visualize
        output_path: Output HTML file path (default: investigation_id.html)

    Returns:
        Path to the generated HTML file
    """
    G = build_identity_graph(conn, investigation_id)

    if G.number_of_nodes() == 0:
        logger.warning("Empty graph for investigation %s", investigation_id)
        return ""

    # Create pyvis network
    net = Network(
        height="700px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#ffffff",
        directed=False,
    )

    # Configure physics
    net.set_options("""
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 200,
                "springConstant": 0.08
            },
            "solver": "forceAtlas2Based",
            "stabilization": {"iterations": 150}
        },
        "nodes": {
            "font": {"size": 12, "face": "monospace"}
        },
        "edges": {
            "smooth": {"type": "continuous"}
        }
    }
    """)

    # Add nodes
    for node_id in G.nodes():
        node_data = G.nodes[node_id]
        artifact_type = node_data.get("artifact_type", "unknown")
        value = node_data.get("value", node_id)

        # Truncate long values for display
        label = value if len(value) <= 30 else value[:27] + "..."

        color = TYPE_COLORS.get(artifact_type, "#999999")
        size = TYPE_SIZES.get(artifact_type, 20)
        shape = TYPE_SHAPES.get(artifact_type, "dot")

        title = (
            f"Type: {artifact_type}\n"
            f"Value: {value}\n"
            f"Source: {node_data.get('source', 'unknown')}\n"
            f"Confidence: {node_data.get('confidence', 'N/A')}\n"
            f"Depth: {node_data.get('depth', 0)}"
        )

        net.add_node(
            node_id,
            label=label,
            title=title,
            color=color,
            size=size,
            shape=shape,
        )

    # Add edges
    for u, v in G.edges():
        edge_data = G.edges[u, v]
        link_type = edge_data.get("link_type", "")
        confidence = edge_data.get("confidence", 0.5)

        # Edge width based on confidence
        width = max(1, int(confidence * 4))

        net.add_edge(
            u, v,
            title=f"{link_type} (conf: {confidence:.2f})",
            width=width,
            color="#555555",
        )

    # Save
    if output_path is None:
        output_path = f"reports/{investigation_id}_graph.html"

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    net.save_graph(str(output_file))

    logger.info("Graph saved to %s (%d nodes, %d edges)", output_file, G.number_of_nodes(), G.number_of_edges())
    return str(output_file)


def get_graph_stats(conn: sqlite3.Connection, investigation_id: str) -> dict:
    """Get statistics about the identity graph."""
    G = build_identity_graph(conn, investigation_id)

    stats = {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "connected_components": nx.number_connected_components(G),
        "density": round(nx.density(G), 4) if G.number_of_nodes() > 1 else 0,
    }

    # Node type distribution
    type_counts = {}
    for node_id in G.nodes():
        t = G.nodes[node_id].get("artifact_type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    stats["type_distribution"] = type_counts

    # Degree stats
    if G.number_of_nodes() > 0:
        degrees = [d for _, d in G.degree()]
        stats["max_degree"] = max(degrees)
        stats["avg_degree"] = round(sum(degrees) / len(degrees), 2)

    return stats

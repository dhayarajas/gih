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

import json
import logging
import math
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

# Available node layouts
LAYOUTS = ("organic", "hierarchical", "circular")
DEFAULT_LAYOUT = "organic"

# Collapse a node's same-type leaf neighbours into one node at this count
DEFAULT_COLLECTION_THRESHOLD = 8

# Shape by artifact type
TYPE_SHAPES = {
    "phone": "dot",
    "email": "diamond",
    "username": "triangle",
    "image": "square",
    "platform_presence": "star",
}


def graph_config() -> dict:
    """Read graph.* from YAML with safe defaults."""
    try:
        from src.config.loader import get_config
        cfg = get_config().get("graph", {}) or {}
    except Exception:
        cfg = {}
    layout = (cfg.get("layout") or DEFAULT_LAYOUT).strip().lower()
    try:
        threshold = int(cfg.get("collection_threshold", DEFAULT_COLLECTION_THRESHOLD))
    except (TypeError, ValueError):
        threshold = DEFAULT_COLLECTION_THRESHOLD
    return {
        "layout": layout if layout in LAYOUTS else DEFAULT_LAYOUT,
        "collection_threshold": max(0, threshold),
    }


def build_collections(G, threshold: int) -> dict:
    """Group each node's same-type leaf neighbours into one collection node.

    A subdomain enumeration or a username sweep attaches dozens of leaves to a
    single parent, which turns the graph into an unreadable hairball while
    saying nothing a count would not. Only leaves qualify: a node with another
    relation carries structure that collapsing it would hide.

    Returns ``{collection_id: {"parent", "artifact_type", "members"}}``.
    """
    if threshold <= 0:
        return {}

    collections = {}
    for parent in G.nodes():
        if G.degree(parent) < 2:
            # A leaf cannot anchor a summary of its own neighbour: in a bare
            # pair each node is the other's leaf, and collapsing both hides
            # the pair completely.
            continue
        leaves = {}
        for neighbour in G.neighbors(parent):
            if G.degree(neighbour) != 1:
                continue
            atype = G.nodes[neighbour].get("artifact_type", "unknown")
            leaves.setdefault(atype, []).append(neighbour)
        for atype, members in leaves.items():
            if len(members) >= threshold:
                collections[f"collection::{parent}::{atype}"] = {
                    "parent": parent,
                    "artifact_type": atype,
                    "members": sorted(members),
                }
    return collections


def _circular_positions(G, collections: dict, collapsed: set) -> dict:
    """Place what is actually on screen around the ring.

    Positioning the underlying graph would leave a gap at every collapsed
    member's slot and no coordinate at all for the collection nodes, which the
    circular layout cannot relax into place because physics is off. The ring is
    therefore laid out over the visible nodes, and each collapsed member is
    parked just outside its collection so it appears there when expanded.
    """
    ring_graph = nx.Graph()
    ring_graph.add_nodes_from([n for n in G.nodes() if n not in collapsed])
    ring_graph.add_nodes_from(sorted(collections))
    positions = {k: (float(v[0]), float(v[1]))
                 for k, v in nx.circular_layout(ring_graph, scale=600).items()}

    for collection_id, data in collections.items():
        origin_x, origin_y = positions.get(collection_id, (0.0, 0.0))
        members = data["members"]
        for index, member in enumerate(members):
            angle = 2 * math.pi * index / max(len(members), 1)
            positions[member] = (origin_x + 90 * math.cos(angle),
                                 origin_y + 90 * math.sin(angle))
    return positions


def _position_of(node_id: str, positions: dict) -> dict:
    """vis.js coordinate kwargs for a node, or none when the layout is free."""
    if node_id not in positions:
        return {}
    x, y = positions[node_id]
    return {"x": x, "y": y}


def _layout_options(layout: str) -> str:
    """Return the vis.js options block for a layout name."""
    common_nodes = '"nodes": {"font": {"size": 12, "face": "monospace", "color": "#ffffff"}}'
    common_edges = ('"edges": {"smooth": {"type": "continuous"}, '
                    '"font": {"color": "#e2e8f0", "strokeWidth": 0}}')

    if layout == "hierarchical":
        return f"""
    {{
        "layout": {{
            "hierarchical": {{
                "enabled": true,
                "direction": "UD",
                "sortMethod": "directed",
                "levelSeparation": 160,
                "nodeSpacing": 140
            }}
        }},
        "physics": {{"enabled": false}},
        {common_nodes},
        {common_edges}
    }}
    """
    if layout == "circular":
        # Positions are assigned per node, so physics would only fight them.
        return f"""
    {{
        "physics": {{"enabled": false}},
        {common_nodes},
        {common_edges}
    }}
    """
    return f"""
    {{
        "physics": {{
            "forceAtlas2Based": {{
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 200,
                "springConstant": 0.08
            }},
            "solver": "forceAtlas2Based",
            "stabilization": {{"iterations": 150}}
        }},
        {common_nodes},
        {common_edges}
    }}
    """


def _interaction_script(collections: dict) -> str:
    """JS that expands collections and links nodes to their report section.

    The graph is embedded in the report through a ``file://`` iframe, where
    reaching into the parent document directly is blocked, so navigation is
    requested by postMessage and the report decides what to reveal.
    """
    payload = json.dumps(
        {cid: data["members"] for cid, data in collections.items()}
    )
    return f"""
<script type="text/javascript">
  var gihCollections = {payload};

  function gihExpand(collectionId) {{
      var members = gihCollections[collectionId];
      if (!members) {{ return false; }}
      nodes.update(members.map(function (id) {{ return {{id: id, hidden: false}}; }}));
      edges.update(edges.get().filter(function (e) {{
          return members.indexOf(e.from) !== -1 || members.indexOf(e.to) !== -1;
      }}).map(function (e) {{ return {{id: e.id, hidden: false}}; }}));
      nodes.update([{{id: collectionId, hidden: true}}]);
      return true;
  }}

  network.on("click", function (params) {{
      if (!params.nodes.length) {{ return; }}
      var id = params.nodes[0];
      if (gihExpand(id)) {{ return; }}
      var message = {{source: "gih-graph", artifactId: id}};
      if (window.parent && window.parent !== window) {{
          // Over http(s) the report and the graph share an origin, so the
          // message is addressed to it; a file:// page has an opaque origin
          // that only the wildcard can name.
          var target = window.location.protocol === "file:" ? "*" : window.location.origin;
          window.parent.postMessage(message, target);
      }} else {{
          window.location.hash = "artifact-" + id;
      }}
  }});
</script>
</body>"""


def generate_interactive_graph(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
    *,
    layout: Optional[str] = None,
    collection_threshold: Optional[int] = None,
) -> str:
    """
    Generate an interactive HTML graph visualization of the identity network.

    Args:
        conn: Database connection
        investigation_id: Investigation to visualize
        output_path: Output HTML file path (default: investigation_id.html)
        layout: One of ``organic``, ``hierarchical`` or ``circular``
        collection_threshold: Collapse a node's same-type leaf neighbours into
            one collection node once there are at least this many; 0 disables

    Returns:
        Path to the generated HTML file
    """
    G = build_identity_graph(conn, investigation_id)

    if G.number_of_nodes() == 0:
        logger.warning("Empty graph for investigation %s", investigation_id)
        return ""

    defaults = graph_config()
    layout = (layout or defaults["layout"]).strip().lower()
    if layout not in LAYOUTS:
        logger.warning("Unknown graph layout %r, falling back to %s", layout, DEFAULT_LAYOUT)
        layout = DEFAULT_LAYOUT
    if collection_threshold is None:
        collection_threshold = defaults["collection_threshold"]

    collections = build_collections(G, collection_threshold)
    collapsed = {member: cid for cid, data in collections.items() for member in data["members"]}

    # Create pyvis network
    net = Network(
        height="700px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#ffffff",
        directed=False,
    )
    net.set_options(_layout_options(layout))

    positions = _circular_positions(G, collections, collapsed) if layout == "circular" else {}

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
            f"Depth: {node_data.get('depth', 0)}\n"
            f"Click to open this artifact in the report"
        )

        extra = _position_of(node_id, positions)

        net.add_node(
            node_id,
            label=label,
            title=title,
            color=color,
            size=size,
            shape=shape,
            hidden=node_id in collapsed,
            **extra,
        )

    for collection_id, data in collections.items():
        members = data["members"]
        net.add_node(
            collection_id,
            label=f"{data['artifact_type']} \u00d7 {len(members)}",
            title=(
                f"{len(members)} {data['artifact_type']} artifacts\n"
                "Click to expand"
            ),
            color=TYPE_COLORS.get(data["artifact_type"], "#999999"),
            size=TYPE_SIZES.get(data["artifact_type"], 20) + 12,
            shape="database",
            borderWidth=3,
            **_position_of(collection_id, positions),
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
            hidden=u in collapsed or v in collapsed,
        )

    for collection_id, data in collections.items():
        net.add_edge(
            data["parent"], collection_id,
            title=f"{len(data['members'])} collapsed {data['artifact_type']} artifacts",
            width=3,
            color="#777777",
        )

    # Save
    if output_path is None:
        output_path = f"reports/{investigation_id}_graph.html"

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    net.save_graph(str(output_file))

    html = output_file.read_text(encoding="utf-8")
    output_file.write_text(
        html.replace("</body>", _interaction_script(collections), 1), encoding="utf-8"
    )

    logger.info(
        "Graph saved to %s (%d nodes, %d edges, %d collection(s), layout=%s)",
        output_file, G.number_of_nodes(), G.number_of_edges(), len(collections), layout,
    )
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

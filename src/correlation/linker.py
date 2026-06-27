"""
Ghost Identity Hunter - Identity Correlation Linker

PURPOSE:
--------
This module provides advanced identity correlation capabilities that link fragmented digital
artifacts into unified attribution profiles using NetworkX graph analysis, confidence scoring,
and risk assessment to identify likely identity clusters across platforms and services.

FUNCTIONALITY:
--------------
- Graph construction from database artifacts and relationship links
- Connected component analysis for identity cluster identification
- Confidence scoring based on cross-platform evidence strength
- Risk indicator aggregation across identity clusters
- Platform presence integration for comprehensive profiles
- Graph metrics computation (nodes, edges, components, density)

ALGORITHM:
---------
1. Build directed graph from database artifacts (nodes) and links (edges)
2. Identify weakly connected components as potential identity clusters
3. Compute confidence scores based on cross-type link density and evidence strength
4. Aggregate risk indicators from cluster member artifacts
5. Generate identity profiles with supporting platform presence data
6. Calculate graph metrics for investigation summarization

CORRELATION LOGIC:
-----------------
- Exact matches (same value across platforms) = 1.0 confidence
- Registration links (email to phone) = 0.9 confidence
- Breach correlations = 0.8 confidence
- Username patterns = 0.6 confidence
- Temporal co-occurrence = 0.4 confidence
- Cross-type links boost overall persona confidence
- Platform presence increases attribution confidence

DATABASE INTEGRATION:
--------------------
- Reads artifacts and links from SQLite investigation database
- Integrates platform presence records for comprehensive profiles
- Stores correlation results as investigation metadata
- Supports correlation analysis on completed investigations

USAGE EXAMPLES:
--------------
# Correlate identities from investigation database
result = correlate_identities(conn, investigation_id)

# Get number of identity profiles found
print(f"Found {len(result.identities)} identity profiles")

# Extract high-confidence profiles
for profile in result.identities:
    if profile.confidence > 0.8:
        print(f"High-confidence profile: {profile.profile_id}")

DEPENDENCIES:
-------------
- networkx: Graph construction and analysis
- src.storage.database: Database operations
- dataclasses: Structured result objects
- json: Serialization for database storage
- logging: Debug and error reporting

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
from dataclasses import dataclass, field

import networkx as nx

from src.storage import database as db

logger = logging.getLogger(__name__)


@dataclass
class IdentityProfile:
    """A correlated identity profile linking multiple artifacts."""

    profile_id: str
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    platforms: list[dict] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
    confidence: float = 0.0
    artifact_count: int = 0

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "phones": self.phones,
            "emails": self.emails,
            "usernames": self.usernames,
            "images": self.images,
            "platforms": self.platforms,
            "risk_indicators": self.risk_indicators,
            "confidence": self.confidence,
            "artifact_count": self.artifact_count,
        }


@dataclass
class CorrelationResult:
    """Results from identity correlation analysis."""

    investigation_id: str
    identities: list[IdentityProfile] = field(default_factory=list)
    graph_nodes: int = 0
    graph_edges: int = 0
    connected_components: int = 0

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "identities": [i.to_dict() for i in self.identities],
            "graph_nodes": self.graph_nodes,
            "graph_edges": self.graph_edges,
            "connected_components": self.connected_components,
        }


def build_identity_graph(conn: sqlite3.Connection, investigation_id: str) -> nx.Graph:
    """
    Build a NetworkX graph from investigation artifacts and links.

    Nodes = artifacts (phone, email, username, image, etc.)
    Edges = links between artifacts (discovered_from, found_in_breach, etc.)
    """
    G = nx.Graph()

    # Add artifact nodes
    artifacts = db.get_artifacts(conn, investigation_id)
    for artifact in artifacts:
        # Skip risk_indicator and meta artifacts
        if artifact["artifact_type"] in ("risk_indicator", "carrier_info", "breach_data"):
            continue
        G.add_node(
            artifact["artifact_id"],
            artifact_type=artifact["artifact_type"],
            value=artifact["value"],
            source=artifact["source"],
            confidence=artifact["confidence"],
            depth=artifact["depth"],
        )

    # Add edges from links
    links = db.get_links(conn, investigation_id)
    for link in links:
        if G.has_node(link["source_artifact"]) and G.has_node(link["target_artifact"]):
            G.add_edge(
                link["source_artifact"],
                link["target_artifact"],
                link_type=link["link_type"],
                confidence=link["confidence"],
            )

    return G


def correlate_identities(conn: sqlite3.Connection, investigation_id: str) -> CorrelationResult:
    """
    Correlate artifacts into identity profiles using connected component analysis.

    Algorithm:
    1. Build graph from artifacts and links
    2. Find connected components (each component = likely same person)
    3. For each component, extract identity profile with typed artifacts
    4. Compute confidence score based on cross-type link density
    """
    G = build_identity_graph(conn, investigation_id)

    result = CorrelationResult(
        investigation_id=investigation_id,
        graph_nodes=G.number_of_nodes(),
        graph_edges=G.number_of_edges(),
    )

    # Find connected components
    components = list(nx.connected_components(G))
    result.connected_components = len(components)

    # Build identity profile for each component
    platform_presences = db.get_platform_presences(conn, investigation_id)
    presence_by_artifact = {}
    for p in platform_presences:
        aid = p.get("artifact_id")
        if aid:
            presence_by_artifact.setdefault(aid, []).append(p)

    for i, component in enumerate(components):
        profile = IdentityProfile(profile_id=f"IDENTITY-{i + 1:03d}")

        for node_id in component:
            node_data = G.nodes[node_id]
            artifact_type = node_data.get("artifact_type", "")
            value = node_data.get("value", "")

            if artifact_type == "phone":
                profile.phones.append(value)
            elif artifact_type == "email":
                profile.emails.append(value)
            elif artifact_type == "username":
                profile.usernames.append(value)
            elif artifact_type == "image":
                profile.images.append(value)

            # Collect platform presences for this artifact
            if node_id in presence_by_artifact:
                for presence in presence_by_artifact[node_id]:
                    profile.platforms.append({
                        "platform": presence["platform_name"],
                        "profile_url": presence["profile_url"],
                        "username": presence["username"],
                        "display_name": presence["display_name"],
                    })

        profile.artifact_count = len(component)

        # Compute confidence based on cross-type linking
        profile.confidence = _compute_confidence(G, component)

        # Collect risk indicators from artifact metadata
        profile.risk_indicators = _collect_risk_indicators(conn, component)

        result.identities.append(profile)

    # Sort by artifact count (largest identity first)
    result.identities.sort(key=lambda x: x.artifact_count, reverse=True)

    logger.info(
        "Correlation complete: %d nodes, %d edges, %d identities",
        result.graph_nodes, result.graph_edges, len(result.identities)
    )
    return result


def _compute_confidence(G: nx.Graph, component: set) -> float:
    """
    Compute confidence score for an identity profile.

    Higher confidence when:
    - More diverse artifact types are linked together
    - More cross-type edges exist
    - Higher average edge confidence
    """
    if len(component) <= 1:
        return 0.3

    subgraph = G.subgraph(component)

    # Count unique artifact types
    types = set()
    for node in component:
        types.add(G.nodes[node].get("artifact_type", "unknown"))

    type_diversity = min(len(types) / 4.0, 1.0)  # Max 4 types: phone, email, username, image

    # Count cross-type edges
    cross_edges = 0
    total_edges = subgraph.number_of_edges()
    for u, v in subgraph.edges():
        if G.nodes[u].get("artifact_type") != G.nodes[v].get("artifact_type"):
            cross_edges += 1

    cross_ratio = cross_edges / max(total_edges, 1)

    # Average edge confidence
    edge_confidences = [
        subgraph.edges[u, v].get("confidence", 0.5)
        for u, v in subgraph.edges()
    ]
    avg_confidence = sum(edge_confidences) / max(len(edge_confidences), 1)

    # Weighted combination
    confidence = (
        0.4 * type_diversity +
        0.3 * cross_ratio +
        0.3 * avg_confidence
    )

    return round(min(confidence, 1.0), 3)


def _collect_risk_indicators(conn: sqlite3.Connection, component: set) -> list[str]:
    """Collect risk indicators from artifact metadata in a component."""
    indicators = []
    for artifact_id in component:
        row = conn.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row and row["metadata"]:
            try:
                meta = json.loads(row["metadata"])
                if isinstance(meta, dict):
                    if "risk_indicators" in meta:
                        indicators.extend(meta["risk_indicators"])
                    if "is_disposable" in meta and meta["is_disposable"]:
                        indicators.append("disposable_email")
                    if "is_voip" in meta and meta["is_voip"]:
                        indicators.append("voip_phone")
            except (json.JSONDecodeError, KeyError):
                pass

    return sorted(set(indicators))

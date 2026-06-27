"""
Ghost Identity Hunter - Correlation Module

PURPOSE:
--------
This module provides identity correlation capabilities that link fragmented digital artifacts
into unified attribution profiles using graph-theoretic analysis, confidence scoring, and
risk assessment to identify likely identity clusters across platforms and services.

FUNCTIONALITY:
--------------
- Graph construction from artifacts and relationship links
- Connected component analysis for identity cluster identification
- Confidence scoring based on cross-platform evidence strength
- Risk indicator aggregation across identity clusters
- Graph metrics computation (component size, centrality, density)
- Persona profile generation with supporting evidence

ALGORITHM:
---------
1. Build directed graph from artifacts (nodes) and links (edges)
2. Identify weakly connected components as potential identity clusters
3. Compute confidence scores based on cross-type link density
4. Aggregate risk indicators from cluster member artifacts
5. Generate persona profiles with supporting evidence
6. Calculate graph metrics for investigation summarization

CORRELATION LOGIC:
-----------------
- Exact matches (same value across platforms) = 1.0 confidence
- Registration links (email to phone) = 0.9 confidence
- Breach correlations = 0.8 confidence
- Username patterns = 0.6 confidence
- Temporal co-occurrence = 0.4 confidence
- Cross-type links boost overall persona confidence

USAGE EXAMPLES:
--------------
# Analyze correlation between artifacts
analysis = analyze_correlation(artifacts, links)

# Get number of identity clusters found
print(f"Found {analysis.connected_components} identity profiles")

# Extract high-confidence personas
for score in analysis.confidence_scores:
    if score > 0.8:
        print("High-confidence identity cluster detected")

DEPENDENCIES:
-------------
- networkx: Graph construction and analysis
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
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class CorrelationAnalysis:
    """Results from correlation analysis of artifacts."""
    
    artifacts_analyzed: int = 0
    links_found: int = 0
    connected_components: int = 0
    largest_component_size: int = 0
    confidence_scores: list[float] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "artifacts_analyzed": self.artifacts_analyzed,
            "links_found": self.links_found,
            "connected_components": self.connected_components,
            "largest_component_size": self.largest_component_size,
            "confidence_scores": self.confidence_scores,
            "risk_indicators": self.risk_indicators,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def analyze_correlation(artifacts: list[dict], links: list[dict]) -> CorrelationAnalysis:
    """
    Analyze correlation between artifacts using NetworkX graph analysis.
    
    This is a simplified correlation module that provides basic graph metrics
    without requiring database connections. The full correlation logic
    is implemented in src/correlation/linker.py.
    
    Args:
        artifacts: List of artifact dictionaries with type, value, confidence
        links: List of link dictionaries connecting artifacts
        
    Returns:
        CorrelationAnalysis with graph metrics and insights
    """
    result = CorrelationAnalysis()
    result.artifacts_analyzed = len(artifacts)
    result.links_found = len(links)
    
    if not artifacts:
        return result
    
    # Build NetworkX graph
    G = nx.Graph()
    
    # Add artifact nodes
    for artifact in artifacts:
        G.add_node(
            artifact.get("id", artifact.get("artifact_id")),
            artifact_type=artifact.get("artifact_type", "unknown"),
            value=artifact.get("value", ""),
            confidence=artifact.get("confidence", 0.8),
        )
    
    # Add edges from links
    for link in links:
        source = link.get("source_artifact")
        target = link.get("target_artifact")
        if source and target and G.has_node(source) and G.has_node(target):
            G.add_edge(
                source,
                target,
                link_type=link.get("link_type", "linked"),
                confidence=link.get("confidence", 0.8),
            )
    
    # Analyze connected components
    if G.number_of_nodes() > 0:
        components = list(nx.connected_components(G))
        result.connected_components = len(components)
        result.largest_component_size = max(len(comp) for comp in components) if components else 0
        
        # Compute confidence scores for each component
        for component in components:
            if len(component) > 1:
                confidence = _compute_component_confidence(G, component)
                result.confidence_scores.append(confidence)
        
        # Collect risk indicators from metadata
        result.risk_indicators = _extract_risk_indicators(artifacts)
    
    logger.info(
        "Correlation analysis: %d artifacts, %d links, %d components",
        result.artifacts_analyzed, result.links_found, result.connected_components
    )
    
    return result


def _compute_component_confidence(G: nx.Graph, component: set) -> float:
    """Compute confidence score for a connected component."""
    if len(component) <= 1:
        return 0.3
    
    subgraph = G.subgraph(component)
    
    # Type diversity (more types = higher confidence)
    types = set()
    for node in component:
        types.add(G.nodes[node].get("artifact_type", "unknown"))
    type_diversity = min(len(types) / 4.0, 1.0)  # Max 4 types
    
    # Edge density
    max_edges = len(component) * (len(component) - 1) / 2
    edge_density = subgraph.number_of_edges() / max(max_edges, 1)
    
    # Average edge confidence
    edge_confidences = [
        subgraph.edges[u, v].get("confidence", 0.5)
        for u, v in subgraph.edges()
    ]
    avg_confidence = sum(edge_confidences) / max(len(edge_confidences), 1)
    
    # Weighted combination
    confidence = (
        0.4 * type_diversity +
        0.3 * edge_density +
        0.3 * avg_confidence
    )
    
    return round(min(confidence, 1.0), 3)


def _extract_risk_indicators(artifacts: list[dict]) -> list[str]:
    """Extract risk indicators from artifact metadata."""
    indicators = []
    
    for artifact in artifacts:
        metadata = artifact.get("metadata")
        if metadata and isinstance(metadata, str):
            try:
                meta = json.loads(metadata)
                if isinstance(meta, dict):
                    if "risk_indicators" in meta:
                        indicators.extend(meta["risk_indicators"])
                    if meta.get("is_disposable"):
                        indicators.append("disposable_detected")
                    if meta.get("is_voip"):
                        indicators.append("voip_detected")
            except (json.JSONDecodeError, TypeError):
                pass
    
    return sorted(set(indicators))


def get_discovered_artifacts(analysis: CorrelationAnalysis) -> list[dict]:
    """Extract artifacts discovered from correlation analysis."""
    artifacts = []
    
    # Add risk indicators as artifacts
    for indicator in analysis.risk_indicators:
        artifacts.append({
            "type": "risk_indicator",
            "value": indicator,
            "source": "correlation_analysis",
            "confidence": 0.9,
        })
    
    # Add high-confidence components as identity indicators
    for i, confidence in enumerate(analysis.confidence_scores):
        if confidence > 0.7:
            artifacts.append({
                "type": "identity_cluster",
                "value": f"IDENTITY-{i + 1:03d}",
                "source": "correlation_analysis",
                "confidence": confidence,
                "metadata": json.dumps({"confidence": confidence, "cluster_id": i + 1}),
            })
    
    return artifacts

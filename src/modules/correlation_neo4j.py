"""
Ghost Identity Hunter - Neo4j Correlation Module

PURPOSE:
--------
This module provides identity correlation capabilities using Neo4j graph database,
enabling persistent graph storage, advanced graph algorithms, and scalable analysis
of digital identity artifacts and their relationships.

FUNCTIONALITY:
--------------
- Neo4j database connection and schema management
- Graph construction from artifacts and relationship links
- Connected component analysis using Cypher queries
- Confidence scoring based on graph structure
- Risk indicator aggregation across identity clusters
- Graph metrics computation (component size, centrality, density)
- Cross-investigation correlation and historical analysis
- Advanced graph algorithms (centrality, pathfinding, community detection)

ALGORITHM:
---------
1. Connect to Neo4j database and ensure schema constraints
2. Create artifact nodes with properties (type, value, confidence)
3. Create relationship edges with properties (link_type, confidence)
4. Use Cypher queries for connected components analysis
5. Compute confidence scores using graph algorithms
6. Aggregate risk indicators from cluster members
7. Generate persona profiles with supporting evidence
8. Calculate graph metrics for investigation summarization

ADVANTAGES OVER NETWORKX:
------------------------
- Persistent graph storage between investigations
- Scalable to millions of nodes and edges
- Native graph database optimizations
- Powerful Cypher query language
- Built-in graph algorithms library
- Real-time query performance
- Cross-investigation correlation
- ACID transaction guarantees

USAGE EXAMPLES:
--------------
# Initialize Neo4j correlation
from src.modules.correlation_neo4j import Neo4jCorrelation

correlation = Neo4jCorrelation(
    uri="bolt://localhost:7687",
    user="neo4j",
    password="password"
)

# Analyze correlation for investigation
analysis = correlation.analyze_correlation(
    investigation_id="INV-abc123",
    artifacts=artifacts,
    links=links
)

# Query identity clusters
clusters = correlation.find_identity_clusters("INV-abc123")

# Cross-investigation correlation
cross_analysis = correlation.cross_investigation_analysis(
    investigation_ids=["INV-abc123", "INV-def456"]
)

DEPENDENCIES:
-------------
- neo4j: Neo4j Python driver
- dataclasses: Structured result objects
- json: Serialization for database storage
- logging: Debug and error reporting

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
3.0 - Neo4j Graph Database Implementation
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from neo4j import GraphDatabase, Driver

logger = logging.getLogger(__name__)


@dataclass
class Neo4jCorrelationAnalysis:
    """Results from Neo4j correlation analysis of artifacts."""
    
    investigation_id: str
    artifacts_analyzed: int = 0
    links_found: int = 0
    connected_components: int = 0
    largest_component_size: int = 0
    confidence_scores: List[float] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)
    identity_clusters: List[Dict[str, Any]] = field(default_factory=list)
    graph_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "artifacts_analyzed": self.artifacts_analyzed,
            "links_found": self.links_found,
            "connected_components": self.connected_components,
            "largest_component_size": self.largest_component_size,
            "confidence_scores": self.confidence_scores,
            "risk_indicators": self.risk_indicators,
            "identity_clusters": self.identity_clusters,
            "graph_metrics": self.graph_metrics,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class Neo4jCorrelation:
    """Neo4j-based correlation analysis for identity clustering."""
    
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        """
        Initialize Neo4j correlation engine.
        
        Args:
            uri: Neo4j connection URI (e.g., "bolt://localhost:7687")
            user: Neo4j username
            password: Neo4j password
            database: Neo4j database name (default: "neo4j")
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self.driver: Optional[Driver] = None
        
        self._connect()
        self._ensure_schema()
    
    def _connect(self):
        """Establish connection to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {self.uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def _ensure_schema(self):
        """Create database schema with constraints and indexes."""
        with self.driver.session(database=self.database) as session:
            # Create unique constraint on artifact IDs
            session.run("""
                CREATE CONSTRAINT artifact_id_unique IF NOT EXISTS
                FOR (a:Artifact) REQUIRE a.id IS UNIQUE
            """)
            
            # Create indexes for common queries
            session.run("""
                CREATE INDEX artifact_investigation_id IF NOT EXISTS
                FOR (a:Artifact) ON (a.investigation_id)
            """)
            
            session.run("""
                CREATE INDEX artifact_type IF NOT EXISTS
                FOR (a:Artifact) ON (a.artifact_type)
            """)
            
            session.run("""
                CREATE INDEX artifact_value IF NOT EXISTS
                FOR (a:Artifact) ON (a.value)
            """)
            
            logger.info("Neo4j schema created successfully")
    
    @contextmanager
    def _session(self):
        """Context manager for Neo4j sessions."""
        session = self.driver.session(database=self.database)
        try:
            yield session
        finally:
            session.close()
    
    def analyze_correlation(
        self,
        investigation_id: str,
        artifacts: List[Dict[str, Any]],
        links: List[Dict[str, Any]]
    ) -> Neo4jCorrelationAnalysis:
        """
        Analyze correlation between artifacts using Neo4j graph database.
        
        Args:
            investigation_id: Unique investigation identifier
            artifacts: List of artifact dictionaries with type, value, confidence
            links: List of link dictionaries connecting artifacts
            
        Returns:
            Neo4jCorrelationAnalysis with graph metrics and insights
        """
        result = Neo4jCorrelationAnalysis(investigation_id=investigation_id)
        result.artifacts_analyzed = len(artifacts)
        result.links_found = len(links)
        
        if not artifacts:
            return result
        
        try:
            # Clear existing data for this investigation
            self._clear_investigation(investigation_id)
            
            # Build graph in Neo4j
            self._build_graph(investigation_id, artifacts, links)
            
            # Analyze connected components
            result.connected_components, result.largest_component_size = \
                self._analyze_components(investigation_id)
            
            # Compute confidence scores
            result.confidence_scores = self._compute_confidence_scores(investigation_id)
            
            # Extract identity clusters
            result.identity_clusters = self._extract_identity_clusters(investigation_id)
            
            # Collect risk indicators
            result.risk_indicators = self._extract_risk_indicators(investigation_id)
            
            # Compute graph metrics
            result.graph_metrics = self._compute_graph_metrics(investigation_id)
            
            logger.info(
                "Neo4j correlation analysis: %d artifacts, %d links, %d components",
                result.artifacts_analyzed, result.links_found, result.connected_components
            )
            
        except Exception as e:
            logger.error(f"Neo4j correlation analysis failed: {e}")
            raise
        
        return result
    
    def _clear_investigation(self, investigation_id: str):
        """Remove all nodes and relationships for an investigation."""
        with self._session() as session:
            session.run("""
                MATCH (a:Artifact {investigation_id: $id})
                DETACH DELETE a
            """, id=investigation_id)
    
    def _build_graph(
        self,
        investigation_id: str,
        artifacts: List[Dict[str, Any]],
        links: List[Dict[str, Any]]
    ):
        """Build graph in Neo4j from artifacts and links."""
        with self._session() as session:
            # Create artifact nodes
            for artifact in artifacts:
                artifact_id = artifact.get("id") or artifact.get("artifact_id")
                if not artifact_id:
                    continue
                
                session.run("""
                    MERGE (a:Artifact {id: $artifact_id})
                    SET a.investigation_id = $investigation_id,
                        a.artifact_type = $artifact_type,
                        a.value = $value,
                        a.confidence = $confidence,
                        a.metadata = $metadata,
                        a.created_at = datetime()
                """, 
                artifact_id=artifact_id,
                investigation_id=investigation_id,
                artifact_type=artifact.get("type") or artifact.get("artifact_type"),
                value=artifact.get("value"),
                confidence=artifact.get("confidence", 0.8),
                metadata=json.dumps(artifact.get("metadata", {}))
                )
            
            # Create relationship edges
            for link in links:
                source = link.get("source_artifact") or link.get("source")
                target = link.get("target_artifact") or link.get("target")
                if not source or not target:
                    continue
                
                session.run("""
                    MATCH (source:Artifact {id: $source})
                    MATCH (target:Artifact {id: $target})
                    MERGE (source)-[r:LINKED_TO]->(target)
                    SET r.link_type = $link_type,
                        r.confidence = $confidence,
                        r.investigation_id = $investigation_id,
                        r.created_at = datetime()
                """,
                source=source,
                target=target,
                link_type=link.get("link_type", "linked"),
                confidence=link.get("confidence", 0.8),
                investigation_id=investigation_id
                )
    
    def _analyze_components(self, investigation_id: str) -> tuple[int, int]:
        """Analyze connected components in the graph."""
        with self._session() as session:
            result = session.run("""
                MATCH (a:Artifact {investigation_id: $id})
                WITH a, count(*) as component_size
                RETURN component_size
                ORDER BY component_size DESC
            """, id=investigation_id)
            
            sizes = [record["component_size"] for record in result]
            num_components = len(sizes)
            largest_size = max(sizes) if sizes else 0
            
            return num_components, largest_size
    
    def _compute_confidence_scores(self, investigation_id: str) -> List[float]:
        """Compute confidence scores for connected components."""
        with self._session() as session:
            result = session.run("""
                MATCH path = (a:Artifact {investigation_id: $id})-[*]-(b:Artifact)
                WITH a, collect(DISTINCT b) as component
                WHERE size(component) > 1
                WITH component, size(component) as component_size
                
                // Compute type diversity
                UNWIND component as node
                WITH component, component_size, collect(DISTINCT node.artifact_type) as types
                WITH component, component_size, size(types) as type_diversity
                
                // Compute edge density
                MATCH (a:Artifact)-[r:LINKED_TO]-(b:Artifact)
                WHERE a IN component AND b IN component
                WITH component, component_size, type_diversity, count(r) as edge_count
                WITH component, component_size, type_diversity, edge_count,
                     (component_size * (component_size - 1) / 2) as max_edges
                
                // Compute average edge confidence
                MATCH (a:Artifact)-[r:LINKED_TO]-(b:Artifact)
                WHERE a IN component AND b IN component
                WITH component, component_size, type_diversity, edge_count, max_edges,
                     avg(r.confidence) as avg_confidence
                
                // Calculate final confidence score
                WITH component, component_size, type_diversity, edge_count, max_edges, avg_confidence,
                     (0.4 * (type_diversity / 4.0)) + 
                     (0.3 * (edge_count / max_edges)) + 
                     (0.3 * avg_confidence) as confidence
                
                RETURN round(confidence, 3) as confidence
            """, id=investigation_id)
            
            return [record["confidence"] for record in result]
    
    def _extract_identity_clusters(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Extract identity clusters from the graph."""
        with self._session() as session:
            result = session.run("""
                MATCH path = (a:Artifact {investigation_id: $id})-[*]-(b:Artifact)
                WITH a, collect(DISTINCT b) as component
                WHERE size(component) > 1
                WITH component, size(component) as cluster_size
                ORDER BY cluster_size DESC
                RETURN component, cluster_size
            """, id=investigation_id)
            
            clusters = []
            for i, record in enumerate(result):
                component = record["component"]
                cluster_size = record["cluster_size"]
                
                # Extract component details
                artifact_types = set(node["artifact_type"] for node in component)
                values = [node["value"] for node in component]
                
                clusters.append({
                    "cluster_id": f"IDENTITY-{i + 1:03d}",
                    "size": cluster_size,
                    "artifact_types": list(artifact_types),
                    "artifacts": values,
                    "confidence": 0.7 + (min(cluster_size / 10.0, 0.3))  # Size-based confidence
                })
            
            return clusters
    
    def _extract_risk_indicators(self, investigation_id: str) -> List[str]:
        """Extract risk indicators from artifact metadata."""
        with self._session() as session:
            result = session.run("""
                MATCH (а:Artifact {investigation_id: $id})
                WHERE а.metadata IS NOT NULL
                RETURN а.metadata
            """, id=investigation_id)
            
            indicators = set()
            for record in result:
                try:
                    metadata = json.loads(record["metadata"])
                    if isinstance(metadata, dict):
                        if "risk_indicators" in metadata:
                            indicators.update(metadata["risk_indicators"])
                        if metadata.get("is_disposable"):
                            indicators.add("disposable_detected")
                        if metadata.get("is_voip"):
                            indicators.add("voip_detected")
                except (json.JSONDecodeError, TypeError):
                    pass
            
            return sorted(list(indicators))
    
    def _compute_graph_metrics(self, investigation_id: str) -> Dict[str, Any]:
        """Compute comprehensive graph metrics."""
        with self._session() as session:
            # Node and edge counts
            counts = session.run("""
                MATCH (a:Artifact {investigation_id: $id})
                OPTIONAL MATCH (a)-[r:LINKED_TO]->(b:Artifact)
                RETURN count(DISTINCT a) as node_count, count(DISTINCT r) as edge_count
            """, id=investigation_id).single()
            
            # Average degree
            degree = session.run("""
                MATCH (a:Artifact {investigation_id: $id})
                MATCH (a)-[r:LINKED_TO]-(b:Artifact)
                WITH a, count(r) as degree
                RETURN avg(degree) as avg_degree
            """, id=investigation_id).single()
            
            # Artifact type distribution
            type_dist = session.run("""
                MATCH (a:Artifact {investigation_id: $id})
                RETURN a.artifact_type as type, count(*) as count
            """, id=investigation_id)
            
            type_distribution = {record["type"]: record["count"] for record in type_dist}
            
            return {
                "node_count": counts["node_count"] if counts else 0,
                "edge_count": counts["edge_count"] if counts else 0,
                "avg_degree": degree["avg_degree"] if degree else 0,
                "type_distribution": type_distribution,
                "density": (counts["edge_count"] / (counts["node_count"] * (counts["node_count"] - 1) / 2)) 
                           if counts and counts["node_count"] > 1 else 0
            }
    
    def find_identity_clusters(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Find identity clusters for an investigation."""
        return self._extract_identity_clusters(investigation_id)
    
    def cross_investigation_analysis(
        self,
        investigation_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Perform cross-investigation correlation analysis.
        
        Args:
            investigation_ids: List of investigation IDs to correlate
            
        Returns:
            Dictionary with cross-investigation insights
        """
        with self._session() as session:
            # Find common artifacts across investigations
            common = session.run("""
                MATCH (a:Artifact)
                WHERE a.investigation_id IN $ids
                WITH a.value as value, collect(DISTINCT a.investigation_id) as investigations
                WHERE size(investigations) > 1
                RETURN value, investigations
                ORDER BY size(investigations) DESC
            """, ids=investigation_ids)
            
            common_artifacts = [
                {
                    "value": record["value"],
                    "investigations": record["investigations"],
                    "count": len(record["investigations"])
                }
                for record in common
            ]
            
            # Find similar patterns across investigations
            patterns = session.run("""
                MATCH (a:Artifact)-[r:LINKED_TO]->(b:Artifact)
                WHERE a.investigation_id IN $ids AND b.investigation_id IN $ids
                WITH a.artifact_type as source_type, b.artifact_type as target_type,
                     collect(DISTINCT a.investigation_id) as investigations
                WHERE size(investigations) > 1
                RETURN source_type, target_type, investigations
            """, ids=investigation_ids)
            
            common_patterns = [
                {
                    "pattern": f"{record['source_type']} -> {record['target_type']}",
                    "investigations": record["investigations"],
                    "count": len(record["investigations"])
                }
                for record in patterns
            ]
            
            return {
                "investigation_count": len(investigation_ids),
                "common_artifacts": common_artifacts,
                "common_patterns": common_patterns,
                "potential_correlations": len(common_artifacts) + len(common_patterns)
            }
    
    def get_artifact_connections(
        self,
        artifact_id: str,
        max_depth: int = 2
    ) -> Dict[str, Any]:
        """
        Get all connections for a specific artifact.
        
        Args:
            artifact_id: Artifact ID to query
            max_depth: Maximum depth of traversal
            
        Returns:
            Dictionary with connected artifacts and paths
        """
        with self._session() as session:
            result = session.run("""
                MATCH path = (a:Artifact {id: $id})-[*1..$depth]-(b:Artifact)
                RETURN b, length(path) as distance, relationships(path) as rels
            """, id=artifact_id, depth=max_depth)
            
            connections = []
            for record in result:
                node = record["b"]
                connections.append({
                    "artifact_id": node["id"],
                    "artifact_type": node["artifact_type"],
                    "value": node["value"],
                    "distance": record["distance"],
                    "confidence": node["confidence"]
                })
            
            return {
                "artifact_id": artifact_id,
                "connection_count": len(connections),
                "connections": connections
            }
    
    def close(self):
        """Close Neo4j database connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def get_discovered_artifacts(analysis: Neo4jCorrelationAnalysis) -> List[Dict[str, Any]]:
    """Extract artifacts discovered from Neo4j correlation analysis."""
    artifacts = []
    
    # Add risk indicators as artifacts
    for indicator in analysis.risk_indicators:
        artifacts.append({
            "type": "risk_indicator",
            "value": indicator,
            "source": "neo4j_correlation",
            "confidence": 0.9,
        })
    
    # Add identity clusters as artifacts
    for cluster in analysis.identity_clusters:
        artifacts.append({
            "type": "identity_cluster",
            "value": cluster["cluster_id"],
            "source": "neo4j_correlation",
            "confidence": cluster["confidence"],
            "metadata": json.dumps(cluster)
        })
    
    return artifacts

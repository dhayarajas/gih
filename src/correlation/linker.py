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
import re
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import urlparse

import networkx as nx

from src.storage import database as db

logger = logging.getLogger(__name__)


# Noise patterns for filtering non-identity artifacts
NOISE_PATTERNS = [
    r"^\?",                    # URL parameters like ?hl=en
    r"^\d+\-",                 # Issue IDs like 10684626-enable-and-use-web-search
    r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.(com|org|net|io|co|ai)$",  # Standalone domain-like strings
    r"^[a-z]{2}-[A-Z]{2}$",    # Language codes like en-IN
    r"^[a-z]{2}_[A-Z]{2}$",    # Locale codes like en_US
    r"^login\?",               # Login URLs
    r"^advanced_search$",
    r"^websearch$",
    r"^simple_search$",
    r"^search$",
    r"^open-webSearch$",
    r"^InteractiveLogin",
    r"^login$",
    r"^signin$",
    r"^log-in$",
    r"^mail$",
    r"^inbox$",
    r"^secure\.login\.gov$",
    r"^myaadhaar\.uidai\.gov\.in$",
    r"^bio$",
    r"^playlists$",
    r"^UC[a-zA-Z0-9_-]{20,}$",  # YouTube channel IDs
]

# Minimum confidence for artifacts to be included in identity correlation
MIN_ARTIFACT_CONFIDENCE = 0.3

# Identity artifact types
IDENTITY_ARTIFACT_TYPES = {"phone", "email", "username", "image", "fullname"}


def _extract_platform_from_url(url: str) -> str:
    """Extract platform name from a profile URL."""
    domain = urlparse(url).netloc.lower()
    platform_map = {
        "instagram.com": "Instagram",
        "pinterest.com": "Pinterest",
        "steamcommunity.com": "Steam",
        "medium.com": "Medium",
        "mastodon.social": "Mastodon",
        "github.com": "GitHub",
        "gitlab.com": "GitLab",
        "linkedin.com": "LinkedIn",
        "reddit.com": "Reddit",
        "twitter.com": "Twitter",
        "x.com": "Twitter",
        "keybase.io": "Keybase",
        "news.ycombinator.com": "HackerNews",
    }
    for key, value in platform_map.items():
        if key in domain:
            return value
    return "unknown"


def _is_noise_value(value: str) -> bool:
    """Check if an artifact value is noise and should not be part of identity correlation."""
    if not value or not isinstance(value, str):
        return True
    
    value = value.strip()
    
    # Too short
    if len(value) < 3:
        return True
    
    # Contains URL-like structures
    if value.startswith("http://") or value.startswith("https://"):
        return True
    
    # Contains query parameters or fragments
    if "?" in value or "#" in value or "=" in value:
        return True
    
    # Domain-like values
    if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.(com|org|net|io|co|edu|gov|in|uk|us|ai)$", value):
        return True
    
    # IP addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
        return True
    
    # YouTube channel IDs
    if re.match(r"^UC[a-zA-Z0-9_-]{20,}$", value):
        return True
    
    for pattern in NOISE_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    
    return False


def _is_valid_username(value: str) -> bool:
    """Check if a username value looks like a real username."""
    if not value or not isinstance(value, str):
        return False
    
    value = value.strip()
    
    # Length check
    if len(value) < 3 or len(value) > 64:
        return False
    
    # Should not be an email
    if "@" in value:
        return False
    
    # Should not contain URL characters
    if any(c in value for c in ["?", "=", "&", "#", "\\", " "]):
        return False
    
    # Should not be a domain
    if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}$", value):
        return False
    
    # Should have at least one letter
    if not re.search(r"[a-zA-Z]", value):
        return False
    
    # Should not be a known generic/non-username word
    generic_words = {
        "login", "signin", "log-in", "signup", "register", "logout",
        "mail", "inbox", "email", "search", "advanced_search", "websearch",
        "simple_search", "open-websearch", "about", "contact", "help",
        "home", "index", "bio", "playlists", "videos", "photos",
    }
    if value.lower() in generic_words:
        return False
    
    return True


def _is_identity_artifact(artifact: dict) -> bool:
    """Check if an artifact should be included in identity correlation."""
    artifact_type = artifact.get("artifact_type", "")
    value = artifact.get("value", "")
    confidence = artifact.get("confidence", 0.0) or 0.0
    
    # Skip low-confidence artifacts
    if confidence < MIN_ARTIFACT_CONFIDENCE:
        return False
    
    # Skip non-identity artifact types
    if artifact_type not in IDENTITY_ARTIFACT_TYPES and artifact_type != "platform_presence":
        return False
    
    # Filter noise values
    if _is_noise_value(value):
        return False
    
    # Validate usernames
    if artifact_type == "username" and not _is_valid_username(value):
        return False
    
    # Validate emails
    if artifact_type == "email":
        if "@" not in value or "." not in value.split("@")[-1]:
            return False
    
    return True


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
    identity_artifact_ids = set()
    
    for artifact in artifacts:
        # Skip risk_indicator and meta artifacts
        if artifact["artifact_type"] in ("risk_indicator", "carrier_info", "breach_data"):
            continue
        
        # Filter non-identity artifacts from correlation graph
        if not _is_identity_artifact(artifact):
            logger.debug("Skipping non-identity artifact from correlation: %s=%s", 
                        artifact["artifact_type"], artifact["value"])
            continue
        
        identity_artifact_ids.add(artifact["artifact_id"])
        G.add_node(
            artifact["artifact_id"],
            artifact_type=artifact["artifact_type"],
            value=artifact["value"],
            source=artifact["source"],
            confidence=artifact["confidence"],
            depth=artifact["depth"],
        )

    # Add edges from links (only between identity artifacts)
    links = db.get_links(conn, investigation_id)
    for link in links:
        source_id = link["source_artifact"]
        target_id = link["target_artifact"]
        
        # Only add edges between identity artifacts
        if source_id in identity_artifact_ids and target_id in identity_artifact_ids:
            G.add_edge(
                source_id,
                target_id,
                link_type=link["link_type"],
                confidence=link["confidence"],
            )

    return G


def correlate_identities(conn: sqlite3.Connection, investigation_id: str) -> CorrelationResult:
    """
    Correlate artifacts into identity profiles using connected component analysis.

    Algorithm:
    1. Build graph from filtered identity artifacts and links
    2. Find connected components (each component = likely same person)
    3. For each component, extract identity profile with typed artifacts
    4. Compute confidence score based on cross-type link density and evidence strength
    5. Filter out weak/noise components into an unclassified profile
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

    valid_identities = []
    noise_artifacts = []
    
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
            elif artifact_type == "platform_presence":
                # platform_presence artifacts only contribute platform URLs, not usernames
                # Extract platform name and username from URL
                from urllib.parse import urlparse
                parsed = urlparse(value)
                platform_name = _extract_platform_from_url(value)
                username = parsed.path.strip("/").split("/")[-1] if parsed.path else ""
                if username and _is_valid_username(username):
                    profile.platforms.append({
                        "platform": platform_name,
                        "profile_url": value,
                        "username": username,
                        "display_name": None,
                    })

            # Collect platform presences for this artifact
            if node_id in presence_by_artifact:
                for presence in presence_by_artifact[node_id]:
                    # Avoid duplicate platform entries
                    existing = [p for p in profile.platforms if p.get("profile_url") == presence.get("profile_url")]
                    if not existing:
                        profile.platforms.append({
                            "platform": presence["platform_name"],
                            "profile_url": presence["profile_url"],
                            "username": presence["username"],
                            "display_name": presence["display_name"],
                        })

                    # Surface any scraped profile image so it renders in the
                    # report. Image URLs are otherwise filtered from the
                    # correlation graph as noise, so presences are the reliable
                    # path to attach them to an identity.
                    presence_image = presence.get("profile_image_url")
                    if presence_image:
                        profile.images.append(presence_image)

        # Deduplicate values
        profile.phones = sorted(set(profile.phones))
        profile.emails = sorted(set(profile.emails))
        profile.usernames = sorted(set(profile.usernames))
        profile.images = sorted(set(profile.images))

        # Deduplicate platforms by profile_url
        seen_urls = set()
        unique_platforms = []
        for p in profile.platforms:
            url = p.get("profile_url")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_platforms.append(p)
        profile.platforms = unique_platforms

        profile.artifact_count = len(component)

        # Compute confidence based on cross-type linking
        profile.confidence = _compute_confidence(G, component)

        # Collect risk indicators from artifact metadata
        profile.risk_indicators = _collect_risk_indicators(conn, component)

        # Filter out weak/noise components
        identity_type_count = sum(1 for field in [profile.phones, profile.emails, profile.usernames, profile.images] if field)
        
        # A valid identity should have at least one strong identity type
        if identity_type_count >= 1 and (len(profile.emails) > 0 or len(profile.usernames) > 0 or len(profile.phones) > 0):
            valid_identities.append(profile)
        else:
            noise_artifacts.extend([G.nodes[n].get("value", "") for n in component])

    # Add unclassified/noise profile if any noise artifacts exist
    if noise_artifacts:
        noise_profile = IdentityProfile(
            profile_id="IDENTITY-NOISE",
            usernames=sorted(set(noise_artifacts)),
            confidence=0.1
        )
        noise_profile.artifact_count = len(noise_artifacts)
        noise_profile.risk_indicators = ["noise_artifacts"]
        valid_identities.append(noise_profile)

    result.identities = valid_identities

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

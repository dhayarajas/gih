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

# Artifact types produced by external OSINT tools, mapped to the IdentityProfile
# field they populate. These are infrastructure/context findings rather than
# identity anchors, so they are attached to a profile instead of forming one.
TOOL_ARTIFACT_FIELDS = {
    "domain": "domains",
    "domain_info": "domains",
    "subdomain": "subdomains",
    "ip_address": "ip_addresses",
    "ip": "ip_addresses",
    "dns_a": "ip_addresses",
    "dns_mx": "dns_records",
    "dns_ns": "dns_records",
    "dns_txt": "dns_records",
    "nameserver": "dns_records",
    "name_server": "dns_records",
    "mail_server": "dns_records",
    "hostname": "hosts",
    "location": "geolocations",
    "open_port": "open_ports",
    "host_info": "hosts",
    "historical_url": "historical_urls",
    "web_technology": "web_technologies",
    "gps_coordinates": "geolocations",
    "camera_info": "device_info",
    "creation_date": "device_info",
    "software": "device_info",
    "device_serial": "device_info",
    # Breach rows belong to the selector they were found for, so they are
    # attributed like any other tool finding rather than left unattached.
    "leak_record": "leak_records",
}

# Tool artifact types that represent an account on a platform.
ACCOUNT_ARTIFACT_TYPES = {"username_presence", "email_presence"}


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
    # Signals behind `confidence`; see explain_confidence()
    confidence_signals: list[dict] = field(default_factory=list)
    confidence_note: str = ""

    # Findings contributed by external OSINT tools, attached to this identity
    domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    dns_records: list[str] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)
    web_technologies: list[str] = field(default_factory=list)
    geolocations: list[str] = field(default_factory=list)
    device_info: list[str] = field(default_factory=list)
    leak_records: list[str] = field(default_factory=list)
    tool_findings: list[dict] = field(default_factory=list)

    @property
    def name(self) -> str:
        """Human-readable label for the identity."""
        for candidate in (self.usernames, self.emails, self.phones, self.images):
            if candidate:
                return candidate[0]
        return self.profile_id

    @property
    def artifacts(self) -> list[str]:
        """All identity-anchor values belonging to this profile."""
        return self.phones + self.emails + self.usernames + self.images

    @property
    def tools_used(self) -> list[str]:
        """Names of the external tools that contributed to this profile."""
        return sorted({f["source"] for f in self.tool_findings if f.get("source")})

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "phones": self.phones,
            "emails": self.emails,
            "usernames": self.usernames,
            "images": self.images,
            "platforms": self.platforms,
            "risk_indicators": self.risk_indicators,
            "confidence": self.confidence,
            "confidence_signals": self.confidence_signals,
            "confidence_note": self.confidence_note,
            "artifact_count": self.artifact_count,
            "domains": self.domains,
            "subdomains": self.subdomains,
            "ip_addresses": self.ip_addresses,
            "dns_records": self.dns_records,
            "open_ports": self.open_ports,
            "hosts": self.hosts,
            "historical_urls": self.historical_urls,
            "web_technologies": self.web_technologies,
            "geolocations": self.geolocations,
            "device_info": self.device_info,
            "leak_records": self.leak_records,
            "tool_findings": self.tool_findings,
            "tools_used": self.tools_used,
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
    profile_components: list[tuple[IdentityProfile, set]] = []
    
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

        # Compute confidence based on cross-type linking, keeping the signals
        # so the report can show why the score is what it is
        explanation = explain_confidence(G, component)
        profile.confidence = explanation["score"]
        profile.confidence_signals = explanation["signals"]
        profile.confidence_note = explanation["note"]

        # Collect risk indicators from artifact metadata
        profile.risk_indicators = _collect_risk_indicators(conn, component)

        # Filter out weak/noise components
        identity_type_count = sum(1 for field in [profile.phones, profile.emails, profile.usernames, profile.images] if field)
        
        # A valid identity should have at least one strong identity type
        if identity_type_count >= 1 and (
            len(profile.emails) > 0
            or len(profile.usernames) > 0
            or len(profile.phones) > 0
            or len(profile.images) > 0
        ):
            valid_identities.append(profile)
            profile_components.append((profile, component))
        else:
            noise_artifacts.extend([G.nodes[n].get("value", "") for n in component])

    # Add unclassified/noise profile if any noise artifacts exist
    if noise_artifacts:
        noise_profile = IdentityProfile(
            profile_id="IDENTITY-NOISE",
            usernames=sorted(set(noise_artifacts)),
            confidence=0.1,
            confidence_note=("Fixed score for artifacts that matched no identity "
                             "anchor; they are listed for review, not attributed."),
        )
        noise_profile.artifact_count = len(noise_artifacts)
        noise_profile.risk_indicators = ["noise_artifacts"]
        valid_identities.append(noise_profile)

    # Attach external tool findings to the identities they were discovered from
    _attach_tool_findings(conn, investigation_id, profile_components, G)

    result.identities = valid_identities

    # Sort by artifact count (largest identity first)
    result.identities.sort(key=lambda x: x.artifact_count, reverse=True)

    logger.info(
        "Correlation complete: %d nodes, %d edges, %d identities",
        result.graph_nodes, result.graph_edges, len(result.identities)
    )
    return result


def _attach_tool_findings(
    conn: sqlite3.Connection,
    investigation_id: str,
    profile_components: list[tuple[IdentityProfile, set]],
    identity_graph: nx.Graph,
) -> None:
    """
    Attach artifacts discovered by external OSINT tools to their identity profile.

    Tool outputs (subdomains, open ports, historical URLs, account presences, ...)
    are not identity anchors, so they are excluded from the correlation graph.
    They are still linked to the seed artifact that produced them, so each profile
    is expanded over the full link graph - stopping at artifacts that belong to a
    different identity - and everything reachable is attributed to that profile.
    """
    if not profile_components:
        return

    artifacts = {a["artifact_id"]: a for a in db.get_artifacts(conn, investigation_id)}

    full_graph = nx.Graph()
    full_graph.add_nodes_from(artifacts)
    for link in db.get_links(conn, investigation_id):
        source, target = link["source_artifact"], link["target_artifact"]
        if source in artifacts and target in artifacts:
            full_graph.add_edge(source, target)

    identity_nodes = set(identity_graph.nodes)

    for profile, component in profile_components:
        reachable = _expand_from_component(full_graph, component, identity_nodes)

        for node_id in reachable:
            artifact = artifacts[node_id]
            artifact_type = artifact["artifact_type"]
            value = artifact["value"]
            source = artifact.get("source") or "unknown"

            if artifact_type in ACCOUNT_ARTIFACT_TYPES:
                platform = _platform_from_metadata(artifact) or _extract_platform_from_url(value)
                profile.platforms.append({
                    "platform": platform,
                    "profile_url": value if value.startswith("http") else None,
                    "username": _account_username(artifact, value),
                    "display_name": None,
                    "source": source,
                })
            elif artifact_type in TOOL_ARTIFACT_FIELDS:
                getattr(profile, TOOL_ARTIFACT_FIELDS[artifact_type]).append(value)
            elif artifact_type in IDENTITY_ARTIFACT_TYPES:
                # Anchors are already on the profile through the graph.
                continue

            # A finding with no field of its own -- an ASN, a copyright line --
            # still belongs to the identity it was reached from, so it is
            # listed rather than dropped.
            profile.tool_findings.append({
                "type": artifact_type,
                "value": value,
                "source": source,
                "confidence": artifact.get("confidence"),
            })

        for field_name in set(TOOL_ARTIFACT_FIELDS.values()):
            setattr(profile, field_name, sorted(set(getattr(profile, field_name))))

        seen_platforms = set()
        unique_platforms = []
        for entry in profile.platforms:
            key = (entry.get("platform"), entry.get("profile_url"))
            if key in seen_platforms:
                continue
            seen_platforms.add(key)
            unique_platforms.append(entry)
        profile.platforms = unique_platforms

        profile.tool_findings.sort(key=lambda f: (f["source"], f["type"], f["value"]))


def _expand_from_component(full_graph: nx.Graph, component: set, identity_nodes: set) -> set:
    """Return non-identity artifacts reachable from a component without crossing identities."""
    visited = set(component)
    queue = [n for n in component if full_graph.has_node(n)]
    reachable = set()

    while queue:
        node = queue.pop()
        for neighbor in full_graph.neighbors(node):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            if neighbor in identity_nodes:
                # Belongs to a different identity; do not traverse through it
                continue
            reachable.add(neighbor)
            queue.append(neighbor)

    return reachable


def _platform_from_metadata(artifact: dict) -> str | None:
    """Read the platform name a tool recorded in an artifact's metadata."""
    metadata = artifact.get("metadata")
    if not metadata:
        return None
    try:
        parsed = json.loads(metadata) if isinstance(metadata, str) else metadata
    except json.JSONDecodeError:
        return None
    return parsed.get("platform") if isinstance(parsed, dict) else None


def _account_username(artifact: dict, value: str) -> str:
    """Determine the account name a presence artifact refers to."""
    metadata = artifact.get("metadata")
    if metadata:
        try:
            parsed = json.loads(metadata) if isinstance(metadata, str) else metadata
            if isinstance(parsed, dict) and parsed.get("username"):
                return parsed["username"]
        except json.JSONDecodeError:
            pass

    if value.startswith("http"):
        return urlparse(value).path.strip("/").split("/")[-1]
    return value


def explain_confidence(G: nx.Graph, component: set) -> dict:
    """
    Compute an identity's confidence score and the signals that produced it.

    A bare percentage is not reviewable: an analyst cannot tell whether 60%
    means three artifact types weakly linked or two types linked by an exact
    match. The score is unchanged; each signal is reported with its measured
    value, its weight and what it contributed.
    """
    if len(component) <= 1:
        return {
            "score": 0.3,
            "signals": [],
            "note": ("Floor score for a single unlinked artifact: nothing "
                     "corroborates it, so no signal is measurable."),
        }

    subgraph = G.subgraph(component)

    types = {G.nodes[node].get("artifact_type", "unknown") for node in component}
    # Max 4 identity types: phone, email, username, image
    type_diversity = min(len(types) / 4.0, 1.0)

    total_edges = subgraph.number_of_edges()
    cross_edges = sum(
        1 for u, v in subgraph.edges()
        if G.nodes[u].get("artifact_type") != G.nodes[v].get("artifact_type")
    )
    cross_ratio = cross_edges / max(total_edges, 1)

    edge_confidences = [
        subgraph.edges[u, v].get("confidence", 0.5) for u, v in subgraph.edges()
    ]
    avg_confidence = sum(edge_confidences) / max(len(edge_confidences), 1)

    signals = [
        {
            "name": "Artifact type diversity",
            "weight": 0.4,
            "value": round(type_diversity, 3),
            "detail": (f"{len(types)} of 4 identity types present "
                       f"({', '.join(sorted(types))})"),
        },
        {
            "name": "Cross-type links",
            "weight": 0.3,
            "value": round(cross_ratio, 3),
            "detail": (f"{cross_edges} of {total_edges} link(s) join two "
                       f"different artifact types"),
        },
        {
            "name": "Mean link confidence",
            "weight": 0.3,
            "value": round(avg_confidence, 3),
            "detail": f"averaged over {len(edge_confidences)} link(s)",
        },
    ]
    for signal in signals:
        signal["contribution"] = round(signal["weight"] * signal["value"], 3)

    score = round(min(sum(s["contribution"] for s in signals), 1.0), 3)
    return {"score": score, "signals": signals, "note": ""}


def _compute_confidence(G: nx.Graph, component: set) -> float:
    """Confidence score for an identity profile; see explain_confidence."""
    return explain_confidence(G, component)["score"]


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

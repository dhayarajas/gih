"""
Ghost Identity Hunter - Investigation Orchestrator

PURPOSE:
--------
This module implements the core investigation orchestration engine that coordinates
OSINT data collection across multiple modules using a breadth-first search (BFS)
pipeline with depth-limited artifact discovery.

FUNCTIONALITY:
--------------
- BFS-based artifact discovery with configurable depth limits
- Coordination of 6 OSINT modules (phone, email, username, image, breach, correlation)
- SQLite database persistence for investigation state
- Automatic artifact linking and relationship discovery
- Risk indicator collection and aggregation
- Investigation lifecycle management (create, execute, complete)
- Graceful handling of missing external OSINT tools

ALGORITHM:
---------
1. Initialize BFS queue with seed artifacts (phone, email, username, image)
2. Process artifacts in FIFO order, dispatching to appropriate OSINT modules
3. Discover new artifacts from module results and add to queue (if within depth limit)
4. Link source artifacts to discovered artifacts with confidence scores
5. Repeat until queue empty or max depth reached
6. Run correlation analysis on collected artifacts
7. Generate investigation summary with statistics and risk indicators

CONFIGURATION:
-------------
- MAX_DEPTH: Maximum recursion depth (default: 2) to prevent infinite loops
- InvestigationConfig: Controls module enablement and behavior
- Rate limiting and timeout handling for external API calls
- Tool availability checking for external OSINT tools

USAGE EXAMPLES:
--------------
# Basic investigation
result = run_investigation(conn, seeds, config, title="Email Investigation")

# Custom configuration
config = InvestigationConfig(max_depth=3, check_breaches=False)
result = run_investigation(conn, seeds, config)

DEPENDENCIES:
-------------
- collections.deque: BFS queue implementation
- sqlite3: Database persistence
- src.modules: OSINT collection modules
- src.storage.database: Database operations
- src.modules.correlation: Identity correlation analysis
- src.utils.tool_checker: External tool availability checking

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
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from src.modules import phone_osint, email_osint, username_search, image_search, breach_check, correlation
from src.modules.correlation_neo4j import Neo4jCorrelation
from src.modules.google_dorks import run_google_dorks_search, check_google_dorks_availability
from src.storage import database as db
from src.utils.tool_checker import get_tool_checker, check_tool_availability
from src.modules.external_tools import run_tool_analysis, get_tool_integrations
from src.plugins import PluginManager, PluginRegistry, Artifact as PluginArtifact, PluginConfig

logger = logging.getLogger(__name__)

MAX_DEPTH = 2  # Maximum recursion depth for artifact discovery


@dataclass
class InvestigationConfig:
    """Configuration for an investigation run."""

    max_depth: int = MAX_DEPTH
    check_breaches: bool = True
    search_usernames: bool = True
    check_images: bool = True
    verbose: bool = False
    check_external_tools: bool = True  # Check external OSINT tool availability
    skip_missing_tools: bool = True  # Skip analysis if tool not available
    use_neo4j: bool = False  # Use Neo4j for graph correlation
    neo4j_uri: str = "bolt://localhost:7687"  # Neo4j connection URI
    neo4j_user: str = "neo4j"  # Neo4j username
    neo4j_password: str = "password"  # Neo4j password
    neo4j_database: str = "neo4j"  # Neo4j database name
    use_google_dorks: bool = False  # Use Google Dorks for username discovery
    google_api_key: Optional[str] = None  # Google Custom Search API key
    google_cx: Optional[str] = None  # Google Custom Search Engine ID
    use_google_api: bool = False  # Use Google API instead of web scraping
    search_engine: str = "auto"  # Search engine for Google Dorks (auto, duckduckgo, google, bing)


@dataclass
class InvestigationResult:
    """Summary result of a completed investigation."""

    investigation_id: str
    seed_artifacts: list[dict] = field(default_factory=list)
    total_artifacts: int = 0
    total_links: int = 0
    total_platforms: int = 0
    risk_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "seed_artifacts": self.seed_artifacts,
            "total_artifacts": self.total_artifacts,
            "total_links": self.total_links,
            "total_platforms": self.total_platforms,
            "risk_indicators": self.risk_indicators,
        }


def run_investigation(
    conn: sqlite3.Connection,
    seeds: list[dict],
    config: Optional[InvestigationConfig] = None,
    title: Optional[str] = None,
) -> InvestigationResult:
    """
    Run an investigation starting from seed artifacts.

    Implements BFS pipeline:
    1. Start with seed artifacts (phone, email, username, image)
    2. Run appropriate OSINT module for each artifact
    3. Discover new artifacts from results
    4. Add discovered artifacts to queue (up to max_depth)
    5. Link source → discovered artifacts
    6. Repeat until queue is empty or depth limit reached

    Args:
        conn: Database connection
        seeds: List of seed artifacts [{"type": "phone", "value": "+1..."}, ...]
        config: Investigation configuration
        title: Optional investigation title

    Returns:
        InvestigationResult with summary statistics
    """
    config = config or InvestigationConfig()

    logger.info("Starting investigation with %d seed artifact(s)", len(seeds))
    logger.debug("Investigation config: max_depth=%d, breach_checks=%s, username_search=%s", 
                config.max_depth, config.check_breaches, config.search_usernames)
    
    if title:
        logger.info("Investigation title: %s", title)

    # Check external tool availability if enabled
    if config.check_external_tools:
        logger.debug("Checking external OSINT tool availability...")
        tool_checker = get_tool_checker()
        available_tools = tool_checker.get_available_tools()
        missing_tools = tool_checker.get_missing_tools()
        
        logger.info(f"Available external tools: {len(available_tools)}")
        logger.info(f"Missing external tools: {len(missing_tools)}")
        
        if config.verbose and missing_tools:
            logger.debug(f"Missing tools: {', '.join(missing_tools[:5])}")
            if len(missing_tools) > 5:
                logger.debug(f"Additional missing tools: {len(missing_tools) - 5}")

    # Initialize plugin system
    logger.debug("Initializing plugin system...")
    plugin_registry = PluginRegistry()
    plugin_registry.discover_plugins()
    
    plugin_manager = PluginManager(plugin_registry)
    available_plugins = plugin_registry.get_available_plugins()
    
    logger.info(f"Available plugins: {len(available_plugins)}")
    if config.verbose:
        logger.debug(f"Plugins: {', '.join(available_plugins)}")

    # Create investigation
    inv_id = db.create_investigation(conn, title=title)
    result = InvestigationResult(investigation_id=inv_id, seed_artifacts=seeds)
    
    logger.info("Created investigation: %s", inv_id)

    # Initialize BFS queue with seed artifacts
    queue: deque[dict] = deque()
    seen: set[str] = set()

    logger.debug("Initializing BFS queue with seed artifacts")
    for i, seed in enumerate(seeds):
        artifact_id = db.add_artifact(
            conn,
            investigation_id=inv_id,
            artifact_type=seed["type"],
            value=seed["value"],
            source="seed",
            depth=0,
        )
        key = f"{seed['type']}:{seed['value']}"
        seen.add(key)
        queue.append({
            "artifact_id": artifact_id,
            "type": seed["type"],
            "value": seed["value"],
            "depth": 0,
        })
        logger.debug("Added seed %d: %s=%s (ID: %s)", i+1, seed["type"], seed["value"], artifact_id)

    logger.info("Starting BFS processing with %d artifacts in queue", len(queue))

    # BFS loop
    processed_count = 0
    while queue:
        current = queue.popleft()
        current_depth = current["depth"]
        current_id = current["artifact_id"]
        processed_count += 1

        logger.info(
            "Processing: %s=%s (depth=%d, queue_size=%d)",
            current["type"], current["value"], current_depth, len(queue)
        )

        # Run appropriate OSINT module
        discovered = _process_artifact(conn, inv_id, current, config, plugin_manager)
        
        logger.debug("Discovered %d new artifacts from %s=%s", 
                    len(discovered), current["type"], current["value"])

        # Add discovered artifacts to queue (if within depth limit)
        if current_depth < config.max_depth:
            added_count = 0
            for artifact in discovered:
                key = f"{artifact['type']}:{artifact['value']}"
                if key in seen:
                    logger.debug("Skipping duplicate artifact: %s", key)
                    continue
                seen.add(key)

                # Store new artifact
                new_id = db.add_artifact(
                    conn,
                    investigation_id=inv_id,
                    artifact_type=artifact["type"],
                    value=artifact["value"],
                    source=artifact.get("source", "discovered"),
                    confidence=artifact.get("confidence", 0.8),
                    metadata=artifact.get("metadata"),
                    depth=current_depth + 1,
                )

                # Create link from source to discovered
                db.add_link(
                    conn,
                    investigation_id=inv_id,
                    source_artifact=current_id,
                    target_artifact=new_id,
                    link_type=artifact.get("link_type", "discovered_from"),
                    confidence=artifact.get("confidence", 0.8),
                    evidence=artifact.get("source", ""),
                )

                # Add to queue for further investigation
                queue.append({
                    "artifact_id": new_id,
                    "type": artifact["type"],
                    "value": artifact["value"],
                    "depth": current_depth + 1,
                })
                added_count += 1
                
                logger.debug("Added artifact: %s=%s (confidence=%.2f, link=%s)", 
                           artifact["type"], artifact["value"], 
                           artifact.get("confidence", 0.8),
                           artifact.get("link_type", "discovered_from"))
            
            logger.debug("Added %d new artifacts to queue from %s=%s", 
                        added_count, current["type"], current["value"])
        else:
            logger.debug("Depth limit reached (%d), not adding discovered artifacts", config.max_depth)

    logger.info("BFS processing complete. Processed %d artifacts", processed_count)
    
    # Finalize
    logger.debug("Finalizing investigation %s", inv_id)
    db.complete_investigation(conn, inv_id)

    # Compute summary
    logger.debug("Computing investigation summary statistics")
    all_artifacts = db.get_artifacts(conn, inv_id)
    all_links = db.get_links(conn, inv_id)
    all_presences = db.get_platform_presences(conn, inv_id)

    result.total_artifacts = len(all_artifacts)
    result.total_links = len(all_links)
    result.total_platforms = len(all_presences)
    
    logger.info("Summary: %d artifacts, %d links, %d platform presences", 
               result.total_artifacts, result.total_links, result.total_platforms)
    
    # Run correlation analysis
    logger.debug("Running correlation analysis on %d artifacts and %d links", 
                len(all_artifacts), len(all_links))
    
    if config.use_neo4j:
        # Use Neo4j for graph correlation
        logger.info("Using Neo4j for correlation analysis")
        try:
            neo4j_correlation = Neo4jCorrelation(
                uri=config.neo4j_uri,
                user=config.neo4j_user,
                password=config.neo4j_password,
                database=config.neo4j_database
            )
            correlation_analysis = neo4j_correlation.analyze_correlation(inv_id, all_artifacts, all_links)
            neo4j_correlation.close()
            logger.info("Neo4j correlation analysis completed successfully")
        except Exception as e:
            logger.error(f"Neo4j correlation failed, falling back to NetworkX: {e}")
            correlation_analysis = correlation.analyze_correlation(all_artifacts, all_links)
    else:
        # Use NetworkX for graph correlation
        correlation_analysis = correlation.analyze_correlation(all_artifacts, all_links)
    
    logger.info("Correlation analysis: %d connected components, largest component size: %d", 
               correlation_analysis.connected_components, correlation_analysis.largest_component_size)
    
    # Store correlation analysis metadata
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO investigation_metadata (investigation_id, key, value, created_at) VALUES (?, ?, ?, ?)",
        (inv_id, "correlation_analysis", correlation_analysis.to_json(), now)
    )
    conn.commit()
    logger.debug("Stored correlation analysis metadata")

    # Collect risk indicators
    logger.debug("Collecting risk indicators from artifacts")
    for artifact in all_artifacts:
        if artifact.get("metadata"):
            try:
                meta = json.loads(artifact["metadata"])
                if isinstance(meta, dict) and "risk_indicators" in meta:
                    result.risk_indicators.extend(meta["risk_indicators"])
            except (json.JSONDecodeError, KeyError):
                pass

    # Remove duplicates from risk indicators
    result.risk_indicators = list(set(result.risk_indicators))
    
    if result.risk_indicators:
        logger.info("Found %d unique risk indicators: %s", 
                   len(result.risk_indicators), ", ".join(result.risk_indicators[:5]))
        if len(result.risk_indicators) > 5:
            logger.debug("Additional risk indicators: %s", 
                        ", ".join(result.risk_indicators[5:]))

    logger.info(
        "Investigation %s complete: %d artifacts, %d links, %d platforms, %d risk indicators",
        inv_id, result.total_artifacts, result.total_links, result.total_platforms, len(result.risk_indicators)
    )
    return result


def _process_artifact(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    config: InvestigationConfig,
    plugin_manager: PluginManager = None,
) -> list[dict]:
    """Process a single artifact through the appropriate OSINT module."""
    discovered = []
    artifact_type = artifact["type"]
    value = artifact["value"]

    logger.debug("Dispatching artifact to OSINT module: %s=%s", artifact_type, value)

    if artifact_type == "phone":
        logger.debug("Processing phone number with phone_osint module")
        discovered.extend(_process_phone(conn, inv_id, artifact, value, config))
    elif artifact_type == "email":
        logger.debug("Processing email address with email_osint module")
        discovered.extend(_process_email(conn, inv_id, artifact, value, config))
    elif artifact_type == "username":
        logger.debug("Processing username with username_search module")
        discovered.extend(_process_username(conn, inv_id, artifact, value, config))
    elif artifact_type == "image":
        logger.debug("Processing image with image_search module")
        discovered.extend(_process_image(conn, inv_id, artifact, value, config))
    else:
        logger.warning("Unknown artifact type: %s", artifact_type)

    logger.debug("OSINT module returned %d discovered artifacts", len(discovered))
    
    # Process with external OSINT tools if enabled
    if config.check_external_tools:
        logger.debug("Processing artifact with external OSINT tools")
        external_discovered = _process_external_tools(conn, inv_id, artifact, config)
        discovered.extend(external_discovered)
        logger.debug("External tools returned %d additional artifacts", len(external_discovered))
    
    # Process with plugin system if available
    if plugin_manager:
        logger.debug("Processing artifact with plugin system")
        plugin_discovered = _process_with_plugins(conn, inv_id, artifact, config, plugin_manager)
        discovered.extend(plugin_discovered)
        logger.debug("Plugin system returned %d additional artifacts", len(plugin_discovered))
    
    return discovered


def _process_phone(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    value: str,
    config: InvestigationConfig,
) -> list[dict]:
    """Process a phone number artifact."""
    discovered = []
    try:
        logger.debug("Analyzing phone number: %s", value)
        analysis = phone_osint.analyze_phone(value)

        logger.debug("Phone analysis complete: valid=%s, carrier=%s, line_type=%s", 
                    analysis.valid, analysis.carrier_name, analysis.line_type)

        # Store analysis metadata
        metadata = analysis.to_json()
        conn.execute(
            "UPDATE artifacts SET metadata = ? WHERE artifact_id = ?",
            (metadata, artifact["artifact_id"]),
        )
        conn.commit()
        logger.debug("Stored phone analysis metadata for artifact %s", artifact["artifact_id"])

        # Extract discovered artifacts
        phone_artifacts = phone_osint.get_discovered_artifacts(analysis)
        discovered.extend(phone_artifacts)
        logger.debug("Extracted %d artifacts from phone analysis", len(phone_artifacts))

        # Add risk indicators
        if analysis.risk_indicators:
            logger.debug("Found %d phone risk indicators: %s", 
                        len(analysis.risk_indicators), ", ".join(analysis.risk_indicators))
            for indicator in analysis.risk_indicators:
                discovered.append({
                    "type": "risk_indicator",
                    "value": indicator,
                    "source": "phone_osint",
                    "confidence": 0.9,
                    "link_type": "has_risk",
                })

    except Exception as e:
        logger.error("Phone OSINT failed for %s: %s", value, e)

    return discovered


def _process_email(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    value: str,
    config: InvestigationConfig,
) -> list[dict]:
    """Process an email artifact."""
    discovered = []
    try:
        logger.debug("Analyzing email address: %s", value)
        analysis = email_osint.analyze_email(value)

        logger.debug("Email analysis complete: valid=%s, disposable=%s, domain=%s", 
                    analysis.valid_format, analysis.is_disposable, analysis.domain)

        # Store analysis metadata
        metadata = analysis.to_json()
        conn.execute(
            "UPDATE artifacts SET metadata = ? WHERE artifact_id = ?",
            (metadata, artifact["artifact_id"]),
        )
        conn.commit()
        logger.debug("Stored email analysis metadata for artifact %s", artifact["artifact_id"])

        # Record platform presences
        if analysis.platforms_found:
            logger.debug("Recording %d platform presences for email %s", 
                        len(analysis.platforms_found), value)
            for platform in analysis.platforms_found:
                db.add_platform_presence(
                    conn,
                    investigation_id=inv_id,
                    artifact_id=artifact["artifact_id"],
                    platform_name=platform.get("platform", "unknown"),
                    profile_url=platform.get("profile_url"),
                    username=platform.get("username"),
                )

        # Extract discovered artifacts
        email_artifacts = email_osint.get_discovered_artifacts(analysis)
        discovered.extend(email_artifacts)
        logger.debug("Extracted %d artifacts from email analysis", len(email_artifacts))

        # Breach check
        if config.check_breaches:
            logger.debug("Running breach check for email: %s", value)
            breach_result = breach_check.check_email_breaches(value)
            
            if breach_result.breaches:
                logger.info("Found %d breaches for email %s: %s", 
                           len(breach_result.breaches), value,
                           ", ".join([b.name for b in breach_result.breaches[:3]]))
            else:
                logger.debug("No breaches found for email: %s", value)
            
            if breach_result.error:
                logger.warning("Breach check warning: %s", breach_result.error)
                
            breach_artifacts = breach_check.get_discovered_artifacts(breach_result)
            for ba in breach_artifacts:
                ba["link_type"] = "found_in_breach"
            discovered.extend(breach_artifacts)

        # Try username from email local part
        local_part = value.split("@")[0]
        if config.search_usernames and len(local_part) >= 3:
            logger.debug("Extracted username from email local part: %s", local_part)
            discovered.append({
                "type": "username",
                "value": local_part,
                "source": "email_local_part",
                "confidence": 0.5,
                "link_type": "possible_username",
            })

    except Exception as e:
        logger.error("Email OSINT failed for %s: %s", value, e)

    return discovered


def _process_username(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    value: str,
    config: InvestigationConfig,
) -> list[dict]:
    """Process a username artifact."""
    discovered = []
    try:
        if not config.search_usernames:
            return discovered

        search_result = username_search.search_username(value)

        # Store search result metadata
        metadata = search_result.to_json()
        conn.execute(
            "UPDATE artifacts SET metadata = ? WHERE artifact_id = ?",
            (metadata, artifact["artifact_id"]),
        )
        conn.commit()

        # Record platform presences
        for platform in search_result.platforms_found:
            db.add_platform_presence(
                conn,
                investigation_id=inv_id,
                artifact_id=artifact["artifact_id"],
                platform_name=platform.platform_name,
                profile_url=platform.profile_url,
                username=platform.username,
                display_name=platform.display_name,
                bio=platform.bio,
                follower_count=platform.follower_count,
            )

        # Extract platform presences as new artifacts
        discovered.extend(username_search.get_discovered_artifacts(search_result))

    except Exception as e:
        logger.error("Username search failed for %s: %s", value, e)

    return discovered


def _process_external_tools(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    config: InvestigationConfig,
) -> list[dict]:
    """Process artifact using external OSINT tools when available."""
    discovered = []
    artifact_type = artifact["type"]
    value = artifact["value"]
    
    if not config.check_external_tools:
        return discovered
    
    logger.debug("Processing artifact with external OSINT tools: %s=%s", artifact_type, value)
    
    try:
        # Username-based external tools
        if artifact_type == "username":
            # Run Sherlock for comprehensive username search
            if check_tool_availability("sherlock"):
                logger.debug("Running Sherlock username search for: %s", value)
                sherlock_result = run_tool_analysis("sherlock", "username_search", value)
                
                if sherlock_result.success and sherlock_result.artifacts_discovered:
                    discovered.extend(sherlock_result.artifacts_discovered)
                    logger.info("Sherlock found %d artifacts for username %s", 
                               len(sherlock_result.artifacts_discovered), value)
                else:
                    logger.debug("Sherlock skipped or failed for %s", value)
            
            # Run Google Dorks for advanced username discovery
            if check_google_dorks_availability(config.google_api_key):
                logger.debug("Running Google Dorks search for: %s", value)
                google_dorks_result = run_google_dorks_search(
                    username=value,
                    api_key=config.google_api_key,
                    cx=config.google_cx,
                    use_api=config.use_google_api,
                    search_engine=config.search_engine
                )
                
                if google_dorks_result:
                    discovered.extend(google_dorks_result)
                    logger.info("Google Dorks found %d artifacts for username %s", 
                               len(google_dorks_result), value)
                else:
                    logger.debug("Google Dorks found no results for %s", value)
        
        # Domain-based external tools
        elif artifact_type == "domain":
            # Run theHarvester for email and subdomain discovery
            if check_tool_availability("theharvester"):
                logger.debug("Running theHarvester for domain: %s", value)
                harvest_result = run_tool_analysis("theharvester", "email_harvest", value)
                
                if harvest_result.success and harvest_result.artifacts_discovered:
                    discovered.extend(harvest_result.artifacts_discovered)
                    logger.info("theHarvester found %d emails for domain %s", 
                               len(harvest_result.artifacts_discovered), value)
                
                # Also harvest subdomains
                subdomain_result = run_tool_analysis("theharvester", "subdomain_harvest", value)
                if subdomain_result.success and subdomain_result.artifacts_discovered:
                    discovered.extend(subdomain_result.artifacts_discovered)
                    logger.info("theHarvester found %d subdomains for domain %s", 
                               len(subdomain_result.artifacts_discovered), value)
            
            # Run Amass for subdomain enumeration
            if check_tool_availability("amass"):
                logger.debug("Running Amass subdomain enumeration for: %s", value)
                amass_result = run_tool_analysis("amass", "subdomain_enum", value)
                
                if amass_result.success and amass_result.artifacts_discovered:
                    discovered.extend(amass_result.artifacts_discovered)
                    logger.info("Amass found %d subdomains for domain %s", 
                               len(amass_result.artifacts_discovered), value)
            
            # Run Whois for domain information
            if check_tool_availability("whois"):
                logger.debug("Running Whois lookup for: %s", value)
                whois_result = run_tool_analysis("whois", "domain_lookup", value)
                
                if whois_result.success and whois_result.artifacts_discovered:
                    discovered.extend(whois_result.artifacts_discovered)
                    logger.info("Whois found %d artifacts for domain %s", 
                               len(whois_result.artifacts_discovered), value)
            
            # Run Dig for DNS records
            if check_tool_availability("dig"):
                logger.debug("Running Dig DNS lookup for: %s", value)
                dig_result = run_tool_analysis("dig", "dns_lookup", value)
                
                if dig_result.success and dig_result.artifacts_discovered:
                    discovered.extend(dig_result.artifacts_discovered)
                    logger.info("Dig found %d DNS records for domain %s", 
                               len(dig_result.artifacts_discovered), value)
            
            # Run Wayback Machine for historical data
            wayback_result = run_tool_analysis("wayback_machine", "historical_urls", value)
            if wayback_result.success and wayback_result.artifacts_discovered:
                discovered.extend(wayback_result.artifacts_discovered)
                logger.info("Wayback Machine found %d historical URLs for %s", 
                           len(wayback_result.artifacts_discovered), value)
        
        # IP-based external tools
        elif artifact_type == "ip_address":
            # Run Shodan for host information
            if check_tool_availability("shodan"):
                logger.debug("Running Shodan search for: %s", value)
                shodan_result = run_tool_analysis("shodan", "host_search", value)
                
                if shodan_result.success and shodan_result.artifacts_discovered:
                    discovered.extend(shodan_result.artifacts_discovered)
                    logger.info("Shodan found %d artifacts for IP %s", 
                               len(shodan_result.artifacts_discovered), value)
            
            # Run Nmap for port scanning
            if check_tool_availability("nmap"):
                logger.debug("Running Nmap scan for: %s", value)
                nmap_result = run_tool_analysis("nmap", "host_scan", value)
                
                if nmap_result.success and nmap_result.artifacts_discovered:
                    discovered.extend(nmap_result.artifacts_discovered)
                    logger.info("Nmap found %d open ports on %s", 
                               len(nmap_result.artifacts_discovered), value)
        
        # Image-based external tools
        elif artifact_type == "image":
            # Run ExifTool for metadata extraction
            if check_tool_availability("exiftool"):
                logger.debug("Running ExifTool on image: %s", value)
                exif_result = run_tool_analysis("exiftool", "metadata_extract", value)
                
                if exif_result.success and exif_result.artifacts_discovered:
                    discovered.extend(exif_result.artifacts_discovered)
                    logger.info("ExifTool found %d artifacts in image %s", 
                               len(exif_result.artifacts_discovered), value)
        
        # Email-based external tools
        elif artifact_type == "email":
            # Extract domain from email for domain-based analysis
            if "@" in value:
                domain = value.split("@")[1]
                domain_artifact = {
                    "type": "domain",
                    "value": domain,
                    "source": "email_domain_extraction",
                    "confidence": 0.7,
                    "link_type": "domain_of_email"
                }
                discovered.append(domain_artifact)
                logger.debug("Extracted domain from email: %s", domain)
    
    except Exception as e:
        logger.error("External tools processing failed for %s: %s", value, e)
    
    return discovered


def _process_with_plugins(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    config: InvestigationConfig,
    plugin_manager: PluginManager,
) -> list[dict]:
    """Process artifact using the plugin system."""
    discovered = []
    
    try:
        # Convert artifact to plugin format
        plugin_artifact = PluginArtifact(
            type=artifact["type"],
            value=artifact["value"],
            source="orchestrator",
            confidence=1.0,
            metadata={"artifact_id": artifact["artifact_id"]}
        )
        
        # Execute compatible plugins
        plugin_results = plugin_manager.execute_plugins_for_artifact(
            artifact=plugin_artifact,
            parallel=True,
            max_workers=5
        )
        
        # Extract findings from plugin results
        for result in plugin_results:
            if result.status.value == "success":
                for plugin_artifact in result.artifacts:
                    discovered.append({
                        "type": plugin_artifact.type,
                        "value": plugin_artifact.value,
                        "source": f"plugin:{result.plugin_name}",
                        "confidence": plugin_artifact.confidence,
                        "metadata": plugin_artifact.metadata,
                        "link_type": "discovered_from"
                    })
        
        logger.info(f"Plugin system processed {len(plugin_results)} plugins, discovered {len(discovered)} artifacts")
        
    except Exception as e:
        logger.error(f"Plugin system processing failed: {e}")
    
    return discovered


def _process_image(
    conn: sqlite3.Connection,
    inv_id: str,
    artifact: dict,
    value: str,
    config: InvestigationConfig,
) -> list[dict]:
    """Process an image artifact."""
    discovered = []
    try:
        if not config.check_images:
            return discovered

        analysis = image_search.analyze_image(value)

        # Store analysis metadata
        metadata = analysis.to_json()
        conn.execute(
            "UPDATE artifacts SET metadata = ? WHERE artifact_id = ?",
            (metadata, artifact["artifact_id"]),
        )
        conn.commit()

        # Extract discovered artifacts
        discovered.extend(image_search.get_discovered_artifacts(analysis))

    except Exception as e:
        logger.error("Image analysis failed for %s: %s", value, e)

    return discovered

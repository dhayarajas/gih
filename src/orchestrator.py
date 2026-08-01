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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
from pathlib import Path
from typing import Any, Optional

from src.modules import phone_osint, email_osint, username_search, image_search, breach_check, correlation, image_match
from src.modules.correlation_neo4j import Neo4jCorrelation
from src.modules.google_dorks import run_google_dorks_search, check_google_dorks_availability
from src.storage import database as db
from src.utils.tool_checker import get_tool_checker, check_tool_availability
from src.modules.external_tools import (
    run_tool_analysis,
    get_tool_integrations,
    clear_tool_analysis_cache,
)
from src.plugins import PluginManager, PluginRegistry, Artifact as PluginArtifact, PluginConfig
from src.config.loader import get_config
from src.utils import concurrency

logger = logging.getLogger(__name__)


def _get_orchestrator_config() -> dict:
    """Get orchestrator configuration from config.yaml."""
    config = get_config()
    return config.get("orchestrator", {
        "bfs_batch_size": 10,
        "max_depth": 2,
        "max_parallel_workers": 10,  # BFS-level artifact concurrency
    })


def _get_investigation_defaults() -> dict:
    """Resolve investigation-wide bounds (runtime, artifact budget, workers)."""
    config = get_config()
    inv = config.get("investigation", {}) or {}
    orch = config.get("orchestrator", {}) or {}
    plugin_settings = config.get("plugin_settings", {}) or {}

    # Prefer a dedicated orchestrator setting, then fall back to the shared
    # plugin worker count, then a sane default.
    workers = orch.get(
        "max_parallel_workers",
        plugin_settings.get("max_parallel_workers", 10),
    )

    return {
        "max_runtime_minutes": float(inv.get("max_runtime_minutes", 18.0)),
        "max_total_artifacts": int(inv.get("max_total_artifacts", 500)),
        "max_parallel_workers": max(1, int(workers)),
    }


MAX_DEPTH = _get_orchestrator_config().get("max_depth", 2)
_INV_DEFAULTS = _get_investigation_defaults()

# Only these artifact types are re-queued for further processing. Everything
# else (risk_indicator, open_port, dns_*, historical_url, identity_match, ...)
# is a leaf result: it is still stored and linked, but never triggers another
# round of module/external-tool processing.
#
# `platform_presence` is included because it runs no OSINT module or external
# tool (see _process_artifact / _process_external_tools) -- it is cheap and is
# the sole input to the profile_image plugin, which extracts profile pictures
# from discovered social accounts. Dropping it would silently disable that step.
EXPANDABLE_ARTIFACT_TYPES = frozenset({
    "phone", "email", "username", "image", "fullname", "domain", "ip_address",
    "platform_presence",
})


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
    # Bounds that guarantee the overall time budget
    max_runtime_minutes: float = _INV_DEFAULTS["max_runtime_minutes"]  # Wall-clock deadline
    max_total_artifacts: int = _INV_DEFAULTS["max_total_artifacts"]  # Cap on total artifacts
    max_parallel_workers: int = _INV_DEFAULTS["max_parallel_workers"]  # BFS-level concurrency


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


@dataclass
class ArtifactProcessResult:
    """Outcome of processing a single artifact.

    Produced entirely from network/subprocess work in a worker thread. It
    carries only *descriptions* of the DB mutations to perform; every actual
    SQLite write is applied later, serially, on the main thread. This keeps the
    single shared connection free of data races while the expensive I/O runs
    concurrently.
    """

    artifact: dict
    discovered: list[dict] = field(default_factory=list)
    # JSON metadata to UPDATE onto the source artifact row (None = leave as-is).
    source_metadata: Optional[str] = None
    # kwargs (minus artifact_id) for db.add_platform_presence.
    platform_presences: list[dict] = field(default_factory=list)


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

    # BFS loop: each depth "level" (all artifacts currently queued) is processed
    # concurrently. The expensive, I/O-bound work (_process_artifact: OSINT
    # modules + external tools + plugins) runs in a bounded ThreadPoolExecutor,
    # while every SQLite write is applied serially on this (main) thread after
    # the parallel phase returns -- the single shared connection is therefore
    # never touched from a worker thread and the `seen` dedup set is mutated
    # only here.
    start_time = time.monotonic()
    # Bound total concurrent outbound I/O across all nested pools, and reset the
    # per-run tool-analysis memoization so results aren't reused across runs.
    concurrency.configure()
    clear_tool_analysis_cache()
    runtime_budget_s = max(0.0, config.max_runtime_minutes * 60.0)
    max_total_artifacts = config.max_total_artifacts
    max_workers = max(1, config.max_parallel_workers)
    processed_count = 0
    level = 0

    while queue:
        # Enforce the overall wall-clock deadline at each level boundary.
        elapsed = time.monotonic() - start_time
        if runtime_budget_s and elapsed >= runtime_budget_s:
            logger.warning(
                "Runtime budget of %.1f min reached (%.1fs elapsed); stopping BFS "
                "with %d artifact(s) still queued",
                config.max_runtime_minutes, elapsed, len(queue),
            )
            break

        # Drain the current level.
        current_level = list(queue)
        queue.clear()
        level += 1
        level_start = time.monotonic()
        logger.info(
            "Processing BFS level %d: %d artifact(s) (elapsed=%.1fs, workers=%d)",
            level, len(current_level), elapsed, min(max_workers, len(current_level)),
        )

        # --- Parallel network/subprocess phase (NO DB writes) ---
        results: list[ArtifactProcessResult] = []
        with ThreadPoolExecutor(max_workers=min(max_workers, len(current_level))) as executor:
            futures = {
                executor.submit(_process_artifact, inv_id, item, config, plugin_manager): item
                for item in current_level
            }
            for future in as_completed(futures):
                item = futures[future]
                processed_count += 1
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.error(
                        "Error processing artifact %s=%s: %s",
                        item["type"], item["value"], e,
                    )
        parallel_s = time.monotonic() - level_start

        # --- Serial DB-write phase (main thread only) ---
        budget_reached = False
        for res in results:
            current = res.artifact
            current_depth = current["depth"]
            current_id = current["artifact_id"]

            # Persist analysis metadata for the source artifact.
            if res.source_metadata is not None:
                conn.execute(
                    "UPDATE artifacts SET metadata = ? WHERE artifact_id = ?",
                    (res.source_metadata, current_id),
                )

            # Persist platform presences discovered for this artifact.
            for presence in res.platform_presences:
                db.add_platform_presence(
                    conn, investigation_id=inv_id, artifact_id=current_id, **presence
                )

            # The metadata/presence writes above are unrelated to the artifact
            # count and must always be applied for every already-processed
            # result; only new-artifact expansion below is bounded by depth and
            # the budget, so we `continue` (not `break`) once either is hit.
            if current_depth >= config.max_depth or budget_reached:
                continue

            for artifact in res.discovered:
                key = f"{artifact['type']}:{artifact['value']}"
                if key in seen:
                    logger.debug("Skipping duplicate artifact: %s", key)
                    continue
                if len(seen) >= max_total_artifacts:
                    logger.warning(
                        "Artifact budget of %d reached; no further artifacts will be enqueued",
                        max_total_artifacts,
                    )
                    budget_reached = True
                    break
                seen.add(key)

                metadata_value = artifact.get("metadata")
                if metadata_value and isinstance(metadata_value, dict):
                    metadata_value = json.dumps(metadata_value)

                new_id = db.add_artifact(
                    conn,
                    investigation_id=inv_id,
                    artifact_type=artifact["type"],
                    value=artifact["value"],
                    source=artifact.get("source", "discovered"),
                    confidence=artifact.get("confidence", 0.8),
                    metadata=metadata_value,
                    depth=current_depth + 1,
                )
                db.add_link(
                    conn,
                    investigation_id=inv_id,
                    source_artifact=current_id,
                    target_artifact=new_id,
                    link_type=artifact.get("link_type", "discovered_from"),
                    confidence=artifact.get("confidence", 0.8),
                    evidence=artifact.get("source", ""),
                )
                # Store & link every discovery, but only re-queue expandable
                # types so leaf results don't drive further expensive tool runs.
                if artifact["type"] in EXPANDABLE_ARTIFACT_TYPES:
                    queue.append({
                        "artifact_id": new_id,
                        "type": artifact["type"],
                        "value": artifact["value"],
                        "depth": current_depth + 1,
                    })

        conn.commit()
        logger.info(
            "BFS level %d done in %.1fs (parallel=%.1fs, db=%.1fs); processed=%d, "
            "seen=%d, next_level=%d",
            level, time.monotonic() - level_start, parallel_s,
            time.monotonic() - level_start - parallel_s,
            processed_count, len(seen), len(queue),
        )
        if budget_reached:
            break

    logger.info(
        "BFS processing complete: %d artifact(s) processed across %d level(s) in %.1fs",
        processed_count, level, time.monotonic() - start_time,
    )
    
    # Finalize
    finalize_start = time.monotonic()
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
        "Investigation %s complete: %d artifacts, %d links, %d platforms, %d risk indicators "
        "(finalize/correlation=%.1fs, total=%.1fs)",
        inv_id, result.total_artifacts, result.total_links, result.total_platforms,
        len(result.risk_indicators),
        time.monotonic() - finalize_start, time.monotonic() - start_time,
    )
    return result


def _process_artifacts_generator(
    inv_id: str,
    artifacts: list[dict],
    config: InvestigationConfig,
    plugin_manager: PluginManager = None,
):
    """
    Process artifacts using a generator for memory efficiency.
    
    Yields discovered artifacts one at a time instead of building a large list.
    
    Args:
        inv_id: Investigation ID
        artifacts: List of artifacts to process
        config: Investigation configuration
        plugin_manager: Plugin manager instance
        
    Yields:
        Discovered artifacts one at a time
    """
    for artifact in artifacts:
        yield from _process_artifact(inv_id, artifact, config, plugin_manager).discovered


def _get_artifacts_stream(
    conn: sqlite3.Connection,
    inv_id: str,
    limit: Optional[int] = None,
):
    """
    Stream artifacts from database using a generator for memory efficiency.
    
    Args:
        conn: Database connection
        inv_id: Investigation ID
        limit: Optional limit on number of artifacts to stream
        
    Yields:
        Artifact records one at a time
    """
    query = """
        SELECT artifact_id, artifact_type, value, source, depth, metadata
        FROM artifacts
        WHERE investigation_id = ?
        ORDER BY depth, artifact_id
    """
    
    if limit:
        query += f" LIMIT {limit}"
    
    cursor = conn.execute(query, (inv_id,))
    for row in cursor:
        yield {
            "artifact_id": row[0],
            "type": row[1],
            "value": row[2],
            "source": row[3],
            "depth": row[4],
            "metadata": row[5],
        }


def _process_artifact(
    inv_id: str,
    artifact: dict,
    config: InvestigationConfig,
    plugin_manager: PluginManager = None,
) -> ArtifactProcessResult:
    """Process a single artifact through the appropriate OSINT module.

    Performs only network/subprocess work (no DB writes). The type-specific
    helpers populate ``result.source_metadata`` and ``result.platform_presences``
    with descriptions of the writes the main thread should later apply, and
    append any newly discovered artifacts to ``result.discovered``.
    """
    result = ArtifactProcessResult(artifact=artifact)
    artifact_type = artifact["type"]
    value = artifact["value"]

    logger.debug("Dispatching artifact to OSINT module: %s=%s", artifact_type, value)

    if artifact_type == "phone":
        logger.debug("Processing phone number with phone_osint module")
        _process_phone(value, config, result)
    elif artifact_type == "email":
        logger.debug("Processing email address with email_osint module")
        _process_email(value, config, result)
    elif artifact_type == "username":
        logger.debug("Processing username with username_search module")
        _process_username(value, config, result)
    elif artifact_type == "image":
        logger.debug("Processing image with image_search module")
        _process_image(value, config, result)
    elif artifact_type == "fullname":
        logger.debug("Processing full name with image_match module")
        _process_fullname(value, config, result)
    elif artifact_type == "platform_presence":
        logger.debug("Processing platform presence URL with plugin system")
        # Platform presence URLs are processed by plugins (e.g., profile image extraction)
        pass
    else:
        logger.warning("Unknown artifact type: %s", artifact_type)

    logger.debug("OSINT module returned %d discovered artifacts", len(result.discovered))
    
    # Process with external OSINT tools if enabled
    if config.check_external_tools:
        logger.debug("Processing artifact with external OSINT tools")
        external_discovered = _process_external_tools(inv_id, artifact, config)
        result.discovered.extend(external_discovered)
        logger.debug("External tools returned %d additional artifacts", len(external_discovered))
    
    # Process with plugin system if available
    if plugin_manager:
        logger.debug("Processing artifact with plugin system")
        plugin_discovered = _process_with_plugins(artifact, config, plugin_manager)
        result.discovered.extend(plugin_discovered)
        logger.debug("Plugin system returned %d additional artifacts", len(plugin_discovered))
    
    return result


def _process_phone(
    value: str,
    config: InvestigationConfig,
    result: ArtifactProcessResult,
) -> None:
    """Process a phone number artifact (network only; DB writes deferred)."""
    try:
        logger.debug("Analyzing phone number: %s", value)
        analysis = phone_osint.analyze_phone(value)

        logger.debug("Phone analysis complete: valid=%s, carrier=%s, line_type=%s", 
                    analysis.valid, analysis.carrier_name, analysis.line_type)

        # Defer metadata write to the main thread.
        result.source_metadata = analysis.to_json()

        # Extract discovered artifacts
        phone_artifacts = phone_osint.get_discovered_artifacts(analysis)
        result.discovered.extend(phone_artifacts)
        logger.debug("Extracted %d artifacts from phone analysis", len(phone_artifacts))

        # Add risk indicators
        if analysis.risk_indicators:
            logger.debug("Found %d phone risk indicators: %s", 
                        len(analysis.risk_indicators), ", ".join(analysis.risk_indicators))
            for indicator in analysis.risk_indicators:
                result.discovered.append({
                    "type": "risk_indicator",
                    "value": indicator,
                    "source": "phone_osint",
                    "confidence": 0.9,
                    "link_type": "has_risk",
                })

    except Exception as e:
        logger.error("Phone OSINT failed for %s: %s", value, e)


def _process_email(
    value: str,
    config: InvestigationConfig,
    result: ArtifactProcessResult,
) -> None:
    """Process an email artifact (network only; DB writes deferred)."""
    try:
        logger.debug("Analyzing email address: %s", value)
        analysis = email_osint.analyze_email(value)

        logger.debug("Email analysis complete: valid=%s, disposable=%s, domain=%s", 
                    analysis.valid_format, analysis.is_disposable, analysis.domain)

        # Defer metadata write to the main thread.
        result.source_metadata = analysis.to_json()

        # Queue platform presences for the main thread to persist.
        if analysis.platforms_found:
            logger.debug("Recording %d platform presences for email %s", 
                        len(analysis.platforms_found), value)
            for platform in analysis.platforms_found:
                result.platform_presences.append({
                    "platform_name": platform.get("platform", "unknown"),
                    "profile_url": platform.get("profile_url"),
                    "username": platform.get("username"),
                })

        # Extract discovered artifacts
        email_artifacts = email_osint.get_discovered_artifacts(analysis)
        result.discovered.extend(email_artifacts)
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
            result.discovered.extend(breach_artifacts)

        # Try username from email local part
        local_part = value.split("@")[0]
        if config.search_usernames and len(local_part) >= 3:
            logger.debug("Extracted username from email local part: %s", local_part)
            result.discovered.append({
                "type": "username",
                "value": local_part,
                "source": "email_local_part",
                "confidence": 0.5,
                "link_type": "possible_username",
            })

    except Exception as e:
        logger.error("Email OSINT failed for %s: %s", value, e)


def _process_username(
    value: str,
    config: InvestigationConfig,
    result: ArtifactProcessResult,
) -> None:
    """Process a username artifact (network only; DB writes deferred)."""
    try:
        if not config.search_usernames:
            return

        search_result = username_search.search_username(value)

        # Defer metadata write to the main thread.
        result.source_metadata = search_result.to_json()

        # Queue platform presences for the main thread to persist.
        for platform in search_result.platforms_found:
            result.platform_presences.append({
                "platform_name": platform.platform_name,
                "profile_url": platform.profile_url,
                "username": platform.username,
                "display_name": platform.display_name,
                "bio": platform.bio,
                "follower_count": platform.follower_count,
            })

        # Extract platform presences as new artifacts
        result.discovered.extend(username_search.get_discovered_artifacts(search_result))

    except Exception as e:
        logger.error("Username search failed for %s: %s", value, e)


def _process_fullname(
    value: str,
    config: InvestigationConfig,
    result: ArtifactProcessResult,
) -> None:
    """Process a full name artifact using image matching (DB writes deferred)."""
    try:
        logger.debug("Processing full name with image matching: %s", value)
        
        # Search and match identity
        match_result = image_match.search_and_match_identity(
            full_name=value,
            max_results=20
        )
        
        # Defer metadata write to the main thread.
        result.source_metadata = json.dumps(match_result.to_dict())
        
        logger.info(
            "Image match complete for %s: %d images, %d face matches, probability=%.2f",
            value, len(match_result.images), len(match_result.face_matches), match_result.overall_probability
        )
        
        # Extract discovered artifacts
        result.discovered.extend(image_match.get_discovered_artifacts(match_result))
        
        # Add high-probability face matches as identity artifacts
        for match in match_result.face_matches:
            if match.match_probability > 0.7:
                result.discovered.append({
                    "type": "identity_match",
                    "value": match.image_url,
                    "source": f"face_match_{match.source.lower().replace(' ', '_')}",
                    "confidence": match.match_probability,
                    "metadata": json.dumps(match.to_dict()),
                    "link_type": "identity_verification",
                })
        
        # Add overall probability as a risk/quality indicator
        if match_result.overall_probability > 0.8:
            result.discovered.append({
                "type": "identity_confidence",
                "value": f"high_confidence_{match_result.overall_probability:.2f}",
                "source": "image_match",
                "confidence": match_result.overall_probability,
                "metadata": json.dumps({"sources": match_result.confidence_sources}),
                "link_type": "identity_quality",
            })
    
    except Exception as e:
        logger.error("Image match failed for %s: %s", value, e)


def _process_external_tools(
    inv_id: str,
    artifact: dict,
    config: InvestigationConfig,
) -> list[dict]:
    """Process artifact using external OSINT tools when available.

    The independent tool calls for an artifact are dispatched concurrently and
    their discovered artifacts aggregated, so a run's latency is bounded by the
    slowest tool rather than the sum of them. No DB writes happen here.
    """
    discovered: list[dict] = []
    artifact_type = artifact["type"]
    value = artifact["value"]

    if not config.check_external_tools:
        return discovered

    logger.debug("Processing artifact with external OSINT tools: %s=%s", artifact_type, value)

    # Build a list of independent (name, callable) tool tasks for this artifact.
    # Each callable performs one tool run and returns a list of discovered
    # artifacts; they are executed concurrently below.
    tasks: list[tuple[str, Any]] = []

    def _tool_task(tool: str, analysis: str, label: str):
        def _run() -> list[dict]:
            logger.debug("Running %s (%s) for: %s", tool, analysis, value)
            res = run_tool_analysis(tool, analysis, value)
            if res.success and res.artifacts_discovered:
                logger.info("%s found %d artifacts for %s",
                            label, len(res.artifacts_discovered), value)
                return res.artifacts_discovered
            logger.debug("%s skipped or found nothing for %s", label, value)
            return []
        return _run

    try:
        if artifact_type == "username":
            if check_tool_availability("sherlock"):
                tasks.append(("sherlock", _tool_task("sherlock", "username_search", "Sherlock")))

            if check_google_dorks_availability(config.google_api_key):
                def _google_dorks() -> list[dict]:
                    logger.debug("Running Google Dorks search for: %s", value)
                    res = run_google_dorks_search(
                        username=value,
                        api_key=config.google_api_key,
                        cx=config.google_cx,
                        use_api=config.use_google_api,
                        search_engine=config.search_engine,
                    )
                    if res:
                        logger.info("Google Dorks found %d artifacts for username %s",
                                    len(res), value)
                        return res
                    logger.debug("Google Dorks found no results for %s", value)
                    return []
                tasks.append(("google_dorks", _google_dorks))

        elif artifact_type == "domain":
            if check_tool_availability("theharvester"):
                tasks.append(("theharvester_email",
                              _tool_task("theharvester", "email_harvest", "theHarvester (email)")))
                tasks.append(("theharvester_subdomain",
                              _tool_task("theharvester", "subdomain_harvest", "theHarvester (subdomain)")))
            if check_tool_availability("amass"):
                tasks.append(("amass", _tool_task("amass", "subdomain_enum", "Amass")))
            if check_tool_availability("whois"):
                tasks.append(("whois", _tool_task("whois", "domain_lookup", "Whois")))
            if check_tool_availability("dig"):
                tasks.append(("dig", _tool_task("dig", "dns_lookup", "Dig")))
            # Wayback Machine uses a public API and runs regardless of local tools.
            tasks.append(("wayback_machine",
                          _tool_task("wayback_machine", "historical_urls", "Wayback Machine")))

        elif artifact_type == "ip_address":
            if check_tool_availability("shodan"):
                tasks.append(("shodan", _tool_task("shodan", "host_search", "Shodan")))
            if check_tool_availability("nmap"):
                tasks.append(("nmap", _tool_task("nmap", "host_scan", "Nmap")))

        elif artifact_type == "image":
            if check_tool_availability("exiftool"):
                tasks.append(("exiftool", _tool_task("exiftool", "metadata_extract", "ExifTool")))

        elif artifact_type == "email":
            # Extract domain from email for domain-based analysis (no tool run).
            if "@" in value:
                domain = value.split("@")[1]
                discovered.append({
                    "type": "domain",
                    "value": domain,
                    "source": "email_domain_extraction",
                    "confidence": 0.7,
                    "link_type": "domain_of_email",
                })
                logger.debug("Extracted domain from email: %s", domain)

        discovered.extend(_run_external_tool_tasks(tasks))

    except Exception as e:
        logger.error("External tools processing failed for %s: %s", value, e)

    return discovered


def _run_external_tool_tasks(tasks: "list[tuple[str, Any]]") -> list[dict]:
    """Run independent external-tool callables concurrently and aggregate results.

    Sherlock, Google Dorks, theHarvester, Amass, Whois, Dig, Wayback, etc. for a
    single artifact are independent, so running them in parallel bounds latency
    by the slowest tool instead of their sum.
    """
    aggregated: list[dict] = []
    if not tasks:
        return aggregated

    if len(tasks) == 1:
        name, fn = tasks[0]
        try:
            aggregated.extend(fn() or [])
        except Exception as e:
            logger.error("External tool %s failed: %s", name, e)
        return aggregated

    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks}
        for future in as_completed(futures):
            name = futures[future]
            try:
                aggregated.extend(future.result() or [])
            except Exception as e:
                logger.error("External tool %s failed: %s", name, e)
    return aggregated


def _process_with_plugins(
    artifact: dict,
    config: InvestigationConfig,
    plugin_manager: PluginManager,
) -> list[dict]:
    """Process artifact using the plugin system (network only; no DB writes)."""
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
    value: str,
    config: InvestigationConfig,
    result: ArtifactProcessResult,
) -> None:
    """Process an image artifact (network only; DB writes deferred)."""
    try:
        if not config.check_images:
            return

        analysis = image_search.analyze_image(value)

        # Defer metadata write to the main thread.
        result.source_metadata = analysis.to_json()

        # Extract discovered artifacts
        result.discovered.extend(image_search.get_discovered_artifacts(analysis))

    except Exception as e:
        logger.error("Image analysis failed for %s: %s", value, e)

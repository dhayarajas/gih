"""
Ghost Identity Hunter - SQLite Database Layer

PURPOSE:
--------
This module provides the SQLite database abstraction layer for Ghost Identity Hunter,
handling all data persistence operations including investigations, artifacts, links,
and platform presence records with forensic-grade integrity guarantees.

FUNCTIONALITY:
--------------
- SQLite database connection management with WAL mode for concurrency
- Database schema initialization and migration
- Investigation lifecycle management (create, update, complete, list)
- Artifact storage with metadata and confidence scoring
- Relationship linking between artifacts with evidence provenance
- Platform presence tracking across social media and services
- Database integrity verification with SHA-256 hashing

SCHEMA DESIGN:
-------------
- investigations: Investigation metadata and status tracking
- artifacts: Individual identity fragments (phones, emails, usernames, images)
- artifact_links: Directed relationships between artifacts with confidence scores
- platform_presence: Social media and service account records
- investigation_metadata: Key-value storage for analysis results

INTEGRITY FEATURES:
------------------
- Foreign key constraints enforced
- Unique constraints prevent duplicate artifacts per investigation
- SHA-256 hash verification for tamper detection
- Audit trail with ISO 8601 timestamps
- WAL mode for concurrent access and crash recovery

USAGE EXAMPLES:
--------------
# Get database connection
conn = get_connection(Path("/path/to/investigations.db"))

# Create new investigation
inv_id = create_investigation(conn, title="Email Investigation")

# Add artifact with metadata
artifact_id = add_artifact(conn, inv_id, "email", "user@example.com", 
                          source="seed", confidence=1.0, metadata=json.dumps(meta))

# Link artifacts with evidence
link_id = add_link(conn, inv_id, source_id, target_id, "registered_with", 
                   confidence=0.9, evidence="HIBP breach data")

DEPENDENCIES:
-------------
- sqlite3: Standard library database engine
- uuid: Unique ID generation for investigations and artifacts
- datetime: ISO 8601 timestamp generation
- pathlib: Cross-platform path handling

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".ghost_hunter" / "investigations.db"


def _config_base_dir(config_path: Path) -> Path:
    """Directory a relative configured path is anchored to.

    The project root when the config lives in a ``config/`` subdirectory,
    otherwise the directory holding the config file.
    """
    parent = config_path.expanduser().absolute().parent
    return parent.parent if parent.name == "config" else parent


def resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the database location.

    Precedence: an explicit path (the ``--db`` option), then ``database.path``
    from the loaded configuration, then :data:`DEFAULT_DB_PATH`. A configured
    path is expanded for ``~`` and environment variables; a relative one is
    anchored to the config file's project directory, not the process CWD.
    """
    if db_path:
        return Path(os.path.expandvars(str(db_path))).expanduser()

    try:
        from src.config.loader import get_config
        config = get_config()
        configured = (config.get("database") or {}).get("path")
        if configured:
            path = Path(os.path.expandvars(str(configured))).expanduser()
            if not path.is_absolute():
                path = _config_base_dir(config.config_path) / path
            return path
    except Exception as exc:
        logger.debug("Could not read database.path from config: %s", exc)

    return DEFAULT_DB_PATH


def get_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """Get a database connection, creating the DB file and schema if needed."""
    path = resolve_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    """Initialize database schema."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            title TEXT,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'in_progress'
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            artifact_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT,
            confidence REAL DEFAULT 1.0,
            metadata TEXT,
            discovered_at TEXT NOT NULL,
            depth INTEGER DEFAULT 0,
            FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
        );

        CREATE INDEX IF NOT EXISTS idx_artifacts_type_value
            ON artifacts(artifact_type, value);
        CREATE INDEX IF NOT EXISTS idx_artifacts_investigation
            ON artifacts(investigation_id);

        CREATE TABLE IF NOT EXISTS artifact_links (
            link_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            source_artifact TEXT NOT NULL,
            target_artifact TEXT NOT NULL,
            link_type TEXT,
            confidence REAL DEFAULT 1.0,
            evidence TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id),
            FOREIGN KEY (source_artifact) REFERENCES artifacts(artifact_id),
            FOREIGN KEY (target_artifact) REFERENCES artifacts(artifact_id)
        );

        CREATE INDEX IF NOT EXISTS idx_links_investigation
            ON artifact_links(investigation_id);

        CREATE TABLE IF NOT EXISTS platform_presence (
            presence_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            artifact_id TEXT,
            platform_name TEXT NOT NULL,
            profile_url TEXT,
            username TEXT,
            display_name TEXT,
            bio TEXT,
            profile_image_url TEXT,
            account_created TEXT,
            last_active TEXT,
            follower_count INTEGER,
            is_verified INTEGER DEFAULT 0,
            FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id),
            FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
        );

        CREATE INDEX IF NOT EXISTS idx_presence_platform
            ON platform_presence(platform_name, username);

        CREATE TABLE IF NOT EXISTS investigation_metadata (
            metadata_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
        );

        CREATE INDEX IF NOT EXISTS idx_metadata_investigation_key
            ON investigation_metadata(investigation_id, key);

        CREATE TABLE IF NOT EXISTS audit_trail (
            audit_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id TEXT,
            details TEXT,
            performed_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
        );

        CREATE INDEX IF NOT EXISTS idx_audit_investigation
            ON audit_trail(investigation_id, performed_at);

        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            operation TEXT,
            target TEXT,
            command TEXT,
            tool_version TEXT,
            captured_at TEXT NOT NULL,
            duration_seconds REAL,
            exit_status TEXT,
            sha256 TEXT NOT NULL,
            byte_size INTEGER NOT NULL,
            stored_path TEXT NOT NULL,
            truncated INTEGER DEFAULT 0,
            FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_investigation
            ON evidence(investigation_id, captured_at);

        -- Place names resolved to coordinates for the report map. Cached across
        -- investigations because the answer does not change and the geocoder
        -- is rate-limited; a miss is cached too, so it is asked once.
        CREATE TABLE IF NOT EXISTS geocode_cache (
            place TEXT PRIMARY KEY,
            latitude REAL,
            longitude REAL,
            display_name TEXT,
            resolved_at TEXT NOT NULL
        );
    """)
    _add_missing_columns(conn, "evidence", {"tool_version": "TEXT"})
    conn.commit()


def _add_missing_columns(
    conn: sqlite3.Connection, table: str, columns: dict[str, str]
) -> None:
    """Add columns a newer schema expects to a database created by an older one."""
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, decl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def generate_id() -> str:
    """Generate a unique ID."""
    return str(uuid.uuid4())[:8]


def create_investigation(
    conn: sqlite3.Connection,
    title: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Create a new investigation and return its ID."""
    inv_id = f"INV-{generate_id()}"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO investigations (investigation_id, created_at, title, description, status) "
        "VALUES (?, ?, ?, ?, ?)",
        (inv_id, now, title or f"Investigation {inv_id}", description, "in_progress"),
    )
    conn.commit()
    return inv_id


def complete_investigation(conn: sqlite3.Connection, investigation_id: str) -> None:
    """Mark investigation as completed."""
    conn.execute(
        "UPDATE investigations SET status = 'completed' WHERE investigation_id = ?",
        (investigation_id,),
    )
    conn.commit()


def get_investigation(conn: sqlite3.Connection, investigation_id: str) -> Optional[dict]:
    """Get investigation details."""
    row = conn.execute(
        "SELECT * FROM investigations WHERE investigation_id = ?",
        (investigation_id,),
    ).fetchone()
    return dict(row) if row else None


def list_investigations(conn: sqlite3.Connection) -> list[dict]:
    """List all investigations."""
    rows = conn.execute(
        "SELECT * FROM investigations ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def add_artifact(
    conn: sqlite3.Connection,
    investigation_id: str,
    artifact_type: str,
    value: str,
    source: Optional[str] = None,
    confidence: float = 1.0,
    metadata: Optional[str] = None,
    depth: int = 0,
) -> str:
    """Add an artifact to an investigation. Returns artifact_id."""
    # Check if artifact already exists for this investigation
    existing = conn.execute(
        "SELECT artifact_id FROM artifacts "
        "WHERE investigation_id = ? AND artifact_type = ? AND value = ?",
        (investigation_id, artifact_type, value),
    ).fetchone()
    if existing:
        return existing["artifact_id"]

    artifact_id = f"ART-{generate_id()}"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO artifacts "
        "(artifact_id, investigation_id, artifact_type, value, source, confidence, metadata, discovered_at, depth) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (artifact_id, investigation_id, artifact_type, value, source, confidence, metadata, now, depth),
    )
    conn.commit()
    return artifact_id


def add_artifacts_bulk(
    conn: sqlite3.Connection,
    investigation_id: str,
    artifacts: list[dict],
) -> list[str]:
    """
    Add multiple artifacts in a single transaction for better performance.
    
    Args:
        conn: Database connection
        investigation_id: Investigation ID
        artifacts: List of artifact dicts with keys: type, value, source, confidence, metadata, depth
    
    Returns:
        List of artifact IDs
    """
    artifact_ids = []
    now = datetime.now(timezone.utc).isoformat()
    
    # Start transaction
    conn.execute("BEGIN TRANSACTION")
    
    try:
        for artifact in artifacts:
            # Check if artifact already exists
            existing = conn.execute(
                "SELECT artifact_id FROM artifacts "
                "WHERE investigation_id = ? AND artifact_type = ? AND value = ?",
                (investigation_id, artifact["type"], artifact["value"]),
            ).fetchone()
            
            if existing:
                artifact_ids.append(existing["artifact_id"])
            else:
                artifact_id = f"ART-{generate_id()}"
                conn.execute(
                    "INSERT INTO artifacts "
                    "(artifact_id, investigation_id, artifact_type, value, source, confidence, metadata, discovered_at, depth) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        artifact_id,
                        investigation_id,
                        artifact["type"],
                        artifact["value"],
                        artifact.get("source"),
                        artifact.get("confidence", 1.0),
                        artifact.get("metadata"),
                        now,
                        artifact.get("depth", 0),
                    ),
                )
                artifact_ids.append(artifact_id)
        
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    
    return artifact_ids


def get_artifacts(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    """Get all artifacts for an investigation."""
    rows = conn.execute(
        "SELECT * FROM artifacts WHERE investigation_id = ? ORDER BY discovered_at",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def add_link(
    conn: sqlite3.Connection,
    investigation_id: str,
    source_artifact: str,
    target_artifact: str,
    link_type: str,
    confidence: float = 1.0,
    evidence: Optional[str] = None,
) -> str:
    """Add a link between two artifacts."""
    # Check if link already exists
    existing = conn.execute(
        "SELECT link_id FROM artifact_links "
        "WHERE investigation_id = ? AND source_artifact = ? AND target_artifact = ?",
        (investigation_id, source_artifact, target_artifact),
    ).fetchone()
    if existing:
        return existing["link_id"]

    link_id = f"LNK-{generate_id()}"
    conn.execute(
        "INSERT INTO artifact_links "
        "(link_id, investigation_id, source_artifact, target_artifact, link_type, confidence, evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (link_id, investigation_id, source_artifact, target_artifact, link_type, confidence, evidence),
    )
    conn.commit()
    return link_id


def get_links(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    """Get all links for an investigation."""
    rows = conn.execute(
        "SELECT * FROM artifact_links WHERE investigation_id = ?",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def add_platform_presence(
    conn: sqlite3.Connection,
    investigation_id: str,
    platform_name: Optional[str] = None,
    profile_url: Optional[str] = None,
    username: Optional[str] = None,
    display_name: Optional[str] = None,
    bio: Optional[str] = None,
    follower_count: Optional[int] = None,
    profile_image_url: Optional[str] = None,
    artifact_id: Optional[str] = None,
    is_verified: bool = False,
) -> str:
    """Record platform presence.

    ``is_verified`` marks presences whose existence was proven by content/API
    validation rather than a bare HTTP status code.
    """
    presence_id = f"PRS-{generate_id()}"
    conn.execute(
        "INSERT INTO platform_presence "
        "(presence_id, investigation_id, artifact_id, platform_name, profile_url, "
        "username, display_name, bio, follower_count, profile_image_url, is_verified) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (presence_id, investigation_id, artifact_id, platform_name, profile_url,
         username, display_name, bio, follower_count, profile_image_url,
         1 if is_verified else 0),
    )
    conn.commit()
    return presence_id


def get_platform_presences(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    """Get all platform presences for an investigation."""
    rows = conn.execute(
        "SELECT * FROM platform_presence WHERE investigation_id = ?",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def add_audit_log(
    conn: sqlite3.Connection,
    investigation_id: str,
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    details: Optional[str] = None,
) -> str:
    """Add an audit log entry for an investigation."""
    audit_id = f"AUD-{generate_id()}"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO audit_trail "
        "(audit_id, investigation_id, action, entity_type, entity_id, details, performed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (audit_id, investigation_id, action, entity_type, entity_id, details, now),
    )
    conn.commit()
    return audit_id


def add_evidence(conn: sqlite3.Connection, capture) -> str:
    """Record one preserved tool output (see src.storage.evidence)."""
    evidence_id = f"EVD-{generate_id()}"
    conn.execute(
        "INSERT INTO evidence "
        "(evidence_id, investigation_id, tool, operation, target, command, tool_version, "
        "captured_at, duration_seconds, exit_status, sha256, byte_size, stored_path, truncated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (evidence_id, capture.investigation_id, capture.tool, capture.operation,
         capture.target, capture.command, getattr(capture, "tool_version", None),
         capture.captured_at, capture.duration_seconds,
         capture.exit_status, capture.sha256, capture.byte_size, capture.stored_path,
         1 if capture.truncated else 0),
    )
    conn.commit()
    return evidence_id


def get_evidence(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    """Get preserved tool outputs for an investigation, oldest first."""
    rows = conn.execute(
        "SELECT * FROM evidence WHERE investigation_id = ? ORDER BY captured_at",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_audit_trail(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    """Get audit trail for an investigation."""
    rows = conn.execute(
        "SELECT * FROM audit_trail WHERE investigation_id = ? ORDER BY performed_at DESC",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]

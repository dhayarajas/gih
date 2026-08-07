"""Content-addressed preservation of the raw output every tool produced.

An investigation records what a tool *concluded* -- an artifact, a link, a
confidence -- but not what it actually returned. Once the target changes a
profile or a DNS record, nothing in the case can show what the tool saw at
collection time, which is exactly what the legal report template asserts.

Every subprocess and HTTP response is therefore written verbatim to a file
named after the SHA-256 of its bytes, and a row recording the command, the
timestamps and that digest is stored alongside the investigation. Re-hashing
the file later proves the capture has not been altered.

Captures happen on worker threads, so they are buffered in memory and flushed
to SQLite from the orchestrator's main thread, which owns the connection.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_EVIDENCE_DIR = Path.home() / ".ghost_hunter" / "evidence"

# Captures above this size are truncated: a runaway tool must not fill the
# disk, and the truncation is recorded so the digest is still explainable.
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
TRUNCATION_NOTICE = "\n\n[capture truncated at {limit} bytes]\n"

# A capture holds the rawest material in the case -- whois registrants, page
# bodies, breach-adjacent output -- so it is readable by its owner only, rather
# than by whatever the process umask happens to allow.
DIR_MODE = 0o700
FILE_MODE = 0o600


@dataclass
class EvidenceCapture:
    """One preserved tool output, before it reaches the database."""

    investigation_id: str
    tool: str
    operation: Optional[str]
    target: Optional[str]
    command: Optional[str]
    captured_at: str
    duration_seconds: float
    exit_status: str
    sha256: str
    byte_size: int
    stored_path: str
    truncated: bool = False


@dataclass
class _CaptureSession:
    investigation_id: str
    root: Path
    captures: list[EvidenceCapture] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


_session: Optional[_CaptureSession] = None
_session_lock = threading.Lock()

# What the current thread is analysing, so a capture taken deep inside a tool
# integration can be labelled with the operation and target that asked for it.
_local = threading.local()


class analysing:
    """Context manager labelling every capture made on this thread."""

    def __init__(self, operation: Optional[str], target: Optional[str]):
        self._scope = (operation, target)
        self._previous: tuple = (None, None)

    def __enter__(self) -> "analysing":
        self._previous = getattr(_local, "scope", (None, None))
        _local.scope = self._scope
        return self

    def __exit__(self, *exc_info) -> None:
        _local.scope = self._previous


def _restrict(path: Path, mode: int) -> None:
    """Narrow a capture path to its owner; harmless where chmod does nothing."""
    try:
        path.chmod(mode)
    except (OSError, NotImplementedError) as exc:
        logger.debug("Could not restrict permissions on %s: %s", path, exc)


def evidence_root() -> Path:
    """Resolve the capture directory from config, falling back to the default."""
    try:
        from src.config.loader import get_config
        configured = ((get_config().get("evidence") or {}).get("directory"))
        if configured:
            return Path(configured).expanduser()
    except Exception:
        pass
    return DEFAULT_EVIDENCE_DIR


def is_enabled() -> bool:
    """Whether evidence preservation is switched on in config (default: yes)."""
    try:
        from src.config.loader import get_config
        return bool((get_config().get("evidence") or {}).get("enabled", True))
    except Exception:
        return True


def begin(investigation_id: str) -> None:
    """Start capturing for an investigation; a no-op when disabled."""
    global _session
    with _session_lock:
        _session = None
        if not is_enabled():
            logger.debug("Evidence preservation disabled by config")
            return
        root = evidence_root() / investigation_id
        try:
            root.mkdir(parents=True, exist_ok=True)
            _restrict(root, DIR_MODE)
        except OSError as exc:
            logger.warning("Evidence directory %s unusable, captures disabled: %s", root, exc)
            return
        _session = _CaptureSession(investigation_id=investigation_id, root=root)


def end() -> None:
    """Stop capturing. Pending captures that were never flushed are dropped."""
    global _session
    with _session_lock:
        _session = None


def record(
    tool: str,
    output: str,
    *,
    operation: Optional[str] = None,
    target: Optional[str] = None,
    command: Optional[str] = None,
    duration_seconds: float = 0.0,
    exit_status: str = "unknown",
) -> Optional[EvidenceCapture]:
    """Preserve one tool output. Returns the capture, or None when inactive.

    Safe to call from any thread and from code paths that have no investigation
    in progress (unit tests, plugin dry-runs): both are silent no-ops.
    """
    with _session_lock:
        session = _session
    if session is None or output is None:
        return None

    scoped_operation, scoped_target = getattr(_local, "scope", (None, None))
    operation = operation or scoped_operation
    target = target or scoped_target

    body = output
    truncated = False
    if len(body.encode("utf-8", "replace")) > MAX_CAPTURE_BYTES:
        body = body.encode("utf-8", "replace")[:MAX_CAPTURE_BYTES].decode("utf-8", "ignore")
        body += TRUNCATION_NOTICE.format(limit=MAX_CAPTURE_BYTES)
        truncated = True

    payload = body.encode("utf-8", "replace")
    digest = hashlib.sha256(payload).hexdigest()
    path = session.root / f"{digest}.txt"
    try:
        if not path.exists():
            # Identical output from a re-run is the same evidence; the digest
            # already proves that, so the file is written once.
            path.write_bytes(payload)
            _restrict(path, FILE_MODE)
    except OSError as exc:
        logger.warning("Could not preserve %s output: %s", tool, exc)
        return None

    capture = EvidenceCapture(
        investigation_id=session.investigation_id,
        tool=tool,
        operation=operation,
        target=target,
        command=command,
        captured_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=round(duration_seconds, 3),
        exit_status=exit_status,
        sha256=digest,
        byte_size=len(payload),
        stored_path=str(path),
        truncated=truncated,
    )
    with session.lock:
        session.captures.append(capture)
    return capture


def flush(conn) -> int:
    """Write buffered captures to the database. Returns the number stored."""
    with _session_lock:
        session = _session
    if session is None:
        return 0
    with session.lock:
        pending = session.captures
        session.captures = []
    if not pending:
        return 0

    from src.storage import database as db

    stored = 0
    for capture in pending:
        try:
            db.add_evidence(conn, capture)
            stored += 1
        except Exception as exc:
            logger.warning("Could not record evidence for %s: %s", capture.tool, exc)
    return stored


def verify(rows: list[dict]) -> list[dict]:
    """Re-hash every stored capture and report whether it still matches.

    Each returned row carries a ``status`` of ``verified``, ``modified`` or
    ``missing`` -- the three outcomes a chain-of-custody check can have.
    """
    verified = []
    for row in rows:
        item = dict(row)
        path = Path(item.get("stored_path") or "")
        if not path.is_file():
            item["status"] = "missing"
            item["actual_sha256"] = None
        else:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            item["actual_sha256"] = actual
            item["status"] = "verified" if actual == item.get("sha256") else "modified"
        verified.append(item)
    return verified

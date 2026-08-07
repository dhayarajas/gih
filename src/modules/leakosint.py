"""
LeakOSINT API integration.

LeakOSINT (https://leakosintapi.com/) is a paid breach-data search: one POST
returns the leaked databases a query appears in, each with its own record
schema. Without a token the API cannot be reached at all, so every entry point
here degrades to "unavailable" rather than raising -- an investigation must run
unchanged when the key is absent.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

LEAKOSINT_URL = "https://leakosintapi.com/"
DEFAULT_LIMIT = 100
DEFAULT_LANG = "en"
DEFAULT_TIMEOUT = 20
# The API allows one request per second per token; a shared clock keeps the
# parallel BFS workers from tripping it.
MIN_REQUEST_INTERVAL = 1.0

_rate_lock = threading.Lock()
_last_request_at = 0.0


@dataclass
class LeakRecord:
    """One row of one leaked database."""

    database: str
    fields: Dict[str, Any] = field(default_factory=dict)
    info: str = ""

    @property
    def summary(self) -> str:
        """Caption identifying the record within its database.

        Several significant values are joined rather than just the first: one
        database routinely holds many rows for the same email (one per leaked
        password), and an artifact value that repeated would be deduplicated on
        persistence, dropping every row but the first.
        """
        preferred = [
            str(self.fields[key])
            for key in ("Email", "email", "Phone", "phone", "NickName", "FullName", "Name")
            if self.fields.get(key)
        ]
        rest = [
            str(value)
            for key, value in self.fields.items()
            if value and key not in ("Email", "email", "Phone", "phone", "NickName", "FullName", "Name")
        ]
        return " / ".join((preferred + rest)[:3])


@dataclass
class LeakOsintResult:
    """Outcome of a LeakOSINT query."""

    query: str
    success: bool
    records: List[LeakRecord] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


def _plugin_config() -> Dict[str, Any]:
    try:
        from src.config.loader import get_config
        return ((get_config().get("plugins", {}) or {}).get("leakosint") or {})
    except Exception as exc:
        logger.debug("LeakOSINT config lookup failed: %s", exc)
        return {}


def get_settings() -> Dict[str, Any]:
    """Resolve the tool's settings from ``plugins.leakosint`` in config.yaml.

    The plugin manager keys its own config off the plugin class name, so the
    per-tool block is read here to keep the tool's settings where the other
    tools' settings live.
    """
    cfg = _plugin_config()
    params = cfg.get("custom_params") or {}
    def _int(value, fallback: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return fallback
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "limit": _int(params.get("limit"), DEFAULT_LIMIT),
        "lang": str(params.get("lang") or DEFAULT_LANG),
        "timeout": _int(cfg.get("timeout"), DEFAULT_TIMEOUT),
    }


def get_api_token() -> Optional[str]:
    """Resolve the API token from config or environment.

    ``plugins.leakosint.api_key`` wins so an investigation can be pinned to a
    specific token; otherwise the environment variable the upstream CLI uses is
    honored, plus the ``_API_KEY`` spelling for consistency with the other
    keyed tools.
    """
    configured = _plugin_config().get("api_key")
    if configured and str(configured).strip():
        return str(configured).strip()

    for name in ("LEAKOSINT_API_TOKEN", "LEAKOSINT_API_KEY"):
        token = os.environ.get(name)
        if token and token.strip():
            return token.strip()
    return None


def is_configured() -> bool:
    """Whether a token is available, i.e. whether the API can be queried."""
    return get_api_token() is not None


def _throttle() -> None:
    global _last_request_at
    with _rate_lock:
        wait = MIN_REQUEST_INTERVAL - (time.monotonic() - _last_request_at)
        if wait > 0:
            time.sleep(wait)
        _last_request_at = time.monotonic()


def _parse_databases(payload: Dict[str, Any]) -> List[LeakRecord]:
    """Flatten the API's ``List`` mapping into records.

    Shape is ``{"List": {"<db name>": {"InfoLeak": str, "Data": [ {...} ]}}}``,
    and a miss is reported as the literal database name "No results found".
    """
    records: List[LeakRecord] = []
    databases = payload.get("List")
    if not isinstance(databases, dict):
        return records

    for name, body in databases.items():
        if name == "No results found" or not isinstance(body, dict):
            continue
        info = str(body.get("InfoLeak") or "")
        for entry in body.get("Data") or []:
            if isinstance(entry, dict):
                records.append(LeakRecord(database=str(name), fields=dict(entry), info=info))
    return records


def search(
    query: str,
    limit: int = DEFAULT_LIMIT,
    lang: str = DEFAULT_LANG,
    timeout: int = DEFAULT_TIMEOUT,
) -> LeakOsintResult:
    """Query LeakOSINT for ``query``, never raising.

    Every failure mode the API exhibits -- missing token, non-JSON body, an
    ``Error code`` field with HTTP 200, a 502, a timeout -- comes back as an
    unsuccessful result so the caller can ignore it and continue.
    """
    token = get_api_token()
    if not token:
        return LeakOsintResult(query=query, success=False, error="LeakOSINT API token not configured")

    payload = {
        "token": token,
        "request": query.strip(),
        "limit": limit,
        "lang": lang,
        "type": "json",
    }

    try:
        from src.utils.http_client import get_http_session
        session = get_http_session()
        _throttle()
        response = session.post(LEAKOSINT_URL, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning("LeakOSINT request failed for %s: %s", query, exc)
        return LeakOsintResult(query=query, success=False, error=str(exc))

    try:
        data = response.json()
    except ValueError:
        return LeakOsintResult(
            query=query,
            success=False,
            error=f"non-JSON response (HTTP {response.status_code})",
        )

    if not isinstance(data, dict):
        return LeakOsintResult(query=query, success=False, error="unexpected response shape")

    if response.status_code != 200:
        return LeakOsintResult(
            query=query, success=False, error=f"HTTP {response.status_code}", raw=data
        )

    # The API answers 200 with an error field for quota, malformed queries, etc.
    api_error = data.get("Error code") or data.get("error")
    if api_error:
        logger.warning("LeakOSINT API error for %s: %s", query, api_error)
        return LeakOsintResult(query=query, success=False, error=str(api_error), raw=data)

    records = _parse_databases(data)
    logger.info("LeakOSINT found %d record(s) for %s", len(records), query)
    return LeakOsintResult(
        query=query,
        success=True,
        records=records,
        databases=sorted({r.database for r in records}),
        raw=data,
    )

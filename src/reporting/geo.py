"""
Ghost Identity Hunter - Location signals as map coordinates

PURPOSE:
--------
Turns the location signals an investigation collects into points a map can
plot, so the report shows where a subject appears rather than linking out to
a map service.

FUNCTIONALITY:
--------------
- Parses coordinates already carried by an artifact (EXIF GPS, decimal pairs)
- Resolves place names (phone regions, profile locations) through Nominatim,
  caching every answer -- including a miss -- in the database
- Records who asserted each place, so a string the subject wrote about
  themselves is not plotted with the authority of a measured coordinate
- Degrades to the coordinates it could parse when the geocoder is unreachable,
  so an offline report still has a map

USAGE EXAMPLES:
--------------
from src.reporting.geo import build_map_points

points = build_map_points(conn, geographic_data["locations"])

DEPENDENCIES:
-------------
- src.storage.database: geocode cache
- src.utils.http_client: pooled session with a rotating User-Agent

AUTHOR:
-------
Dhayanidhi Rajasekaran
"""

import logging
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"

# Nominatim's usage policy allows one request a second from a named client.
_GEOCODE_INTERVAL = 1.0
_GEOCODE_TIMEOUT = 5
# A report is not worth a long stall: only this many unseen place names are
# looked up, the rest are left to the textual list.
_GEOCODE_BUDGET = 8
# How long a failure to resolve a name is trusted. A miss is usually the name
# (a platform's "Earth", a joke), but it is sometimes the network or a rate
# limit, and caching that forever means one bad report suppresses the place in
# every later one -- silently, since the name is never sent again.
MISS_TTL = timedelta(days=7)

_DECIMAL_PAIR = re.compile(
    r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*[,;/]\s*(-?\d{1,3}(?:\.\d+)?)\s*$"
)
# ExifTool writes a position as 37 deg 48' 30.00" N, 122 deg 24' 39.00" W
_DMS = re.compile(
    r"(\d{1,3})\s*(?:deg|°)\s*(\d{1,2})['\u2032]?\s*([\d.]+)?[\"\u2033]?\s*([NSEW])",
    re.IGNORECASE,
)

# Only these carry a place name. A "platform" signal's value is the platform a
# located bio was found on -- geocoding "GitHub" plants a marker on whatever
# Nominatim makes of the word and spends a lookup that a real place needed.
PLACE_NAME_TYPES = {"location", "phone_region", "address", "city", "country"}

# Who asserted a place, which is the whole of what the report knows about how
# far to trust it. A coordinate read out of a file was measured; a registrant
# record, a host lookup or a number's region was written by someone other than
# the subject; a profile field or a bio is whatever the subject typed there,
# and "Mars" geocodes as readily as a real village does.
BASIS_MEASURED = "measured"
BASIS_RECORDED = "recorded"
BASIS_CORROBORATED = "corroborated"
BASIS_SELF_DECLARED = "self_declared"

# Weakest first: a place inherits the strongest basis any source gave it.
_BASIS_ORDER = [BASIS_SELF_DECLARED, BASIS_CORROBORATED, BASIS_RECORDED, BASIS_MEASURED]

BASIS_LABELS = {
    BASIS_MEASURED: "measured coordinate",
    BASIS_RECORDED: "third-party record",
    BASIS_CORROBORATED: "named by more than one source",
    BASIS_SELF_DECLARED: "self-declared, unverified",
}

# Tools that report a place from a record the subject does not write. Anything
# else -- every profile field, every bio, every source this list has not been
# taught about -- is treated as the subject's own claim, which is the safe way
# round for a marker that reads as a finding.
# Substrings, so a tool reached through a plugin wrapper is matched under
# whatever name the wrapper reports it as.
RECORDED_SOURCES = (
    "whois", "shodan", "exif", "nmap", "phone_osint", "phonevalidation",
)
# A number's region comes from its numbering plan, not from a profile field.
RECORDED_TYPES = {"phone_region"}


def assertion_basis(source: str, loc_type: str) -> str:
    """Whether a named place was recorded about the subject or claimed by them."""
    if loc_type in RECORDED_TYPES:
        return BASIS_RECORDED
    name = (source or "").lower()
    if any(tool in name for tool in RECORDED_SOURCES):
        return BASIS_RECORDED
    return BASIS_SELF_DECLARED


def _dms_to_decimal(degrees: str, minutes: str, seconds: str | None, hemisphere: str) -> float:
    value = int(degrees) + int(minutes) / 60 + float(seconds or 0) / 3600
    return -value if hemisphere.upper() in ("S", "W") else value


def parse_coordinates(value: str) -> tuple[float, float] | None:
    """Read a latitude/longitude pair out of an artifact value.

    Handles the two forms the tools produce -- a decimal pair from EXIF
    extraction and ExifTool's degrees/minutes/seconds -- and rejects anything
    outside the earth's range, which is how a "12, 34" version string or a
    truncated value gives itself away.
    """
    if not value:
        return None
    text = str(value).strip()

    match = _DECIMAL_PAIR.match(text)
    if match:
        lat, lon = float(match.group(1)), float(match.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon
        return None

    parts = _DMS.findall(text)
    if len(parts) >= 2:
        first = _dms_to_decimal(*parts[0])
        second = _dms_to_decimal(*parts[1])
        # The hemisphere letter says which is which, whatever the order.
        if parts[0][3].upper() in ("E", "W"):
            first, second = second, first
        if -90 <= first <= 90 and -180 <= second <= 180:
            return first, second
    return None


def _cached_geocode(conn: sqlite3.Connection, place: str) -> tuple | None:
    """Return (lat, lon, display_name), or None when the name must be asked.

    A hit is kept for good -- a place does not move. A miss expires, so a name
    that failed while the geocoder was unreachable is tried again rather than
    being written off permanently.
    """
    try:
        row = conn.execute(
            "SELECT latitude, longitude, display_name, resolved_at "
            "FROM geocode_cache WHERE place = ?",
            (place.lower(),),
        ).fetchone()
    except sqlite3.Error as exc:
        logger.debug("Geocode cache unreadable: %s", exc)
        return None
    if row is None:
        return None
    if row["latitude"] is None and _miss_expired(row["resolved_at"]):
        return None
    return row["latitude"], row["longitude"], row["display_name"]


def _miss_expired(resolved_at: str | None) -> bool:
    """Whether a recorded failure is old enough to be worth retrying."""
    if not resolved_at:
        return True
    try:
        recorded = datetime.fromisoformat(resolved_at)
    except ValueError:
        return True
    if recorded.tzinfo is None:
        recorded = recorded.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - recorded > MISS_TTL


def _store_geocode(conn: sqlite3.Connection, place: str, lat, lon, display_name) -> None:
    try:
        conn.execute(
            "INSERT OR REPLACE INTO geocode_cache "
            "(place, latitude, longitude, display_name, resolved_at) VALUES (?, ?, ?, ?, ?)",
            (place.lower(), lat, lon, display_name,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        conn.commit()
    except sqlite3.Error as exc:
        logger.debug("Geocode cache not written for %s: %s", place, exc)


def _geocode(place: str) -> tuple | None:
    """Ask Nominatim for a place's coordinates; None when it cannot answer."""
    try:
        from src.utils.http_client import get_http_session

        response = get_http_session().get(
            NOMINATIM_URL,
            params={"q": place, "format": "json", "limit": 1},
            timeout=_GEOCODE_TIMEOUT,
        )
        if response.status_code != 200:
            logger.info("Geocoding %r returned HTTP %s", place, response.status_code)
            return None
        results = response.json()
        if not results:
            return None
        top = results[0]
        return float(top["lat"]), float(top["lon"]), top.get("display_name") or place
    except Exception as exc:                      # network, JSON, missing keys
        logger.info("Geocoding %r failed: %s", place, exc)
        return None


def build_map_points(conn: sqlite3.Connection, locations: list[dict],
                     geocode: bool = True) -> list[dict]:
    """Plot the location signals: coordinates first, then resolvable names.

    Values that are already coordinates need nothing but parsing. Names are
    resolved through the cache, and only the first few unseen ones are sent to
    the geocoder, so generating a report stays a local operation in all but
    the first run for a place.
    """
    grouped: dict[tuple, dict] = {}
    lookups = 0
    last_call = 0.0

    for loc in locations or []:
        value = str(loc.get("value") or "").strip()
        if not value:
            continue
        label = value
        coords = parse_coordinates(value)
        precise = coords is not None

        if coords is None:
            if loc.get("type") not in PLACE_NAME_TYPES:
                # Either a coordinate this parser cannot read, or a value that
                # was never a place to begin with.
                continue
            cached = _cached_geocode(conn, value)
            if cached is not None:
                lat, lon, display = cached
                if lat is None:
                    continue                      # known to be unresolvable
                coords, label = (lat, lon), display or value
            elif geocode and lookups < _GEOCODE_BUDGET:
                wait = _GEOCODE_INTERVAL - (time.monotonic() - last_call)
                if wait > 0 and lookups:
                    time.sleep(wait)
                resolved = _geocode(value)
                last_call = time.monotonic()
                lookups += 1
                if resolved is None:
                    _store_geocode(conn, value, None, None, None)
                    continue
                lat, lon, display = resolved
                _store_geocode(conn, value, lat, lon, display)
                coords, label = (lat, lon), display
            else:
                continue

        source = loc.get("source") or "unknown"
        loc_type = loc.get("type") or "location"
        basis = assertion_basis(source, loc_type)
        # A coordinate pair is a measurement only when something other than the
        # subject wrote it down: a profile field holding one is still a claim.
        if precise and basis == BASIS_RECORDED:
            basis = BASIS_MEASURED

        key = (round(coords[0], 4), round(coords[1], 4))
        entry = grouped.get(key)
        if entry is None:
            entry = grouped[key] = {
                "lat": coords[0],
                "lon": coords[1],
                "label": label,
                "value": value,
                "source": source,
                "type": loc_type,
                # A parsed coordinate is where the subject was; a geocoded name
                # is only the middle of whatever area the name covers.
                "precise": precise,
                "sources": [],
                "basis": basis,
            }
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if _BASIS_ORDER.index(basis) > _BASIS_ORDER.index(entry["basis"]):
            entry["basis"] = basis
            entry["label"] = label
            entry["source"] = source
            entry["type"] = loc_type
        entry["precise"] = entry["precise"] or precise

    return [_finalise(entry) for entry in grouped.values()]


def _finalise(entry: dict) -> dict:
    """Settle a place's basis once every source that named it is known.

    Two sources naming the same place corroborate each other, which is the only
    way a string the subject wrote about themselves earns a marker; on its own
    it stays a claim, plotted as one or not at all.
    """
    if entry["basis"] == BASIS_SELF_DECLARED and len(entry["sources"]) > 1:
        entry["basis"] = BASIS_CORROBORATED
    entry["basis_label"] = BASIS_LABELS[entry["basis"]]
    entry["authoritative"] = entry["basis"] != BASIS_SELF_DECLARED
    return entry

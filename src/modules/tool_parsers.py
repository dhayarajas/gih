"""One parser per external tool, kept apart from the code that runs them.

Every tool answers in its own shape -- maigret writes newline-delimited JSON
with a nested extraction block, nmap has an XML schema, whatweb a plugin map,
whois a loose key/value list -- and a single shared regex over stdout reads
only the part of each that happens to look alike. That cost real findings: a
maigret hit carries the account's display name, avatar, location and creation
date, and none of it reached the report.

These functions take what the tool produced and return artifact dicts in the
one shape the orchestrator stores. They are pure, so each is tested against
output captured from a live run of the tool.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List

logger = logging.getLogger(__name__)

# Maximum number of artifacts a single tool run contributes to an investigation.
# Keeps BFS expansion (and report size) bounded on high-volume tools.
MAX_ARTIFACTS_PER_TOOL = 15

# Matches the "[+] Platform: https://..." lines sherlock emits for a hit.
FOUND_ACCOUNT_PATTERN = re.compile(r"^\[\+\]\s*(?P<platform>[^:]+?):\s*(?P<url>https?://\S+)\s*$")

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# maigret's per-account extraction block: the keys worth promoting out of the
# ids blob, and the artifact each becomes.
_MAIGRET_IDENTITY_KEYS = {
    "fullname": ("fullname", 0.6),
    "name": ("fullname", 0.55),
    "real_name": ("fullname", 0.6),
    "image": ("image_url", 0.6),
    "avatar": ("image_url", 0.6),
    "location": ("location", 0.5),
    "country": ("location", 0.45),
    "email": ("email", 0.7),
    "phone": ("phone", 0.7),
}
_MAIGRET_NOISE_KEYS = {"_extractor", "id", "uid", "username", "is_private", "is_indexed"}


def _capped(artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return artifacts[:MAX_ARTIFACTS_PER_TOOL]


# --------------------------------------------------------------------------
# username tools
# --------------------------------------------------------------------------

def parse_sherlock(output: str, username: str, confidence: float = 0.8) -> List[Dict[str, Any]]:
    """Accounts from sherlock's --print-found lines.

    sherlock reports one line per hit and nothing else about the account, so
    the line is the whole finding.
    """
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for line in output.splitlines():
        match = FOUND_ACCOUNT_PATTERN.match(line.strip())
        if not match:
            continue
        url = match.group("url").strip()
        if url in seen:
            continue
        seen.add(url)
        artifacts.append({
            "type": "username_presence",
            "value": url,
            "platform": match.group("platform").strip(),
            "username": username,
            "source": "sherlock",
            "confidence": confidence,
        })

    return _capped(artifacts)


def parse_maigret_ndjson(report: str, username: str) -> List[Dict[str, Any]]:
    """Accounts and the personal detail maigret extracted from each.

    maigret's real output is the report file, not the tree it prints: every
    claimed account arrives with the site, the URL and an ``ids`` block the
    site's extractor filled in -- display name, avatar, location, follower
    counts, other usernames. The account becomes a presence and each
    identifying id becomes an artifact of its own, so correlation can link the
    person behind the accounts rather than only the accounts.
    """
    artifacts: List[Dict[str, Any]] = []
    seen_urls = set()
    seen_ids = set()

    for line in report.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("maigret report line is not JSON, skipping")
            continue
        if not isinstance(entry, dict):
            continue

        status = entry.get("status") or {}
        if not isinstance(status, dict) or status.get("status") != "Claimed":
            continue

        url = status.get("url") or entry.get("url_user")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        ids = status.get("ids") if isinstance(status.get("ids"), dict) else {}
        platform = status.get("site_name") or entry.get("sitename") or "unknown"
        artifacts.append({
            "type": "username_presence",
            "value": url,
            "platform": platform,
            "username": username,
            "source": "maigret",
            "confidence": 0.75,
            "metadata": {k: v for k, v in ids.items() if k not in _MAIGRET_NOISE_KEYS},
            "tags": (entry["site"].get("tags")
                     if isinstance(entry.get("site"), dict) else None),
        })

        for key, value in ids.items():
            mapping = _MAIGRET_IDENTITY_KEYS.get(str(key).lower())
            if not mapping or not value:
                continue
            atype, confidence = mapping
            text = str(value).strip()
            if not text or (atype, text.lower()) in seen_ids:
                continue
            seen_ids.add((atype, text.lower()))
            artifacts.append({
                "type": atype,
                "value": text,
                "platform": platform,
                "source": "maigret",
                "confidence": confidence,
                "metadata": {"found_on": url, "field": key},
            })

    return _capped(artifacts)


def parse_usufy_profiles(profiles: Any, username: str) -> List[Dict[str, Any]]:
    """Accounts from usufy's i3visio entity list.

    Each profile carries its URI, alias and platform as sibling attributes
    tagged with a "com.i3visio.*" type rather than as named fields.
    """
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    if not isinstance(profiles, list):
        return artifacts

    for profile in profiles:
        attributes = profile.get("attributes", []) if isinstance(profile, dict) else []
        values = {
            attribute.get("type"): attribute.get("value")
            for attribute in attributes
            if isinstance(attribute, dict)
        }
        url = values.get("com.i3visio.URI")
        if not url or url in seen:
            continue
        seen.add(url)
        artifacts.append({
            "type": "username_presence",
            "value": url,
            "platform": values.get("com.i3visio.Platform", "unknown"),
            "username": values.get("com.i3visio.Alias", username),
            "source": "osrframework",
            "confidence": 0.7,
        })

    return _capped(artifacts)


# --------------------------------------------------------------------------
# email tools
# --------------------------------------------------------------------------

def parse_holehe_csv(report: str, email: str) -> List[Dict[str, Any]]:
    """Registered accounts from holehe's CSV report.

    The CSV says more than the terminal output: besides whether the address is
    registered, a site may hand back a masked recovery address or phone
    number, which is a lead the text mode never shows.
    """
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for row in csv.DictReader(io.StringIO(report)):
        if str(row.get("exists", "")).strip().lower() != "true":
            continue
        platform = (row.get("domain") or row.get("name") or "").strip()
        if not platform or platform in seen:
            continue
        seen.add(platform)

        metadata = {}
        for column, label in (("emailrecovery", "recovery_email"),
                              ("phoneNumber", "recovery_phone"),
                              ("others", "notes")):
            value = (row.get(column) or "").strip()
            if value and value.lower() not in ("none", "nan", ""):
                metadata[label] = value

        artifacts.append({
            # Platform-qualified so each account is a distinct artifact; a bare
            # email would collapse every hit into a single graph node.
            "type": "email_presence",
            "value": f"{platform}:{email}",
            "platform": platform,
            "username": email,
            "source": "holehe",
            "confidence": 0.8,
            "metadata": metadata or None,
        })

    return _capped(artifacts)


def parse_holehe_text(output: str, email: str) -> List[Dict[str, Any]]:
    """Registered accounts from holehe's terminal output.

    Used when the CSV report could not be read; holehe ends with a legend line
    that also starts with "[+]", so a hit is recognised by being a single
    token.
    """
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("[+]"):
            continue
        platform = line[3:].strip()
        if not platform or " " in platform or platform in seen:
            continue
        seen.add(platform)
        artifacts.append({
            "type": "email_presence",
            "value": f"{platform}:{email}",
            "platform": platform,
            "username": email,
            "source": "holehe",
            "confidence": 0.8,
        })

    return _capped(artifacts)


# --------------------------------------------------------------------------
# domain tools
# --------------------------------------------------------------------------

def parse_theharvester_json(report: str, domain: str) -> List[Dict[str, Any]]:
    """Emails, hosts, IPs and people from theHarvester's JSON report.

    Reading the report rather than the printed summary is what makes the
    people, ASNs and host-to-IP pairs available: the terminal output prints
    them in sections a single regex cannot tell apart, and a host there is
    written "name:ip", which a bare hostname regex mangles.
    """
    try:
        data = json.loads(report)
    except json.JSONDecodeError:
        logger.debug("theHarvester report is not JSON")
        return []
    if not isinstance(data, dict):
        return []

    artifacts: List[Dict[str, Any]] = []
    seen = set()

    def add(atype: str, value: str, confidence: float, **extra) -> None:
        value = str(value).strip()
        if not value or (atype, value.lower()) in seen:
            return
        seen.add((atype, value.lower()))
        artifacts.append({
            "type": atype, "value": value, "source": "theharvester",
            "confidence": confidence, **extra,
        })

    for email in data.get("emails") or []:
        add("email", email, 0.8, domain=domain)

    for host in data.get("hosts") or []:
        # "name:ip" when theHarvester resolved the host, bare name otherwise.
        name, _, address = str(host).partition(":")
        if name.lower().endswith(domain.lower()) and name.lower() != domain.lower():
            add("subdomain", name, 0.85, domain=domain,
                metadata={"resolved_ip": address} if address else None)
        if address:
            add("ip_address", address, 0.75, metadata={"hostname": name})

    for address in data.get("ips") or []:
        add("ip_address", address, 0.75, domain=domain)

    for url in data.get("interesting_urls") or []:
        add("url", url, 0.6, domain=domain)

    for person in data.get("people") or []:
        add("fullname", person, 0.5, domain=domain)
    for person in data.get("linkedin_people") or []:
        add("fullname", person, 0.55, domain=domain,
            metadata={"network": "linkedin"})

    for asn in data.get("asns") or []:
        add("asn", asn, 0.7, domain=domain)

    # One run answers two analyses -- contacts and hosts -- so each is capped
    # on its own; a domain publishing fifteen addresses still reports its
    # subdomains.
    contacts = [a for a in artifacts if a["type"] in ("email", "fullname")]
    hosts = [a for a in artifacts if a["type"] not in ("email", "fullname")]
    return _capped(contacts) + _capped(hosts)


def parse_subdomains(output: str, domain: str, tool_name: str,
                     confidence: float = 0.85) -> List[Dict[str, Any]]:
    """Subdomains of ``domain`` mentioned anywhere in a tool's output.

    Shared by the tools whose only output is a list of names (sublist3r,
    amass, and subfinder when it is not asked for JSON); anchoring on the
    domain keeps banners and progress chatter out.
    """
    pattern = re.compile(
        r"(?<![\w.%-])((?:[a-zA-Z0-9_-]+\.)+" + re.escape(domain) + r")(?![\w-])",
        re.IGNORECASE,
    )
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for match in pattern.findall(output):
        subdomain = match.lower().strip(".")
        if subdomain in seen or subdomain == domain.lower():
            continue
        seen.add(subdomain)
        artifacts.append({
            "type": "subdomain",
            "value": subdomain,
            "domain": domain,
            "source": tool_name,
            "confidence": confidence,
        })

    return _capped(artifacts)


def parse_subfinder_json(output: str, domain: str) -> List[Dict[str, Any]]:
    """Subdomains from subfinder's JSON lines, keeping which source found each.

    subfinder aggregates dozens of passive sources; -silent throws that away,
    while the JSON line names the source, which is what a reader needs to
    judge a subdomain that only one aggregator has ever seen.
    """
    artifacts: List[Dict[str, Any]] = []
    seen = set()

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        host = str(entry.get("host") or "").lower().strip(".")
        if not host or host in seen or host == domain.lower():
            continue
        seen.add(host)
        artifacts.append({
            "type": "subdomain",
            "value": host,
            "domain": domain,
            "source": "subfinder",
            "confidence": 0.85,
            "metadata": {"discovered_by": entry.get("source")} if entry.get("source") else None,
        })

    return _capped(artifacts)


# whois labels vary by registry; each maps to one field in the parsed record.
_WHOIS_FIELDS = {
    "registrar": "registrar",
    "registrar url": "registrar_url",
    "creation date": "creation_date",
    "created": "creation_date",
    "registered on": "creation_date",
    "updated date": "updated_date",
    "last updated": "updated_date",
    "registry expiry date": "expiration_date",
    "expiration date": "expiration_date",
    "expiry date": "expiration_date",
    "registrant organization": "registrant_organization",
    "registrant name": "registrant_name",
    "registrant email": "registrant_email",
    "registrant country": "registrant_country",
    "admin email": "admin_email",
    "tech email": "tech_email",
    "registrar abuse contact email": "abuse_email",
    "registrar abuse contact phone": "abuse_phone",
    "dnssec": "dnssec",
    "org": "registrant_organization",
}
_WHOIS_MULTI = {"name server": "name_servers", "nserver": "name_servers",
                "domain status": "status", "status": "status"}


def parse_whois(output: str, domain: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """The registration record and the artifacts hiding inside it.

    A whois answer is a flat key/value list where a label may repeat -- every
    nameserver and every status code is its own line -- so taking the first
    match of each label, as a regex sweep does, drops all but one nameserver
    and misses the registrant contacts entirely. Contacts are people, so they
    become artifacts rather than trivia in a data blob.
    """
    record: Dict[str, Any] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith(("%", "#", ">>>")) or ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip().lower()
        value = value.strip()
        if not value:
            continue
        if label in _WHOIS_MULTI:
            field = _WHOIS_MULTI[label]
            values = record.setdefault(field, [])
            # A status line carries its URL after the code; the code is the fact.
            entry = value.split(" ")[0] if field == "status" else value.lower()
            if entry not in values:
                values.append(entry)
        elif label in _WHOIS_FIELDS and _WHOIS_FIELDS[label] not in record:
            record[_WHOIS_FIELDS[label]] = value

    artifacts: List[Dict[str, Any]] = [{
        "type": "domain_info",
        "value": domain,
        "data": record,
        "source": "whois",
        "confidence": 0.95,
    }]

    seen = set()
    for field in ("registrant_email", "admin_email", "tech_email"):
        address = record.get(field)
        if not address or not _EMAIL_RE.fullmatch(address) or address.lower() in seen:
            continue
        seen.add(address.lower())
        artifacts.append({
            "type": "email",
            "value": address,
            "domain": domain,
            "source": "whois",
            "confidence": 0.7,
            "metadata": {"role": field.replace("_email", "")},
        })

    if record.get("registrant_name"):
        artifacts.append({
            "type": "fullname",
            "value": record["registrant_name"],
            "domain": domain,
            "source": "whois",
            "confidence": 0.6,
        })

    for nameserver in record.get("name_servers") or []:
        artifacts.append({
            "type": "name_server",
            "value": nameserver,
            "domain": domain,
            "source": "whois",
            "confidence": 0.9,
        })

    return record, _capped(artifacts)


def parse_whatweb_json(report: str, target: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Technologies, addresses and page identity from whatweb's JSON log.

    whatweb's one-line summary packs everything into "Plugin[detail]" pairs
    that a regex has to guess at; the JSON log separates the plugin, its
    string value and its module, which is what makes the page title, the
    country and the HTTP status usable instead of being lumped in with the
    technology list.
    """
    try:
        entries = json.loads(report)
    except json.JSONDecodeError:
        logger.debug("whatweb log is not JSON")
        return {}, []
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return {}, []

    technologies: List[str] = []
    addresses: List[str] = []
    details: Dict[str, Any] = {}
    artifacts: List[Dict[str, Any]] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins") or {}
        if entry.get("http_status"):
            details["http_status"] = entry["http_status"]

        for plugin, payload in plugins.items():
            values = []
            if isinstance(payload, dict):
                for key in ("string", "module", "version", "account"):
                    for item in payload.get(key) or []:
                        values.append(str(item))
            detail = ", ".join(dict.fromkeys(values))

            if plugin == "IP":
                addresses.extend(values)
            elif plugin == "Title":
                details["title"] = detail
            elif plugin == "Country":
                details["country"] = detail
            elif plugin in ("RedirectLocation", "Cookies", "HttpOnly", "UncommonHeaders"):
                details.setdefault(plugin.lower(), detail)
            else:
                technologies.append(f"{plugin}[{detail}]" if detail else plugin)

            for item in values:
                if _EMAIL_RE.fullmatch(item):
                    artifacts.append({
                        "type": "email", "value": item, "source": "whatweb",
                        "confidence": 0.6, "metadata": {"found_by": plugin},
                    })

    for address in dict.fromkeys(addresses):
        artifacts.append({
            "type": "ip_address", "value": address,
            "source": "whatweb", "confidence": 0.85,
        })

    for technology in sorted(dict.fromkeys(technologies)):
        artifacts.append({
            "type": "web_technology", "value": technology, "target": target,
            "source": "whatweb", "confidence": 0.8,
            "metadata": details or None,
        })

    parsed = {"technologies": sorted(dict.fromkeys(technologies)),
              "addresses": sorted(dict.fromkeys(addresses)), **details}
    return parsed, _capped(artifacts)


def parse_whatweb_summary(output: str, target: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Technologies from whatweb's one-line summary, when the log is missing.

    The summary flattens everything into "Plugin[detail]" pairs, so a title
    and a technology are indistinguishable; only the address is safely
    recoverable.
    """
    technologies = []
    addresses = []

    for plugin, detail in re.findall(r"([A-Za-z0-9_-]+)\[([^\]]*)\]", output):
        if plugin == "IP":
            addresses.append(detail)
        elif plugin in ("Country", "RedirectLocation", "Cookies", "HttpOnly"):
            continue
        else:
            technologies.append(f"{plugin}[{detail}]" if detail else plugin)

    artifacts: List[Dict[str, Any]] = [
        {"type": "ip_address", "value": address, "source": "whatweb", "confidence": 0.85}
        for address in dict.fromkeys(addresses)
    ]
    artifacts += [
        {"type": "web_technology", "value": technology, "target": target,
         "source": "whatweb", "confidence": 0.8}
        for technology in sorted(dict.fromkeys(technologies))
    ]
    return ({"technologies": sorted(dict.fromkeys(technologies)),
             "addresses": sorted(dict.fromkeys(addresses))}, _capped(artifacts))


# --------------------------------------------------------------------------
# host tools
# --------------------------------------------------------------------------

def parse_nmap_text(output: str, target: str) -> List[Dict[str, Any]]:
    """Open ports from nmap's printed table, when the XML is missing.

    The version column is only present when nmap identified one, so it is
    optional here -- requiring it is what made the previous parser drop most
    of a light scan's findings.
    """
    artifacts: List[Dict[str, Any]] = []
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)[^\S\n]+open[^\S\n]+(\S+)(?:[^\S\n]+(.*))?$", re.MULTILINE
    )

    for port, protocol, service, version in pattern.findall(output):
        artifacts.append({
            "type": "open_port",
            "value": f"{target}:{port}",
            "protocol": protocol,
            "service": service,
            "version": (version or "").strip() or None,
            "source": "nmap",
            "confidence": 0.9,
        })

    return _capped(artifacts)


def parse_nmap_xml(report: str, target: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Open ports, services and hostnames from nmap's XML output.

    The text table only lists a version column when nmap identified one, so
    reading it with a regex that expects "port state service version" silently
    drops every port whose service was named from the port table -- which is
    most of them on a light scan. The XML always separates the fields.
    """
    try:
        root = ET.fromstring(report)
    except ET.ParseError:
        logger.debug("nmap output is not XML")
        return {}, []

    artifacts: List[Dict[str, Any]] = []
    hosts: List[Dict[str, Any]] = []

    for host in root.iter("host"):
        state = host.find("status")
        addresses = [a.get("addr") for a in host.findall("address") if a.get("addr")]
        hostnames = [h.get("name") for h in host.findall("./hostnames/hostname") if h.get("name")]
        address = addresses[0] if addresses else target
        hosts.append({
            "address": address,
            "state": state.get("state") if state is not None else None,
            "hostnames": sorted(set(hostnames)),
        })

        for name in dict.fromkeys(hostnames):
            if name != target:
                artifacts.append({
                    "type": "hostname", "value": name, "source": "nmap",
                    "confidence": 0.8, "metadata": {"address": address},
                })

        for port in host.findall("./ports/port"):
            port_state = port.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue
            service = port.find("service")
            version = " ".join(filter(None, [
                service.get("product") if service is not None else None,
                service.get("version") if service is not None else None,
            ])).strip() if service is not None else ""
            artifacts.append({
                "type": "open_port",
                "value": f"{target}:{port.get('portid')}",
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else None,
                "version": version or None,
                "source": "nmap",
                "confidence": 0.9,
                "metadata": {
                    "address": address,
                    "extra_info": service.get("extrainfo") if service is not None else None,
                },
            })

    return {"hosts": hosts}, _capped(artifacts)


# exiftool tags worth an artifact of their own, and the type each becomes.
_EXIF_IDENTITY_TAGS = {
    "Artist": ("fullname", 0.6),
    "Creator": ("fullname", 0.6),
    "OwnerName": ("fullname", 0.65),
    "Copyright": ("copyright", 0.5),
    "By-line": ("fullname", 0.6),
    "Author": ("fullname", 0.6),
    "Software": ("software", 0.7),
    "SerialNumber": ("device_serial", 0.8),
    "LensSerialNumber": ("device_serial", 0.75),
    "UserComment": ("note", 0.4),
}
_EXIF_DATE_TAGS = ("DateTimeOriginal", "CreateDate", "ModifyDate", "GPSDateTime")


def parse_exiftool_json(report: str, file_path: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Everything identifying in an image's metadata, not only GPS.

    A photograph's owner name, camera serial number and editing software tie
    files to a person as firmly as coordinates do, and the capture date is
    what places the file on the timeline; only the first of those was read
    before.
    """
    try:
        data = json.loads(report)
    except json.JSONDecodeError:
        logger.debug("exiftool output is not JSON")
        return {}, []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        return {}, []

    metadata = data[0] if isinstance(data[0], dict) else {}
    artifacts: List[Dict[str, Any]] = []

    position = metadata.get("GPSPosition")
    if not position and metadata.get("GPSLatitude") and metadata.get("GPSLongitude"):
        position = f"{metadata['GPSLatitude']}, {metadata['GPSLongitude']}"
    if position:
        artifacts.append({
            "type": "gps_coordinates", "value": str(position), "source": "exiftool",
            "confidence": 0.9,
            "metadata": {"altitude": metadata.get("GPSAltitude"),
                         "file": file_path},
        })

    if metadata.get("Make") or metadata.get("Model"):
        artifacts.append({
            "type": "camera_info",
            "value": f"{metadata.get('Make', '')} {metadata.get('Model', '')}".strip(),
            "source": "exiftool", "confidence": 0.9,
            "metadata": {"lens": metadata.get("LensModel")},
        })

    for tag in _EXIF_DATE_TAGS:
        if metadata.get(tag):
            artifacts.append({
                "type": "creation_date", "value": str(metadata[tag]),
                "source": "exiftool", "confidence": 0.9,
                "metadata": {"tag": tag},
            })
            break

    seen = set()
    for tag, (atype, confidence) in _EXIF_IDENTITY_TAGS.items():
        value = metadata.get(tag)
        if value is None:
            continue
        text = str(value).strip()
        if not text or (atype, text.lower()) in seen:
            continue
        seen.add((atype, text.lower()))
        artifacts.append({
            "type": atype, "value": text, "source": "exiftool",
            "confidence": confidence, "metadata": {"tag": tag, "file": file_path},
        })

    return metadata, _capped(artifacts)


def parse_shodan_host(output: str, ip_address: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Host facts from the shodan CLI, whether it answered JSON or a summary."""
    parsed: Dict[str, Any] = {}
    ports: List[str] = []

    try:
        loaded = json.loads(output)
        parsed = loaded if isinstance(loaded, dict) else {}
        ports = [str(p) for p in parsed.get("ports", [])]
    except json.JSONDecodeError:
        for key, pattern in (
            ("organization", r"Organization:\s*(.+)"),
            ("country", r"Country:\s*(.+)"),
            ("city", r"City:\s*(.+)"),
            ("operating_system", r"Operating System:\s*(.+)"),
            ("hostnames", r"Hostnames:\s*(.+)"),
            ("isp", r"ISP:\s*(.+)"),
        ):
            match = re.search(pattern, output)
            if match:
                parsed[key] = match.group(1).strip()
        # The CLI indents its port list under a "Ports:" heading.
        ports = re.findall(r"^\s*(\d+)/(?:tcp|udp)", output, re.MULTILINE)

    if not parsed and not ports:
        return parsed, []

    artifacts: List[Dict[str, Any]] = [{
        "type": "host_info", "value": ip_address, "data": parsed,
        "source": "shodan", "confidence": 0.9,
    }]
    for port in dict.fromkeys(ports):
        artifacts.append({
            "type": "open_port", "value": f"{ip_address}:{port}",
            "source": "shodan", "confidence": 0.95,
        })

    # A JSON answer lists the names; the printed one runs them together.
    hostnames = parsed.get("hostnames") or []
    if isinstance(hostnames, str):
        hostnames = hostnames.replace(",", " ").split()
    for hostname in [str(name).strip() for name in hostnames if str(name).strip()]:
        artifacts.append({
            "type": "hostname", "value": hostname, "source": "shodan",
            "confidence": 0.8, "metadata": {"address": ip_address},
        })

    return parsed, _capped(artifacts)


def parse_wayback_cdx(rows: Iterable[Any], domain: str) -> List[Dict[str, Any]]:
    """Archived URLs from a CDX answer, skipping its header row."""
    artifacts: List[Dict[str, Any]] = []
    for index, row in enumerate(rows or []):
        if index == 0 or not isinstance(row, (list, tuple)) or len(row) < 4:
            continue
        timestamp, original_url, status, mime_type = row[:4]
        artifacts.append({
            "type": "historical_url",
            "value": original_url,
            "timestamp": timestamp,
            "status_code": status,
            "mime_type": mime_type,
            "domain": domain,
            "source": "wayback_machine",
            "confidence": 0.8,
        })
    return _capped(artifacts)


def parse_emails(output: str, domain: str, tool_name: str,
                 confidence: float = 0.8) -> List[Dict[str, Any]]:
    """Email addresses mentioned in a tool's text output."""
    artifacts: List[Dict[str, Any]] = []
    seen = set()
    for address in _EMAIL_RE.findall(output):
        lowered = address.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        artifacts.append({
            "type": "email", "value": address, "domain": domain,
            "source": tool_name, "confidence": confidence,
        })
    return _capped(artifacts)

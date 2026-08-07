# Ghost Identity Hunter — Tooling Inventory, Installation Guide and Provider Gap

**Author:** Dhayanidhi Rajasekaran
**Repository:** https://github.com/dhayarajas/gih
**Date:** 2026-08-02

---

## 1. Scope

Part A lists every tool and service Ghost Identity Hunter (gih) actually invokes, with the installation command for each and the check that proves it is wired up.
Part B lists the Maltego data providers gih does **not** use, so the coverage boundary is explicit.

Sources: `docs/TOOL_COVERAGE.md`, `docs/EXTERNAL_TOOLS.md`, `config/config.yaml`, `requirements*.txt`, `Dockerfile.kali`, and the published Maltego Transform Hub catalogue (https://www.maltego.com/transform-hub/).

---

## 2. Base installation

Python 3.10+ is required.

```bash
git clone https://github.com/dhayarajas/gih.git
cd gih
pip install -r requirements.txt
```

Runtime Python dependencies (all installed by the command above): `click`, `networkx`, `phonenumbers`, `requests`, `Brotli`, `beautifulsoup4`, `Pillow`, `pyvis`, `Jinja2`, `tabulate`, `pyyaml`, `numpy`, `urllib3`.

Optional extras, each degrading cleanly when absent:

```bash
pip install -r requirements-dev.txt       # pytest, pytest-cov, ruff
pip install -r requirements-optional.txt  # face matching (dlib, ~3 GB) + Neo4j driver
```

Verify the external tool inventory at any time — this is the authoritative check and prints exactly what the host has:

```bash
python -m src.cli investigate --check-tools
```

---

## Part A — Tools gih uses

### 3. Integrated external tools (15)

Each of these has a real output parser in `src/modules/external_tools.py` and is dispatched by `_process_external_tools`. A missing binary is never scheduled; the investigation continues without it.

| # | Tool | Used for | Install command | Verify |
| --- | --- | --- | --- | --- |
| 1 | **sherlock** | username → account presence | `pip install sherlock-project` | `sherlock --version` |
| 2 | **maigret** | username → account presence (wider site list) | `pip install maigret` | `maigret --version` |
| 3 | **osrframework** (`usufy`) | username → social account presence | `pip install osrframework` | `usufy --help` |
| 4 | **holehe** | email → registered services | `pip install holehe` | `holehe --help` |
| 5 | **theHarvester** | domain → emails + subdomains | Kali: `sudo apt install theharvester` · elsewhere: `pipx install git+https://github.com/laramies/theHarvester` | `theHarvester -h` |
| 6 | **subfinder** | domain → subdomains | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `subfinder -version` |
| 7 | **sublist3r** | domain → subdomains | `pip install sublist3r` (Kali also packages it as `sublist3r`) | `sublist3r -h` |
| 8 | **amass** | domain → subdomains (passive) | Kali: `sudo apt install amass` · elsewhere: `go install -v github.com/owasp-amass/amass/v4/...@master` | `amass -version` |
| 9 | **whois** | domain → registrar, dates, registrant | `sudo apt install whois` | `whois example.com` |
| 10 | **dig** | domain → A / MX / NS / TXT records | `sudo apt install dnsutils` | `dig example.com +short` |
| 11 | **whatweb** | domain → web technologies, resolved IP | `sudo apt install whatweb` | `whatweb --version` |
| 12 | **nmap** | IP → open ports and service versions | `sudo apt install nmap` | `nmap --version` |
| 13 | **shodan** | IP → host intelligence *(API key required)* | `pip install shodan` then `shodan init <API_KEY>` | `shodan info` |
| 14 | **exiftool** | image → GPS, camera, timestamps | `sudo apt install libimage-exiftool-perl` | `exiftool -ver` |
| 15 | **wayback_machine** | domain → archived URLs | none — HTTP call to `web.archive.org` CDX API | reachable network |

Notes worth knowing before relying on a row:

- `osrframework` exposes no binary of its own; gih detects and runs `usufy`. It is restricted to the `social` platform tag with 32 threads (full list far exceeds the time budget; its timeout is 180 s).
- `amass -passive` often exceeds its 60 s budget and returns nothing; subfinder, sublist3r and theHarvester cover the same role.
- `wayback_machine` needs no binary and reports available whenever the network is up, but its CDX query commonly takes 9–31 s against a 30 s timeout, so archived URLs are absent from many runs.
- `nmap` runs `-Pn -F -sV --version-light`, i.e. no `-sS`, so **no root privileges are needed**.
- `shodan` reads the key stored by `shodan init`; no API key is ever placed on a command line.

### 4. Built-in modules and plugins (no installation)

These ship with the repository and need only the Python dependencies above.

| Capability | Module | Notes |
| --- | --- | --- |
| Phone validation / carrier / region | `src/modules/phone_osint.py` | uses `phonenumbers` |
| Email OSINT and breach lookup | `src/modules/email_osint.py`, `email_breach_plugin` | Have I Been Pwned; key optional |
| Username enumeration (built-in) | `src/modules/username_search.py` | independent of sherlock/maigret |
| Full-name seed expansion | orchestrator + `investigation.strict_match` | generates username candidates |
| Google Dorks | `src/modules/google_dorks.py` | Custom Search API when keyed, scraping otherwise |
| Image EXIF, hashing, reverse-search links | `src/modules/image_search.py` | link generation only, no image API |
| Face similarity | `src/modules/image_match.py` | needs `requirements-optional.txt` (dlib) |
| LeakOSINT breach records | `src/modules/leakosint.py` | paid token required; leads the report when present |
| Correlation, confidence, risk scoring | `src/correlation/linker.py` | core, always on |
| Interactive graph | `src/graph/visualizer.py` | `pyvis` / `networkx` |
| HTML / JSON / CSV / PDF reports | `src/reporting/` | 4 HTML templates + redaction |
| Optional graph backend | Neo4j | `pip install neo4j`, then `use_neo4j: true` |

### 5. API keys

No key is ever written to a command line, a report, a log, or the database.

| Service | Configuration | Behaviour without it |
| --- | --- | --- |
| Shodan | `plugins.shodan.api_key` or `SHODAN_API_KEY`, plus `shodan init` | plugin reports unavailable, run continues |
| LeakOSINT | `plugins.leakosint.api_key`, or `LEAKOSINT_API_TOKEN` / `LEAKOSINT_API_KEY` | skipped, no Breach Records section rendered |
| Have I Been Pwned | `plugins.email_breach.api_key` | optional; unauthenticated calls are rate-limited |
| Google Custom Search | `google_api_key` + `google_cx` | falls back to scraping |
| Etherscan, GeoNames | `plugins.*.api_key` | declared only — **no integration exists**, never scheduled |

### 6. Declared but deliberately not invoked (20)

`ToolChecker` knows 36 tools; 15 are integrated and 1 (`leakosint`) runs through the plugin path. The rest are detected and reported by `--check-tools` but never dispatched, each with a reason recorded in `UNIMPLEMENTED_TOOLS`:

`social_analyzer`, `emailharvester`, `recon-ng`, `spiderfoot`, `ghunt`, `photon`, `metagoofil`, `etherscan`, `geonames`, `wappalyzer`, `masscan`, `nikto`, `sqlmap`, `curl`, `wget`, `nslookup`, `tor_browser`, `flagfox`, `user_agent_switcher`, `google_dorks` (handled in-process, not as a subprocess).

### 7. One-command environment (recommended)

The Kali image installs the whole tool chain, so nothing above has to be installed by hand:

```bash
docker build -f Dockerfile.kali -t gih:kali .
docker run --rm -it -v "$HOME/.ghost_hunter:/home/ghosthunter/.ghost_hunter" gih:kali
```

Equivalent bare-metal one-liner for a Debian/Ubuntu host:

```bash
# in the Ubuntu/Debian repositories
sudo apt update && sudo apt install -y nmap whois dnsutils whatweb libimage-exiftool-perl python3-pip golang-go

# PyPI
pip install sherlock-project maigret holehe sublist3r osrframework shodan

# not packaged for Ubuntu — install from source
pipx install git+https://github.com/laramies/theHarvester
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
```

On Ubuntu 22.04 `apt` carries `nmap`, `whois`, `dnsutils`, `whatweb` and `libimage-exiftool-perl` but **not** `amass`, `theharvester` or `sublist3r` — those three are packaged only on Kali, which is why the Docker image is the shorter route.

---

## Part B — Maltego providers gih does not use

Of the 99 providers published on Maltego's Transform Hub, gih reaches four (**Have I Been Pwned**, **Shodan**, **Wayback Machine**, **Dorking**) and has weaker or stub equivalents for three (**Google Social Network Transforms** → sherlock/maigret; **TinEye / Image Analyzer** → reverse-search links only; **Etherscan** → declared, no plugin). The remaining 92 have no path in gih today.

### Malware / sandbox / threat intelligence
- VirusTotal Public API
- VirusTotal Premium API
- Hybrid Analysis
- Intezer Analyze
- PolySwarm
- Cisco Threat Grid
- CrowdStrike ThreatGraph
- CrowdStrike Intel
- Mandiant
- Abuse.ch URLhaus
- ThreatCrowd
- ThreatMiner
- ThreatConnect
- OpenCTI
- ATT&CK–MISP
- Anomali
- Intel 471
- Recorded Future
- Cybersixgill

### Vulnerabilities
- NIST NVD
- Vulners
- Censys
- GreyNoise Enterprise
- GreyNoise Community
- Elemendar
- Team Cymru

### Infrastructure, DNS and passive data
- DomainTools Iris Investigate
- DomainTools Enterprise
- Farsight DNSDB
- ZETAlytics Massive Passive
- WhoisXML API
- Host.io
- IPInfo
- MaxMind
- PeeringDB
- SSL Certificate Transparency Transforms
- DNSTwist
- alphaMountain
- HYAS Insight
- CrowdSec
- Criminal IP
- Spamhaus Intelligence
- urlscan.io
- SOCRadar
- Silobreaker

### Breaches and leaks
- SpyCloud Cybercrime Investigations
- Constella Intelligence
- Darkside
- Hades
- Flashpoint
- Digital Shadows
- ZeroFOX
- Cofense Intelligence

### Deep and dark web
- DarkOwl
- Vysion
- Web-IQ
- Corvus Intelligence
- Crowlingo
- Tisane Labs

### People and personal identifiers
- Pipl
- FullContact
- PeopleMon
- PhoneSearch
- Epieos
- OSINT Industries
- Hunter.io
- Clearbit
- LittleSis
- LoginsoftOSINT
- FlightAware
- Espy
- Social Links Professional
- Social Links CE
- Google Maps Geocoding

### Company, corporate and sanctions data
- OpenCorporates
- Orbis – Bureau Van Dijk
- OCCRP Aleph
- OpenSanctions
- EntitiesUA

### Cryptocurrency
- Tatum Blockchain Explorer
- Crystal Intelligence

### Phishing and reputation
- Scamadviser
- AbuseIPDB
- AlienVault OTX

### Image, content and language
- GeoSpy
- DeepL
- Regex Library

### Interoperability, case management, long tail
- STIX 2 Utilities
- Polonious
- Discogs
- The Movie Database

### Cheapest of these to add

Free or free-tier, so closable without a commercial contract: **crt.sh / Certificate Transparency**, **IPInfo** (or MaxMind GeoLite2), **NIST NVD**, **VirusTotal Public API**, **Hunter.io**, **AbuseIPDB**, **Abuse.ch URLhaus**, **urlscan.io**, **OpenSanctions**, **Etherscan** (already declared), **STIX 2 / MISP export**.

Two model changes unlock most of them: `file_hash` and `cve` artifact types, and an `organisation` entity. Without those, several of the free providers have nowhere to attach their results.

Structurally unreachable without commercial contracts: SpyCloud, Constella, DomainTools, Farsight, Recorded Future, Flashpoint, Cybersixgill, DarkOwl, Intel 471, Mandiant, CrowdStrike, Pipl, Social Links, Orbis, HYAS, Silobreaker, Digital Shadows, ZeroFOX.

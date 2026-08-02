# External OSINT Tool Coverage

`ToolChecker` declares 35 tools. This document records, for each of them, whether it is
detected, whether it has an integration with a real output parser in
`src/modules/external_tools.py`, whether `_process_external_tools` invokes it, and which
artifact types it contributes to correlation.

Generate the live version of this table at any time with:

```bash
python -m src.cli investigate --check-tools
```

## Integrated tools (14)

Every tool below was invoked against a live target and its real output was parsed into
`artifacts_discovered`, persisted with source attribution, and linked back to the artifact
that triggered the run.

| Tool | Invoked for | Artifact types | Profile fields |
|------|-------------|----------------|----------------|
| sherlock | username | `username_presence` | `platforms`, Platform Presence Matrix |
| maigret | username | `username_presence` | `platforms`, Platform Presence Matrix |
| holehe | email | `email_presence` | `platforms`, Platform Presence Matrix |
| theHarvester | domain, subdomain | `email`, `subdomain` | `emails`, `subdomains` |
| subfinder | domain (depth 0) | `subdomain` | `subdomains` |
| sublist3r | domain (depth 0) | `subdomain` | `subdomains` |
| amass | domain (depth 0) | `subdomain` | `subdomains` |
| whois | domain, subdomain | `domain_info` | `domains` |
| dig | domain, subdomain | `ip_address`, `dns_mx`, `dns_ns`, `dns_txt` | `ip_addresses`, `dns_records` |
| whatweb | domain, subdomain | `ip_address`, `web_technology` | `ip_addresses`, `web_technologies` |
| nmap | ip_address (depth < 2) | `open_port` | `open_ports` |
| shodan | ip_address (depth < 2) | `host_info`, `open_port` | `hosts`, `open_ports` |
| exiftool | image | `gps_coordinates`, `camera_info`, `creation_date` | `geolocations`, `device_info` |
| wayback_machine | domain (depth 0) | `historical_url` | `historical_urls` |

Notes:

- `shodan` needs an API key (`shodan init`); without one the CLI exits non-zero and the
  run is skipped rather than failing the investigation.
- `amass -passive` frequently exceeds its 60s budget and returns nothing; subfinder,
  sublist3r and theHarvester cover the same role.
- `wayback_machine` is an HTTP API, so it has no local executable and is reported as
  available whenever the network is reachable.

## Declared but not integrated (21)

| Tool | Reason |
|------|--------|
| google_dorks | Implemented separately in `src/modules/google_dorks.py`, invoked for username artifacts |
| social_analyzer | No stable CLI contract; node/python variants differ and output is not machine-parseable |
| emailharvester | Superseded by theHarvester, which is integrated and covers the same sources |
| wappalyzer | Superseded by whatweb, which is integrated and detects the same technologies |
| nslookup | Superseded by dig, which is integrated |
| masscan | Requires raw-socket (root) privileges; nmap covers the same port-scan role |
| recon-ng | Interactive framework requiring per-module API keys and a workspace; not batch-invocable |
| spiderfoot | Server/daemon oriented, requires its own database and web UI to collect results |
| osrframework | Ships per-utility entrypoints (usufy/mailfy) rather than an `osrframework` command |
| ghunt | Requires authenticated Google session cookies supplied by the operator |
| photon | Crawler output duplicates wayback_machine historical URLs |
| metagoofil | Document harvesting requires a search-engine API key and downloads remote files |
| etherscan | Requires an Etherscan API key and a wallet-address artifact type |
| geonames | Requires a GeoNames account; geodata is derived from exiftool GPS instead |
| nikto | Vulnerability scanner, out of scope for identity attribution |
| sqlmap | Exploitation tool, out of scope for identity attribution |
| tor_browser | Interactive browser, not a data source |
| flagfox | Browser extension, not a data source |
| user_agent_switcher | Browser extension, not a data source |
| curl | Generic transport used by other integrations rather than a data source |
| wget | Generic transport used by other integrations rather than a data source |

## Validation run

A single investigation seeded with a username, an email, a domain, an IP address and a
JPEG carrying EXIF GPS data (`--depth 2`) completed in about 12 minutes and produced:

```
artifacts 265   links 490   platform presences 106   unlinked artifacts 0

sherlock      username_presence   39      whatweb    web_technology  78
maigret       username_presence   28      whatweb    ip_address       4
holehe        email_presence       3      dig        ip_address      19
subfinder     subdomain           15      dig        dns_a            6
sublist3r     subdomain           10      nmap       open_port        4
theharvester  subdomain           15      whois      domain_info      1
theharvester  email                1      exiftool   gps/camera/date  3
```

Every one of those artifacts is reachable from its seed through `artifact_links`, so
correlation attributes it to the identity profile of the seed that produced it.

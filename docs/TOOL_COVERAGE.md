# External OSINT Tool Coverage

`ToolChecker` declares 35 tools. This document records, for each of them, whether it is
detected, whether it has an integration with a real output parser in
`src/modules/external_tools.py`, whether `_process_external_tools` invokes it, and which
artifact types it contributes to correlation.

Generate the live version of this table at any time with:

```bash
python -m src.cli investigate --check-tools
```

## Integrated tools (15)

Every tool below has an integration with a real output parser and is invoked by
`_process_external_tools`. Which of them actually run depends on what is installed;
`--check-tools` reports what the current host has. All rows except `shodan` and
`theHarvester` have been exercised end-to-end against live targets.

| Tool | Invoked for | Artifact types | Profile fields |
|------|-------------|----------------|----------------|
| sherlock | username | `username_presence` | `platforms`, Platform Presence Matrix |
| maigret | username | `username_presence` | `platforms`, Platform Presence Matrix |
| osrframework (usufy) | username | `username_presence` | `platforms`, Platform Presence Matrix |
| holehe | email | `email_presence` | `platforms`, Platform Presence Matrix |
| theHarvester | domain, subdomain | `email`, `subdomain` | `emails`, `subdomains` |
| subfinder | domain (depth 0) | `subdomain` | `subdomains` |
| sublist3r | domain (depth 0) | `subdomain` | `subdomains` |
| amass | domain (depth 0) | `subdomain` | `subdomains` |
| whois | domain, subdomain | `domain_info` | `domains` |
| dig | domain, subdomain | `ip_address` (from A records), `dns_mx`, `dns_ns`, `dns_txt` | `ip_addresses`, `dns_records` |
| whatweb | domain, subdomain | `ip_address`, `web_technology` | `ip_addresses`, `web_technologies` |
| nmap | ip_address (depth < 2) | `open_port` | `open_ports` |
| shodan | ip_address (depth < 2) | `host_info`, `open_port` | `hosts`, `open_ports` |
| exiftool | image | `gps_coordinates`, `camera_info`, `creation_date` | `geolocations`, `device_info` |
| wayback_machine | domain (depth 0) | `historical_url` | `historical_urls` |

Notes:

- `shodan` needs an API key (`shodan init`); without one the CLI exits non-zero and the
  run is skipped rather than failing the investigation.
- `amass -passive` sometimes exceeds its 60s budget and returns nothing; subfinder,
  sublist3r and theHarvester cover the same role.
- `osrframework` has no command of its own: `ToolChecker` detects it through `usufy`,
  the entrypoint the integration runs. It is restricted to the `social` platform tag
  with 32 threads because the full platform list takes far longer than the time budget
  (~2m15s even for the `social` subset, hence its 180s timeout). Its sibling `mailfy` is
  not integrated: it imports `cfscrape`, which is broken against urllib3 2.x.
- `wayback_machine` is an HTTP API, so it has no local executable and is reported as
  available whenever the network is reachable. Its CDX query regularly takes 9-31s
  against a 30s timeout, so `historical_url` findings are missing from many runs.
- `nmap` findings are attached to the identity that reaches the scanned IP through
  `artifact_links`. An investigation seeded *only* with `--ip` forms no identity at all
  (an IP address is not an identity anchor), so its `open_port` findings appear in the
  database and in the JSON report but under no profile.

## Plugin coverage

The plugin system (`src/plugins/`) is a second entry point to the same tools, used by
callers that want to run one tool against one artifact rather than a whole BFS level.
Every integrated tool now has a plugin:

| Plugin | Tool | Artifact types accepted |
|--------|------|-------------------------|
| `SherlockPlugin` | sherlock | `username` |
| `MaigretPlugin` | maigret | `username` |
| `OsrframeworkPlugin` | osrframework | `username` |
| `HolehePlugin` | holehe | `email` |
| `TheHarvesterPlugin` | theharvester | `domain` |
| `SubfinderPlugin` | subfinder | `domain` |
| `Sublist3rPlugin` | sublist3r | `domain` |
| `AmassPlugin` | amass | `domain` |
| `WhoisPlugin` | whois | `domain`, `ip_address` |
| `DigPlugin` | dig | `domain` |
| `WhatWebPlugin` | whatweb | `domain`, `subdomain` |
| `NmapPlugin` | nmap | `ip_address` |
| `ShodanPlugin` | shodan | `ip_address`, `domain` |
| `ExifToolPlugin` | exiftool | `image` |
| `WaybackMachinePlugin` | wayback_machine | `domain` |

The plugins added for maigret, holehe, subfinder, sublist3r, amass, whatweb, nmap,
exiftool, wayback_machine and osrframework subclass `IntegrationPlugin`, which delegates
to `run_tool_analysis` instead of re-implementing the subprocess call and the parser --
the older hand-written plugins (sherlock, whois, dig, shodan, theharvester) each carry
their own copy, which is why their output can differ from the integration's.
`IntegrationPlugin.check_wiring()` fails a plugin that names an analysis the integration
does not implement; `tests/test_integration_plugins.py` runs it over every plugin.

Note that `PluginManager` looks plugins up in `config.yaml` by class name
(`MaigretPlugin`), while the config keys are tool names (`maigret`), so the `enabled`
flags there do not currently gate plugin execution.

## Declared but not integrated (20)

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

Numbers below come from a host with sherlock, maigret, osrframework, holehe, whois, dig,
nmap, exiftool, subfinder, sublist3r, amass and whatweb installed (shodan and
theHarvester absent).

A single investigation seeded with a username, a full name, an email, an IP address and a
JPEG carrying EXIF GPS data (`--depth 2`) completed in 4m39s and produced:

```
artifacts 145   links 143   platform presences 98

sherlock          username_presence  29      nmap            open_port        2
maigret           username_presence  30      whatweb         web_technology   4
osrframework      username_presence  30      amass           subdomain        2
wayback_machine   historical_url     15      whois           domain_info      1
plugin scrapers   image               8      exiftool        gps/camera/date  3
```

osrframework alone accounts for ~2m15s of that wall clock; without it the same run
takes well under a minute.

Each of those artifacts is reachable from a seed through `artifact_links`, so correlation
attributes it to the identity profile of the seed that produced it -- with the `--ip`-only
caveat noted above.

Installing the Python tools with `pip` puts them in the virtualenv's `bin` directory;
`ToolChecker` resolves tools with `shutil.which`, so that directory must be on `PATH` or
sherlock, maigret and holehe are silently skipped.

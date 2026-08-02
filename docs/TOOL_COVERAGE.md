# External OSINT Tool Coverage

Status of every tool declared by `_initialize_common_tools` in `src/utils/tool_checker.py`
(35 entries) against what is actually implemented and invoked.

Columns:

- **Integrated** — has a class in `src/modules/external_tools.py` registered in
  `get_tool_integrations()` and an entry in `ANALYSIS_METHODS`.
- **Invoked for** — the artifact types that trigger it in `_process_external_tools`
  (`src/orchestrator.py`).
- **Parsed output** — the artifact types the parser appends to `artifacts_discovered`.

## Implemented (12)

| Tool | Integrated | Invoked for | Parsed output |
| --- | --- | --- | --- |
| sherlock | yes | username | `username_presence` (also written as `platform_presence` rows) |
| maigret | yes | username | `username_presence` (also written as `platform_presence` rows) |
| holehe | yes | email | `email_account` |
| theharvester | yes | domain | `email`, `subdomain` |
| amass | yes | domain | `subdomain` |
| subfinder | yes | domain | `subdomain` |
| whois | yes | domain | `domain_info` (registrar, dates, name servers, registrant email in metadata) |
| dig | yes | domain | `dns_a` plus a derived `ip_address` |
| nmap | yes | ip_address | `open_port` (service and version in metadata) |
| shodan | yes | ip_address | `host_info` — requires an API key, unverified here |
| exiftool | yes | image | `gps_coordinates`, `camera_info`, `creation_date` |
| wayback_machine | yes | domain | `historical_url` (HTTP CDX API, capped at 100 rows) |

`wayback_machine` is declared as a binary in the tool checker and therefore always reports as
"missing" in `--check-tools`, but the integration calls the Wayback CDX HTTP API and runs
regardless of local binaries.

`google_dorks` is likewise declared as a tool name but implemented as a Python module
(`src/modules/google_dorks.py`) invoked for usernames when enabled, not as a subprocess.

## Declared but not implemented (23)

No integration class, no dispatch entry and no invocation. `--check-tools` will report their
availability, and nothing else in the pipeline uses them.

`social_analyzer`, `emailharvester`, `sublist3r`, `masscan`, `whatweb`, `wappalyzer`,
`recon-ng`, `spiderfoot`, `osrframework`, `ghunt`, `photon`, `metagoofil`, `etherscan`,
`geonames`, `nikto`, `sqlmap`, `tor_browser`, `flagfox`, `user_agent_switcher`, `nslookup`,
`curl`, `wget`, `google_dorks` (declared as a tool, implemented as a module).

`nslookup`, `curl` and `wget` are generic utilities kept in the declaration list for
environment reporting; `flagfox`, `user_agent_switcher` and `tor_browser` are browser
components with no command-line contract and are unlikely to ever be integrated.

## Availability in this environment

`python -m src.cli investigate --check-tools` reported **10 of 35 available**: `sherlock`,
`maigret`, `holehe`, `whois`, `dig`, `nslookup`, `nmap`, `exiftool`, `curl`, `wget`.

## Live validation

Two runs were used to exercise every artifact-type branch (`nmap` was pointed only at
`scanme.nmap.org`, which its operators publish for scanning):

| Run | Seeds | Result |
| --- | --- | --- |
| Multi-seed | `-u torvalds -n "Linus Torvalds" -e test@scanme.nmap.org -i <exif jpg>`, depth 2 | 56 s, 414 artifacts, 410 links, 378 platform presences |
| IP branch | `--ip 45.33.32.156`, depth 1 | 8 s, 2 `open_port` artifacts with service and version metadata |

Artifact types recorded by the multi-seed run:

```
username_presence 378 (sherlock, maigret)   platform_presence   9
image               7                       historical_url      3 (wayback_machine)
breach_data         2                       image_url           2
username            2                       camera_info         1 (exiftool)
creation_date       1 (exiftool)            dns_a               1 (dig)
domain              1                       domain_info         1 (whois)
email               1                       fullname            1
gps_coordinates     1 (exiftool)            ip                  1 (DigPlugin)
ip_address          1 (dig)                 location            1
```

Correlated identity profiles from the same run (`correlate_identities`):

```
IDENTITY-001 emails=[test@scanme.nmap.org]
    DNS A Records 1        | 45.33.32.156
    Domain Registration 1  | scanme.nmap.org
    Historical URLs 3      | http://scanme.nmap.org:80/
    Platform Accounts 25   | https://en.wikipedia.org/wiki/User:test
IDENTITY-002 usernames=[torvalds]
    Platform Accounts 25   | https://www.9gag.com/u/torvalds
```

Both runs stay far inside the 15-20 minute budget; the wall-clock deadline
(`investigation.max_runtime_minutes`) and the artifact budget
(`investigation.max_total_artifacts`) bound the worst case.

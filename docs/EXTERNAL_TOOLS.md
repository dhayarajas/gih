# External Tool Invocation Reference

How Ghost Identity Hunter builds, runs and parses each external OSINT tool
command. `docs/TOOL_COVERAGE.md` answers *which* tools are wired up; this
document answers *how* each one is invoked and which arguments are passed.

Everything below lives in `src/modules/external_tools.py` unless noted.

## Execution pipeline

```
_process_external_tools(orchestrator)      # picks tools for the artifact type
  -> check_tool_availability(tool)         # shutil.which(); missing -> not scheduled
  -> run_tool_analysis(tool, analysis, target)
       -> per-run cache lookup (tool, analysis, target)
       -> ANALYSIS_METHODS[tool][analysis] -> integration method
            -> @skip_if_not_available(tool)   # second guard, returns None
            -> self.run_tool(tool, argv)      # subprocess.run(capture_output, timeout)
            -> parser -> ToolResult.artifacts_discovered
```

Cross-cutting rules:

- **Availability** is checked twice: once when the orchestrator builds the task
  list, and again by the `@skip_if_not_available` decorator on each integration
  method. A missing binary therefore never reaches `subprocess.run`; when the
  decorator short-circuits, `run_tool_analysis` converts the `None` into a
  failed `ToolResult` with `"<tool> is not available"` rather than raising.
- **Timeouts** come from `plugins.<tool>.timeout` in `config/config.yaml`,
  resolved by `_get_tool_timeout()` and passed to `subprocess.run(timeout=...)`.
  No integration hardcodes a timeout any more; the fallback is
  `DEFAULT_TOOL_TIMEOUT = 60`. The one exception is `wayback_machine`, which is
  an HTTP call with its own 30s `requests` timeout.
- **Failure handling**: `run_tool` catches `TimeoutExpired`, `FileNotFoundError`
  and any other exception, returning `ToolResult(success=False, error_message=...)`.
  A non-zero exit code is also a soft failure (`whois` exits 1 for unregistered
  domains, for example). Parsers only run when `success` is true.
- **Output caps**: each tool run contributes at most
  `MAX_ARTIFACTS_PER_TOOL = 15` artifacts, so a noisy enumeration cannot blow up
  the BFS frontier or the report.
- **Memoization**: results are cached per run under `(tool, analysis, target)`
  and cleared by `clear_tool_analysis_cache()` at the start of an investigation,
  so a domain rediscovered through several parents is scanned once.
- **No shell**: every command is a `list[str]` passed to `subprocess.run`
  without `shell=True`, so artifact values cannot inject shell syntax.

## Per-tool arguments

| Tool | Argv | Why these arguments | Parsed into |
|------|------|--------------------|-------------|
| sherlock | `sherlock <username> --print-found --timeout 5 --no-color --no-txt` | only found hits, bounded per-site wait, no ANSI codes, and `--no-txt` stops sherlock writing `<username>.txt` into the working directory | `[+] Platform: url` lines → `username_presence` |
| maigret | `maigret <username> --top-sites 150 --timeout 5 --no-progressbar --no-color --no-recursion` | the full site list exceeds the run budget; recursion would duplicate the orchestrator's own BFS | `[+] Platform: url` lines → `username_presence` |
| osrframework | `usufy -n <username> -t social -T 32 -e json -o <tmpdir> --avoid_download` | `usufy` prints a human table but only writes structured results to a file, so a temp dir is the real interface; the `social` tag keeps it inside the time budget; `--avoid_download` skips fetching profile pages | `<tmpdir>/profiles.json` → `username_presence` |
| holehe | `holehe <email> --only-used --no-color` | only registered services are useful; colour codes break parsing | `[+] service` lines → `email_presence` |
| theHarvester | `theHarvester -d <domain> -b duckduckgo` | duckduckgo needs no API key; other sources do | emails (regex) and subdomains (regex anchored on the domain) |
| subfinder | `subfinder -d <domain> -silent -timeout 10` | `-silent` gives one subdomain per line; the tool-level timeout bounds each resolver | `subdomain` |
| sublist3r | `sublist3r -d <domain> -n` | `-n` disables the brute-force/portscan phase | `subdomain` |
| amass | `amass enum -passive -d <domain>` | passive mode only: active enumeration is slow and touches the target | `subdomain` |
| whois | `whois <domain>` | no flags needed; the parser pulls registrar, creation/expiration date, name server and registrant email | `domain_info` with `parsed_data` fields |
| dig | `dig <domain> A +short` | `+short` yields bare values, one per line | A records → `ip_address` (other record types → `dns_<type>`) |
| whatweb | `whatweb --color=never --no-errors -a 1 <target>` | aggression level 1 = passive single request; `--no-errors` keeps unreachable hosts from failing the run | `Plugin[detail]` pairs → `web_technology`, plus `IP[...]` → `ip_address` |
| nmap | `nmap -Pn -F -sV --version-light <target>` (or `-p <ports>` instead of `-F`) | `-Pn` skips host discovery (ICMP is usually filtered), `-F` is the top-100-ports scan and `--version-light` keeps service detection cheap; no `-sS`, so no root privileges are required | `<port>/<proto> open <service> <version>` → `open_port` |
| shodan | `shodan host <ip>` | the CLI reads its key from `shodan init`, so no key appears on the command line | JSON when available, otherwise a regex over the human summary → `host_info`, `open_port` |
| exiftool | `exiftool -json <file>` | `-json` gives a stable machine format; the integration refuses non-local paths up front because image artifacts are often URLs | `GPSLatitude/Longitude`, `Make/Model`, `CreateDate` |
| wayback_machine | no subprocess — HTTP `GET web.archive.org/cdx/search/cdx?url=<domain>/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=15` | public API, no binary to install; `collapse=urlkey` and `limit` bound the result set | `historical_url` |

Tools declared in `ToolChecker` but deliberately not invoked (social_analyzer,
emailharvester, recon-ng, spiderfoot, ghunt, photon, metagoofil, etherscan,
geonames, wappalyzer, masscan, nikto, sqlmap, browser extensions) each carry a
reason string in `UNIMPLEMENTED_TOOLS`, surfaced by `--check-tools`.

## Credentials

No API key is ever placed on a command line.

- `shodan` uses the key stored by `shodan init <key>`; without it the CLI errors
  and the run is recorded as a failed `ToolResult`. `ShodanPlugin` additionally
  reports `is_available() == False` when neither `plugins.shodan.api_key` nor
  `SHODAN_API_KEY` is set, so the plugin path returns `SKIPPED`.
- `etherscan` and `geonames` have no integration; with `api_key: null` they are
  simply never scheduled.
- Google Dorks (`src/modules/google_dorks.py`) is not a subprocess: it uses the
  Custom Search API when `google_api_key`/`google_cx` are configured and falls
  back to scraping otherwise.

## Known argument gaps

- **dig runs only `A` lookups.** `DigIntegration.dns_lookup` accepts a
  `record_type` argument, but `ANALYSIS_METHODS["dig"]["dns_lookup"]` is called
  as `method(target)`, so `MX`/`NS`/`TXT` records listed in
  `TOOL_ARTIFACT_TYPES` are never produced today. Emitting them needs an
  analysis type per record type (or a loop inside `dns_lookup`).
- **theHarvester is executed twice per domain** — `email_harvest` and
  `subdomain_harvest` build the identical command and are cached separately, so
  the same output is fetched once per analysis type.
- **nmap port selection is fixed** at the `-F` top-100 list; `scan_host(ports=)`
  is never passed a custom range by the orchestrator.

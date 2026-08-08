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
            -> tool_parsers.parse_<tool>() -> ToolResult.artifacts_discovered
```

Every tool prints something different -- maigret writes an NDJSON report per
site, nmap an XML tree, whatweb a plugin map, whois repeated labels -- so each
has its own parser in `src/modules/tool_parsers.py`, tested against a captured
sample of that tool's real output in `tests/test_tool_parsers.py`. Where the
structured report is optional (the binary is old, or the run wrote nothing) the
parser for the printed output is the fallback, never the primary reader.

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
  an HTTP call with its own 30s `requests` timeout; the CDX index for a busy host
  can outlast it, and that is reported as a timeout rather than as an error, since
  the archive is not at fault.
- **Failure handling**: `run_tool` catches `TimeoutExpired`, `FileNotFoundError`
  and any other exception, returning `ToolResult(success=False, error_message=...)`.
  A non-zero exit code is a soft failure by default, and parsers only run when
  `success` is true -- but an exit code is not a verdict, so two integrations
  overrule it: `holehe` writes its CSV and then exits 1 whatever it found, so the
  report wins over the code; and `whois` exits 1 with "No match" for every name a
  registry does not hold (which is every subdomain), which is an answer, not a
  fault, and is recorded as a run that found nothing.
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
| maigret | `maigret <username> --top-sites 150 --timeout 5 --no-progressbar --no-color --no-recursion -J ndjson -fo <tmpdir>` | the full site list exceeds the run budget; recursion would duplicate the orchestrator's own BFS; the NDJSON report carries what maigret's site extractors found, which the printed tree only draws | one JSON object per site → `username_presence` for each `Claimed` account, keeping the extracted `fullname`, `image`, `location`, `bio`, follower/post counts and account creation date, and promoting the identifying ones to `fullname` / `image_url` / `location` / `email` / `phone` artifacts |
| osrframework | `usufy -n <username> -t social -T 32 -e json -o <tmpdir> --avoid_download` | `usufy` prints a human table but only writes structured results to a file, so a temp dir is the real interface; the `social` tag keeps it inside the time budget; `--avoid_download` skips fetching profile pages | `<tmpdir>/profiles.json` → `username_presence` |
| holehe | `holehe <email> --only-used --no-color --no-clear -C` | only registered services are useful; colour codes break parsing; `-C` writes a CSV whose `emailrecovery`/`phoneNumber` columns are the part of a holehe run worth having | CSV rows with `exists=True` → `email_presence`, keeping the masked recovery address and phone; `[+] service` lines are the fallback |
| theHarvester | `theHarvester -d <domain> -b duckduckgo -f <tmpdir>/report`, executed once per domain with both analyses reading the same report | duckduckgo needs no API key; other sources do; the JSON report separates hosts from addresses from people, which the printed summary runs together | report sections → `email`, `subdomain` (with the resolved address kept on the host), `ip_address`, `url`, `fullname`, `asn`; the printed sections are the fallback |
| subfinder | `subfinder -d <domain> -silent -json -timeout 10` | `-silent` suppresses the banner and `-json` names the source behind each result, which is what makes one worth trusting; the tool-level timeout bounds each resolver | one JSON object per line → `subdomain` with the discovering source |
| sublist3r | `sublist3r -d <domain> -n` | `-n` disables the brute-force/portscan phase | `subdomain` |
| amass | `amass enum -passive -d <domain>` | passive mode only: active enumeration is slow and touches the target | `subdomain` |
| whois | `whois <domain>` | no flags needed | every label, including the repeated ones: all name servers and all status codes rather than the first of each, plus registrar, dates, DNSSEC and the registrant/admin/tech contacts → `domain_info`, `name_server`, `email`, `fullname` |
| whatweb | `whatweb --color=never --no-errors -a 1 --open-timeout 10 --read-timeout 20 --max-threads 5 --log-json=<tmpdir>/whatweb.json <target>` | aggression level 1 = passive single request; `--no-errors` keeps unreachable hosts from failing the run; the network timeouts stop an unresponsive host being waited on until our own timeout kills the run with nothing logged; the JSON log gives each plugin its own fields instead of one `Plugin[detail]` string to unpick. Matching every plugin against a large page costs about a minute of CPU, so its configured timeout is 120s | plugin map → `web_technology`, `ip_address`, any address found in the page, plus HTTP status, title, server and country on `parsed_data`; the printed summary is the fallback |
| nmap | `nmap -Pn -F -sV --version-light -oX <tmpdir>/scan.xml <target>`, or `-p <ports>` instead of `-F` when `plugins.nmap.custom_params.ports` is set to something other than `common` | `-Pn` skips host discovery (ICMP is usually filtered), `-F` is the top-100-ports scan and `--version-light` keeps service detection cheap; no `-sS`, so no root privileges are required; the XML always separates state, service and version, where the text table omits the version column entirely when nothing was identified | `<port>` elements in state `open` → `open_port` with service, version and extra info kept apart, plus host state and `hostname`; the text table is the fallback |
| shodan | `shodan host <ip>` | the CLI reads its key from `shodan init`, so no key appears on the command line | JSON when available, otherwise the human summary → `host_info`, `open_port`, `hostname`, with organisation, city, country and OS on `parsed_data` |
| exiftool | `exiftool -json <file>` | `-json` gives a stable machine format; the integration refuses non-local paths up front because image artifacts are often URLs | the whole tag set on `parsed_data`, and `gps_coordinates`, `camera_info`, `creation_date`, plus the owner (`Artist`/`Creator`/`OwnerName`), `device_serial`, `software` and `copyright` as artifacts |
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
- `leakosint` reads `plugins.leakosint.api_key`, falling back to `LEAKOSINT_API_TOKEN`
  (or `LEAKOSINT_API_KEY`). The token travels in the POST body, never on a command line.
  Without it `LeakosintPlugin.is_available()` is `False` and the plugin path returns
  `SKIPPED`; quota and outage responses come back as `FAILURE` and are ignored.
- `etherscan` and `geonames` have no integration; with `api_key: null` they are
  simply never scheduled.
- Google Dorks (`src/modules/google_dorks.py`) is not a subprocess: it uses the
  Custom Search API when `google_api_key`/`google_cx` are configured and falls
  back to scraping otherwise.

## Multi-analysis tools

One tool exposes more than one analysis type, which changes how it is
scheduled:

- **theHarvester** answers both `email_harvest` and `subdomain_harvest` from a
  single subprocess: `TheHarvesterIntegration._harvest` memoizes the raw
  `ToolResult` per domain under a lock, and each analysis parses a copy of that
  output.

## Strict matching

Tools disagree about what counts as a hit: a search engine returns pages that
merely mention a handle, a status-200 profile check proves nothing on sites with
soft 404s, and a full name expands into guessed username variants. The
`investigation.strict_match` block in `config.yaml` (overridable per run with
`--strict-match` / `--no-strict-match`) applies one rule to every source:

| Setting | Default | Effect |
|---|---|---|
| `enabled` | `true` | Only findings carrying the target's exact value are recorded |
| `require_validated_presence` | `true` | Platform hits proven by a bare HTTP 200 are dropped (tool-derived rows, which are exact by construction, are kept) |
| `allow_name_variants` | `true` | A `fullname` seed still expands into username candidates; set false to search the seed value alone |
| `min_image_probability` | `0.9` | Face matches below this probability are not recorded |

Only a *handle* seed (username or email) can judge a finding. A domain or a full
name legitimately produces handles and addresses that do not contain the seed —
the username behind an address, emails harvested by theHarvester, name variants
— so those pivots are never filtered. For an email seed, both the address and
its local part count as the target.

The filter lives in `src/utils/matching.py` and is applied by the orchestrator to
every module, external-tool and plugin result (`_apply_match_policy` /
`_keep_full_matches`), so no integration has to implement its own rule. A value
counts as a full match only when the target appears as a whole token — separated
by URL or punctuation boundaries — so `octocat` matches
`https://github.com/octocat` but not `octocat-bot`, `octocat99` or
`the_octocat`. A handle that forms a whole hostname label counts too, so
blog-style profiles such as `https://octocat.tumblr.com` are kept, and a
plugin's nested `metadata.username` is consulted when the URL carries no handle.
With `require_validated_presence`, status-only hits are removed from both the
presence table and the findings list. Types that describe infrastructure rather than an identity claim
(subdomains, ports, DNS records, breaches) are never filtered.

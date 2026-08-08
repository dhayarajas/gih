# Standalone tool commands

Every external command Ghost Identity Hunter runs, written out so it can be run
by hand and the answer compared with what the report shows. The argv here is the
argv gih builds — copied from `src/modules/external_tools.py`, not approximated —
so a difference between a hand run and a report is a gih bug, not a difference in
how the tool was called.

Replace `USERNAME`, `EMAIL`, `DOMAIN`, `IP` and `/path/photo.jpg` with the seed.

**Timeout column:** the per-tool budget from `plugins.<tool>.timeout` in
`config/config.yaml`. gih kills the tool at that point and keeps whatever it had
printed; running it by hand has no such limit, which is why a hand run can
succeed where the report says "timed out".

**Which tool runs when:** dispatch is by artifact type, so a username seed never
reaches nmap and an IP seed never reaches sherlock. See `docs/TOOL_COVERAGE.md`.

---

## Username

### sherlock — accounts on ~400 sites

| | |
| --- | --- |
| Timeout | 60s |
| Reads | stdout |
| Parser | `parse_sherlock` |

```bash
sherlock USERNAME --print-found --timeout 5 --no-color --no-txt
```

`--no-txt` stops sherlock writing `USERNAME.txt` into the working directory.
`--timeout 5` is per site; with ~400 sites this routinely exceeds the 60s budget,
so sherlock is usually killed mid-run — expected, and the accounts it printed
first are still kept.

### maigret — accounts plus what each profile says

| | |
| --- | --- |
| Timeout | 60s |
| Reads | the NDJSON report, falling back to stdout |
| Parser | `parse_maigret_ndjson`, else `parse_sherlock` |

```bash
mkdir -p /tmp/maigret-out
maigret USERNAME --top-sites 150 --timeout 5 --no-progressbar --no-color \
        --no-recursion -J ndjson -fo /tmp/maigret-out
cat /tmp/maigret-out/report_USERNAME_ndjson.json | python3 -m json.tool --json-lines
```

The printed tree names the accounts only. The report is where each site's
extractor puts the real name, avatar, biography, follower counts and location —
which is why gih asks for the report and reads that, not the tree. Without
`-J ndjson -fo`, the tree is all there is.

### usufy (OSRFramework) — accounts on the platform list

| | |
| --- | --- |
| Timeout | 180s |
| Reads | the JSON file it writes |
| Parser | `parse_usufy_profiles` |

```bash
mkdir -p /tmp/usufy-out
usufy -n USERNAME -t social -T 32 -e json -o /tmp/usufy-out --avoid_download
ls /tmp/usufy-out
```

`-t social` rather than the full platform list, which does not finish inside any
sane budget. stdout is a human table; only `-o` produces something parseable.
In practice this tool spends its whole budget and exits 1 with nothing.

---

## Email

### holehe — which services an address is registered on

| | |
| --- | --- |
| Timeout | 60s |
| Reads | the CSV it writes into the working directory |
| Parser | `parse_holehe_csv`, else `parse_holehe_text` |

```bash
mkdir -p /tmp/holehe-out && cd /tmp/holehe-out
holehe EMAIL --only-used --no-color --no-clear -C
cat /tmp/holehe-out/*.csv
```

Two things to know. holehe **exits 1 even on a successful run**, so the exit
status says nothing — the CSV does, and gih trusts the CSV over the code. And
`-C` matters: the terminal output is a yes/no per site, while the CSV also
carries the masked recovery address or phone a site volunteered.

---

## Domain

### whois — the registration record

| | |
| --- | --- |
| Timeout | 30s |
| Reads | stdout |
| Parser | `parse_whois` |

```bash
whois DOMAIN
```

A registry answers for a **registered name** only. A subdomain
(`support.google.com`) always returns `No match` and exit 1 — that is an answer,
not a failure, and gih reports it as "no record". Note that labels repeat: every
name server and every status code is its own line, so reading only the first
match of each label loses all but one.

### subfinder — passive subdomain enumeration

| | |
| --- | --- |
| Timeout | 60s |
| Reads | stdout (JSONL) |
| Parser | `parse_subfinder_json`, else `parse_subdomains` |

```bash
subfinder -d DOMAIN -silent -json -timeout 10
```

### sublist3r — subdomains via search engines

| | |
| --- | --- |
| Timeout | 60s |
| Reads | stdout |
| Parser | `parse_subdomains` |

```bash
sublist3r -d DOMAIN -n
```

`-n` is sublist3r's `--no-color`; the ASCII banner is still printed, and the
parser has to skip it rather than read it as findings.

### amass — passive subdomain enumeration

| | |
| --- | --- |
| Timeout | 60s |
| Reads | stdout |
| Parser | `parse_subdomains` |

```bash
amass enum -passive -d DOMAIN
```

Passive enumeration of a *subdomain* has nothing beneath it to enumerate, so
"found nothing" there is correct rather than a failure.

### theHarvester — contacts and hosts

| | |
| --- | --- |
| Timeout | 60s |
| Reads | the JSON report |
| Parser | `parse_theharvester_json` |

```bash
mkdir -p /tmp/th-out
theHarvester -d DOMAIN -b duckduckgo -f /tmp/th-out/report
python3 -m json.tool /tmp/th-out/report.json
```

One source (`duckduckgo`) because the keyed sources need credentials and the
scraped ones rate-limit. gih caps contacts and hosts **independently**, so a
large email set cannot crowd out the subdomains.

### whatweb — web technology fingerprint

| | |
| --- | --- |
| Timeout | 120s |
| Reads | the JSON log, falling back to stdout |
| Parser | `parse_whatweb_json`, else `parse_whatweb_summary` |

```bash
whatweb --color=never --no-errors -a 1 \
        --open-timeout 10 --read-timeout 20 --max-threads 5 \
        --log-json=/tmp/whatweb.json DOMAIN
python3 -m json.tool /tmp/whatweb.json
```

The target is the bare host, not a URL: gih passes the artifact's value, and
whatweb picks the scheme and follows the redirect itself.

The one-line summary packs everything into `Plugin[detail]` pairs a reader has to
guess at; the JSON log keeps the plugin, its value and its module apart, which is
what makes the page title, the country and the HTTP status usable. Matching every
plugin against a large page costs real CPU — hence the 120s budget. A redirect
chain produces one JSON document *per target*, which the parser cannot read as a
whole, so the summary is the fallback.

### Wayback Machine — historical URLs

| | |
| --- | --- |
| Timeout | 30s (HTTP, not a subprocess) |
| Reads | the CDX API's JSON rows |
| Parser | `parse_wayback_cdx` |

```bash
curl -s 'http://web.archive.org/cdx/search/cdx?url=DOMAIN/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=15' \
  | python3 -m json.tool
```

No binary — this is a plain HTTP call. The CDX index for a busy host can take
minutes to answer, so a 30s cap is a timeout on our side, not a broken archive;
`github.com` answers instantly while `support.google.com` does not answer inside
60s. The first row is a header, not a finding.

---

## IP address

### nmap — open ports and service versions

| | |
| --- | --- |
| Timeout | 90s |
| Reads | the XML report, falling back to the printed table |
| Parser | `parse_nmap_xml`, else `parse_nmap_text` |

```bash
nmap -Pn -F -sV --version-light -oX /tmp/scan.xml IP
xmllint --format /tmp/scan.xml | head -40
```

`-F` is nmap's top-100 list, which is what `plugins.nmap.custom_params.ports:
common` selects; any other value becomes `-p <value>`. Only scan hosts you are
authorised to scan.

### shodan — what Shodan already knows about the host

| | |
| --- | --- |
| Timeout | 30s |
| Reads | stdout (printed summary or JSON) |
| Parser | `parse_shodan_host` |

```bash
shodan init "$SHODAN_API_KEY"
shodan host IP
```

Needs `SHODAN_API_KEY`. Beyond ports and hostnames this is the one tool that
gives an IP investigation something to put on the map: its `city`/`region`/
`country` become a low-confidence `location` artifact, low because a host's city
is where the *server* is, not where its owner is.

---

## Image

### exiftool — embedded metadata

| | |
| --- | --- |
| Timeout | 30s |
| Reads | stdout (JSON) |
| Parser | `parse_exiftool_json` |

```bash
exiftool -json /path/photo.jpg
```

exiftool reads **local files only**. Image artifacts include scraped
profile-picture URLs, which gih never passes here — that would be a
guaranteed-failing subprocess. GPS tags are the only source of an exact map
point in an investigation; everything else on the map is a geocoded place name.

---

## Keyed HTTP services (no binary)

### LeakOSINT — breach records

| | |
| --- | --- |
| Timeout | 20s |
| Needs | `LEAKOSINT_API_TOKEN` (or `LEAKOSINT_API_KEY`) |

```bash
curl -s https://leakosintapi.com/ -H 'Content-Type: application/json' \
  -d "{\"token\":\"$LEAKOSINT_API_TOKEN\",\"request\":\"EMAIL\",\"limit\":100,\"lang\":\"en\",\"type\":\"json\"}" \
  | python3 -m json.tool
```

`limit` is clamped to 100–10000. **This answer contains other people's
passwords** — do not paste it anywhere, and do not save it beside the report.
gih reduces each record to the database that leaked it wherever it is masked.

### Google Custom Search — the dork patterns

| | |
| --- | --- |
| Timeout | 30s |
| Needs | `GOOGLE_API_KEY` and `GOOGLE_CX` |

```bash
curl -s -G https://www.googleapis.com/customsearch/v1 \
  --data-urlencode "key=$GOOGLE_API_KEY" \
  --data-urlencode "cx=$GOOGLE_CX" \
  --data-urlencode 'q=site:github.com "USERNAME"' \
  --data-urlencode 'num=10' | python3 -m json.tool
```

Only reached with `--use-google-dorks`. Without a key the module scrapes and is
rate-limited to three patterns per artifact; a 429 is normal.

---

## Tools gih does *not* run

These appear in the tool table (and in most OSINT toolboxes) but are deliberately
not dispatched. The reason each one carries is the string
`get_tool_coverage()` returns, which is also what the report shows — so a tool
absent from a report is explained rather than merely missing.

| Tool | Why it is not run |
| --- | --- |
| `dig`, `nslookup` | DNS resolution names the mail or web *provider*, not the subject; every domain would gain the same worthless finding (`dig` was dispatched until it was removed for exactly this) |
| `masscan` | Needs raw-socket (root) privileges; nmap covers the same ground unprivileged |
| `wappalyzer` | Superseded by whatweb, which detects the same stack from the CLI |
| `emailharvester` | Superseded by theHarvester |
| `photon` | Its crawl duplicates the wayback historical URLs |
| `ghunt` | Needs authenticated Google session cookies supplied by the operator |
| `recon-ng` | Interactive framework: per-module API keys and a workspace |
| `spiderfoot` (`sf.py`) | Server/daemon oriented, with its own database and web UI |
| `social-analyzer` | No stable CLI contract; the node and python variants differ and their output shape is not fixed |
| `metagoofil` | Document harvesting needs a search-engine API key and downloads files |
| `nikto`, `sqlmap` | Vulnerability scanning and exploitation — out of scope for identity attribution |
| `geonames`, `etherscan` | Need their own account/API key, and geodata already comes from exiftool and phone metadata |
| `curl`, `wget` | Generic transports used *inside* other integrations, not data sources |
| Tor Browser, Flagfox, User-Agent Switcher | Interactive browser and browser extensions, not data sources |

`leakosint` and `google_dorks` are also reported as not integrated *as external
tools* — they are HTTP services implemented in `src/modules/` and dispatched
directly, documented above.

Read the live list rather than this table if they disagree:

```bash
python3 - <<'EOF'
from src.modules.external_tools import get_tool_coverage
for name, info in sorted(get_tool_coverage().items()):
    if not info["integrated"]:
        print(f"{name:22} {info['reason']}")
EOF
```

---

## Cross-referencing a report

The `evidence` table records **the exact argv of every run**, so there is no need
to take this file on trust: ask the database what it ran.

```bash
# 1. the command gih actually ran, with its exit status and duration
sqlite3 -header -column ~/.ghost_hunter/investigations.db \
  "SELECT tool, command, exit_status, duration_seconds
     FROM evidence WHERE investigation_id='INV-xxxxxxxx' ORDER BY tool;"

# 2. what it kept from that run
sqlite3 -header -column ~/.ghost_hunter/investigations.db \
  "SELECT artifact_type, value, confidence FROM artifacts
     WHERE investigation_id='INV-xxxxxxxx' AND source='maigret';"

# 3. the raw output, re-hashed against the digest taken at collection time
python3 -m src.cli evidence --id INV-xxxxxxxx --show-path

# 4. then run the tool by hand from this file and compare
```

A hand run that finds more than the report usually means the tool was killed by
its budget (`evidence.exit_status = 'timeout'`), or that strict matching dropped a
finding that did not carry the seed's exact value — the run log says
`Strict match: dropped N partial finding(s)`.

## Checking what is installed

```bash
python3 -m src.cli investigate --check-tools
```

One row per tool: whether the binary is present, whether gih integrates it, what
it produces, and the reason when it does not. Each tool is probed once per
process with `<tool> --version`. A tool that is not installed is not dispatched
and is left out of the report's tool table rather than counted as silent.

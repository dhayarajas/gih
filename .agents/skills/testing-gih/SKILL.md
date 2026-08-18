---
name: testing-gih
description: How to run and verify Ghost Identity Hunter (gih) end-to-end — live CLI investigations, DB/correlation inspection, and HTML/JSON report checks.
---

# Testing Ghost Identity Hunter (gih)

## Environment

- The repo blueprint creates a `.venv`, but on running boxes the dependencies and
  external OSINT tools are often installed **system-wide / in `~/.local/bin`** and no
  `.venv` exists. Check with `ls .venv` first; if it is missing, use plain `python3`
  (works — do not create a venv, it will lack the installed tools).
- External binaries live in `~/.local/bin` (sherlock, maigret, holehe, sublist3r,
  theHarvester) and `/usr/bin` or `/usr/local/bin` (whois, dig, nmap, whatweb,
  exiftool, subfinder, amass). Verify with `which <tool>`.
- Expected clean skips: `shodan` (no API key), `amass` (often times out at 60 s),
  `face_recognition`/dlib absent → image *matching* disabled (EXIF still works).
- Google Dorks frequently returns HTTP 429; the module degrades to 0 artifacts. Not a bug.
- `pip install -r requirements.txt` aborts building **dlib**. Install with
  `grep -vi 'dlib\|face' requirements.txt > /tmp/req.txt && pip install -r /tmp/req.txt`
  plus `pip install pytest ruff`. `face_recognition` absent is expected (image *matching* disabled).
  Baseline on a healthy tree: `python3 -m pytest -q` → 219 passed.

## Testing username/platform detection (`src/modules/username_search.py`)

Platform verdicts can be exercised without a full investigation, which is much faster and
gives per-platform evidence strings:

```python
from src.modules.username_search import _get_username_search_config, _check_platform
cfg = {p['name']: p for p in _get_username_search_config()['platforms']}
r = _check_platform('gaben', cfg['Steam'])
print(r.found, r.validation_method, r.validation_evidence)
```

Known behaviour of the bundled platforms from a datacenter IP (verify before blaming a change):

- **Twitter/X**: `twitter.com/<any handle>` → `301` to `x.com/<same handle>`, for real *and* fake
  handles. With `redirect_means: not_found` that means X can never be reported. Consider it
  environment/config, not a code regression; pointing the template at `x.com` is the likely fix.
- **Instagram**: always `302` to `/accounts/login` when logged out → permanently not found.
- **LinkedIn**: `HTTP 999`; **Medium**: `HTTP 403` — both bot-block this IP range, so their
  content markers cannot be exercised live. Report as untested rather than passing.
- **Steam** rate-limits to `429` after a handful of requests in a run; a missing Steam hit in a
  live investigation may be throttling, not a marker bug. Re-probe the single platform to confirm.
- Reliable live fixtures: `Keybase/chris`, `Keybase/max`, `Steam/gaben`, `Mastodon/Gargron`,
  `Pinterest/nike`, `HackerNews/dang`, `HackerNews/pg`, `GitHub|GitLab/gaben`.
- Soft-404s that answer **HTTP 200** (good false-positive fixtures): Steam
  ("The specified profile could not be found."), Pinterest ("User not found"), HackerNews
  ("No such user.").
- Failure markers are matched **before** success markers, so a short/generic failure marker
  (e.g. `"404"`, `"not found"`) can reject a real profile page. Probe that class of bug directly:
  `_validate_web_content(username, platform_dict, synthetic_body)`.
- A nonexistent seed handle still produces presences for handles Google Dorks harvested
  (commonly `websearch`). Always attribute presences via `platform_presence.username`, not the count.
- Known pre-existing unit failures on `main`: `tests/test_storage.py::TestPlatformPresence::{test_add_presence,test_get_presences}`.
  Always confirm against an `origin/main` worktree (`git worktree add /tmp/gih-main origin/main`)
  before blaming a PR.

## Running a full-coverage live investigation

One command exercises every artifact-type branch (~3 min):

```bash
python3 -m src.cli investigate -u octocat -e test@gmail.com -d github.io \
  --ip 8.8.8.8 -i /path/to/photo-with-exif.jpg
```

Flags confirmed via `--help`: `-p/--phone -e/--email -u/--username -n/--full-name
-i/--image -d/--domain --ip --depth --no-breach --check-tools`.
Reports: `python3 -m src.cli report --id INV-xxxx --format [html|json|both] -o PATH`.

Tips:
- Pick the email seed deliberately. `holehe` returns many hits for `test@gmail.com`
  (~18) but only one for niche addresses — needed when testing per-platform account
  artifacts. Pre-check with `holehe <email> --only-used | grep '^\[+\]'`.
- The image seed needs real EXIF (GPS + camera) to produce
  `gps_coordinates`/`camera_info`/`location` artifacts.

## Full-name seeds

`--full-name "First Last"` derives up to 5 username candidates
(`firstlast, first.last, first_last, flast, firstl`, source
`name_username_candidate`, confidence 0.4) and runs the username toolchain on
each. A full-name run with `--use-google-dorks --search-engine duckduckgo`
takes ~3 min and yields several hundred artifacts; `--no-external-tools` still
derives the handles and runs the in-process `username_search` (~40 s).

Expect Google Dorks to also harvest *unrelated* handles from search results and
feed them to sherlock/maigret; they are merged into the same identity profile,
which can even be named after a harvested handle rather than the subject. When
testing name seeds, always quantify how many account hits belong to
non-derived handles before calling the output "the subject's accounts".

Use a name with a real footprint (e.g. "Linus Torvalds") to prove the toolchain
works; a low-footprint name proves nothing either way.

## Isolating runs

Pass a per-run DB so runs never mix and old-vs-new comparisons stay clean:
`python3 -m src.cli --db /tmp/run-a.db investigate ...`. The auto-generated HTML
report still lands in `<cwd>/reports/INV-*.html`, so run the baseline from the
worktree directory to keep its reports separate.

## Search-engine scraping gotchas

- From datacenter IPs, Google Images usually answers **HTTP 429** and Bing often
  serves *decoy* results unrelated to the query. Do not read "0 images found" as
  a code failure without checking the log for 429s/decoys.
- Content-encoding matters: if the session advertises `br`/`zstd` that urllib3
  cannot decode, `resp.text` is binary and every BeautifulSoup scrape silently
  returns nothing. To test this class of bug, run a subprocess that blocks the
  decoder imports with a `sys.meta_path` finder, then fetch the same URL with
  the hardcoded vs the dynamic `Accept-Encoding` header and compare
  `resp.text[:20]` and the parsed element count — decisive old-vs-new evidence
  without uninstalling anything.

## Secrets Needed

- `GOOGLE_API_KEY` + `GOOGLE_CX` — only needed to exercise the Google Custom
  Search paths (`--use-google-api`, image CSE search). Without them those code
  paths cannot be covered end-to-end; say so rather than implying coverage.

## Inspecting results

DB: `~/.ghost_hunter/investigations.db` (or whatever `--db` you passed). Tables: `investigations`, `artifacts`,
`artifact_links` (NOT `links`), `platform_presence`, `investigation_metadata`,
`audit_trail`.

```python
import sqlite3, json
from src.correlation.linker import correlate_identities
conn = sqlite3.connect('/home/ubuntu/.ghost_hunter/investigations.db')
conn.row_factory = sqlite3.Row
res = correlate_identities(conn, 'INV-xxxx')   # returns CorrelationResult
ids = res.to_dict()['identities']              # dicts with platforms, subdomains,
                                               # ip_addresses, open_ports, geolocations,
                                               # device_info, tool_findings, tools_used
```

Useful invariants to assert:
- No artifact with `depth > 0` is absent from `artifact_links`.
- `artifacts.metadata` should parse to a dict with meaningful top-level keys; a shape
  like `{"value": "{...json string...}"}` means serialized metadata is being nested
  (a bug class that has regressed before — see `_artifact_metadata` in `src/orchestrator.py`).
- Tool artifacts that should be per-platform (e.g. holehe `email_presence`) must have
  distinct values, otherwise BFS dedup collapses them into one graph node.

## Comparing old vs new behaviour (strong regression evidence)

Add an `origin/main` worktree and exec the old function out of its source, then run
both against the same real tool output:

```bash
git worktree add /tmp/gih-main origin/main
```

This yields a side-by-side "OLD vs NEW" print that proves a fix rather than just
showing the new output.

## Report checks

HTML report at `reports/INV-*.html`, opened via `file:///...` in Chrome. When typing
the path in the omnibox, clear it with ctrl+a first — Chrome autocomplete can mangle
`INV-` into `IV-` and produce ERR_FILE_NOT_FOUND. Use ctrl+f to jump to
`IDENTITY-00N` / `Accounts Found`; the per-identity "External Tool Findings (N)"
blocks are `<details>` elements and must be clicked to expand.

### Drill-down / expandable sections

The standard (`standard` == `html`) template renders artifacts, platform presences and
identity evidence as `<details class="drilldown">`. Practical tips:

- Ctrl+F in Chrome auto-opens a matching `<details>`, which is the fastest way to reach a
  specific artifact/presence without scrolling through dozens of rows.
- Verify "Expand all"/"Collapse all" by counting in the console rather than by eye:
  `document.querySelectorAll('details.drilldown').length` vs
  `document.querySelectorAll('details.drilldown[open]').length`.
- The page HTML returned alongside computer-use screenshots only includes *open* `<details>`
  bodies — closed ones appear as an empty `<summary>`. Use that as a cheap open/closed signal.

### Seeding report edge cases

Templates must survive dirty rows. Insert directly into `~/.ghost_hunter/investigations.db`
(back it up first) to cover: `metadata` NULL / malformed JSON / a JSON scalar, NULL `source`,
an `artifact_links` row with NULL `evidence`, a fully populated `platform_presence`
(bio/followers/verified/created/last_active) and one with all-NULL fields plus a
non-resolvable `avatar_url` (the template's `onerror` should hide the img).

- **Avoid seeding `confidence = NULL`.** `_generate_key_findings` in
  `src/reporting/html_report.py` compares `confidence >= 0.8` unguarded and may raise
  `TypeError: '>=' not supported between instances of 'NoneType' and 'float'`. This has been
  present on `main`, so if you hit it, it is likely not the PR under test — seed a real float
  and report the latent bug separately.
- Long URLs inside the identity evidence table can overflow horizontally at normal browser
  width; likely cosmetic unless the PR touches table CSS.

### External tool gotchas

- `-v` is a **global** option: `python3 -m src.cli -v investigate ...`, not
  `investigate -v`. Same for `--db`.
- theHarvester cannot be installed with pipx (`pipx install theHarvester` reports
  "No apps associated with package theharvester" — the wheel ships no console
  script). To exercise its integration, put an executable stub named
  `theHarvester` on PATH that prints sample output; the integration only cares
  about stdout.
- To prove a tool's argv without a network run, monkeypatch
  `ExternalToolsIntegration.run_tool` on a fresh integration instance and patch
  `src.utils.tool_checker.check_tool_availability` (the `@skip_if_not_available`
  decorator resolves that name inside `tool_checker`, so patching the
  `external_tools` alias has no effect).
- `run_tool_analysis` memoizes on `(tool, analysis, target)` for the whole
  process; call `clear_tool_analysis_cache()` between assertions in one script.

## Testing binary / unparsable tool output (control-byte safety)

`whatweb` is often **missing** even though the blueprint installs it; the cheapest way to
exercise the unparsable-output path is a stub first on PATH:

```bash
mkdir -p /tmp/bin-bin && cat > /tmp/bin-bin/whatweb <<'EOF'
#!/bin/bash
case "$1" in --version) echo "WhatWeb version 0.5.5"; exit 0;; esac
head -c 4096 /dev/urandom
printf '\x1f\x8b\x08\x00'
printf 'http://example.com [200 OK] IP[93.184.216.34], Country[X\x00Y], Title[Bad\x1b\x07]\n'
EOF
chmod +x /tmp/bin-bin/whatweb
```

Useful stub variants: fully readable summary + a `--log-json` file whose values contain NUL
(partial rejection path), and a realistic JSON log with two U+FFFD chars in `Title`
(must NOT be rejected — `is_textual` allows up to 10% unreadable chars).

Gotchas:
- **`--depth 0` never persists tool artifacts.** `src/orchestrator.py` skips the whole
  discovered-artifact write phase when `current_depth >= config.max_depth`, so
  "no bad rows in SQLite" is vacuously true at depth 0. Use `--depth 1`.
- Byte-scan generated files instead of eyeballing them; raw control bytes are invisible in
  Chrome. Count bytes `< 0x20` excluding `\t\n\r`, plus `0x7f`, in `report.html`,
  `report_redacted.html`, the JSON/CSV exports and the newest `logs/*.log`.
- Known leak sites (may still be unfixed): the **tool-log excerpt** escapes only part of the
  control range — `\v` (0x0b) and `\f` (0x0c) are in `ALLOWED_WHITESPACE`
  (`src/utils/text.py`) so they survive into HTML; and **artifact metadata / parsed_data
  values** (e.g. a whatweb `title`) are not escaped at all, so a readable capture with one
  poisoned field leaks raw NUL into both the full and the `_redacted` HTML.
- Evidence-status check: query the evidence/capture rows for `exit_status` —
  `unparsable output` for a rejected capture, `exit 0` for an accepted one — and cross-check
  against the report's "Tool Run Status" reason and the "Artifacts per Tool" chart; the two
  must agree.
- The artifacts table column is `artifact_type`, not `type`. There is no `sqlite3` CLI on
  some boxes — use Python's `sqlite3` module.
- `evidence` has no `--verify` flag; use `evidence --id INV-xxxx --show-path` (it recomputes
  digests and reports verified/modified/missing).

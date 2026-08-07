---
name: testing-osint-reports
description: How to run and verify Ghost Identity Hunter end-to-end - live investigations, external OSINT tool dispatch, the four HTML report templates, and the SQLite artifact model. Use when testing changes to the orchestrator, external_tools, correlation linker or html_report.
---

# Testing Ghost Identity Hunter end-to-end

## Environment

Python venv is at `.venv` in the repo root. Always invoke as `.venv/bin/python -m src.cli ...`
(the package must be imported as `src.*`, so run from the repo root).

**Put `.venv/bin` on PATH before any live run.** `sherlock`, `maigret` and `holehe` are pip
packages installed into `.venv/bin`, but `src/utils/tool_checker.py` resolves tools with
`shutil.which`, which reads the *process* PATH. Without the export they are silently skipped
and you will get a much faster run that never exercises the username/email tool branches:

```bash
export PATH="$PWD/.venv/bin:$PATH"
.venv/bin/python -m src.cli investigate --check-tools   # confirm the count before testing
```

`nmap`, `whois`, `dig`, `exiftool` are system packages. `sqlite3` CLI is **not** installed —
query the DB with `.venv/bin/python` + the `sqlite3` module instead.

## A representative live run

Roughly 1 minute with the tools above installed; it exercises the username, fullname, email,
domain, ip_address and image branches at once.

```bash
export PATH="$PWD/.venv/bin:$PATH"
.venv/bin/python -m src.cli --db /tmp/verify.db investigate \
  -u torvalds -n "Linus Torvalds" -e test@scanme.nmap.org \
  --ip 45.33.32.156 -i /tmp/exif_sample.jpg --depth 2 \
  --report-format html --report-output /tmp/verify_report.html
```

`scanme.nmap.org` / `45.33.32.156` is published by nmap's operators for scan testing — use it
rather than an arbitrary host.

### Making the EXIF fixture

Nothing in the repo ships one. Create it so the exiftool branch has GPS + camera data:

```bash
.venv/bin/python -c "from PIL import Image; Image.new('RGB',(600,400),(30,90,160)).save('/tmp/exif_sample.jpg','JPEG')"
exiftool -overwrite_original -Make=Canon -Model="Canon EOS 5D Mark IV" \
  -DateTimeOriginal="2023:06:15 14:22:31" -CreateDate="2023:06:15 14:22:31" \
  -GPSLatitude=37.7749 -GPSLatitudeRef=N -GPSLongitude=-122.4194 -GPSLongitudeRef=W \
  /tmp/exif_sample.jpg
```

## Known traps

- **`--report-format both` retargets the JSON.** The two generators would otherwise write to
  the same `--report-output`; `_json_output_path` in `src/cli.py` sends the JSON to the `.json`
  sibling, so `--report-output /tmp/r.html` yields `/tmp/r.html` + `/tmp/r.json`.
- **The four templates *are* reachable from the CLI** (older revisions of this note said they
  were not — check `--help` before assuming): `investigate --report-template …` and
  `report --template standard|executive|technical|legal`. Regenerating every template for a
  finished run is offline and takes seconds, so run each seed type once and loop the templates:
  ```bash
  for t in executive technical legal; do
    PYTHONPATH=. python3 -m src.cli --db /tmp/t-user.db report --id INV-xxxx \
      --format html --template $t -o /tmp/rep/user-$t.html
  done
  ```
  The public API (`generate_html_report(conn, inv_id, path, template_type=t)`) still works if
  the flag is ever missing.
- **`report --format both -o /tmp/x.html` treats the path as a directory** and writes
  `x.html/INV-*_report.html|.json` inside it (long-standing; do not blame a report PR for it).
- **`--format pdf` needs pandoc**, which is usually absent. Expect
  `PDF export failed: PDF export requires pandoc on PATH` + the HTML path; the `report`
  subcommand exits 1, `investigate --auto-report` exits 0.
- **Wayback Machine is flaky.** Its CDX query (`url={domain}/*&collapse=urlkey`) frequently
  straddles the hard-coded 30s timeout, so `historical_url` may be 0 through no fault of your
  change. Verify with curl before calling it a regression.
- **The embedded pyvis graph injects Bootstrap CSS into the report.** That leaks generic
  selectors (`.badge`, body colour) into the whole page, so template markup can render
  correctly in the HTML source yet be invisible on screen. Always confirm report content with
  a screenshot at full resolution, never with `grep` on the HTML alone. Report CSS defends
  against this by qualifying its rules (`span.badge`, not `.badge`) — keep new rules qualified.
- **Profile images can be remote URLs.** The standard template hides them via
  `onerror="this.style.display='none'; this.parentElement.style.display='none'"`. Real avatars
  usually load, so to actually test the fallback, rewrite one `src` to an invalid host in a
  copy of the report and reload.
- **Ruff has a large pre-existing backlog** (~514 findings on main). Never report the raw
  count; diff rule+file against a `git worktree` of the base branch.

## Measuring layout regressions across many reports

A report run easily produces 40+ HTML files; checking overflow/contrast by eye does not scale.
Drive headless Chromium instead (`pip install playwright && python3 -m playwright install
chromium`; passing `executable_path=` to a system Chrome does **not** work — install the
bundled browser):

- Overflow: load at `viewport={'width':1280,'height':900}`, click the **Expand all details**
  button, then assert `document.documentElement.scrollWidth <= clientWidth`.
- To find *what* overflows, walk `document.querySelectorAll('*')` and report every element
  whose `getBoundingClientRect().right > clientWidth`. Recurring offenders in the standard
  template, all of them non-obvious because the page only grows once every drill-down is
  open: long unbroken strings in table cells and in `span.chain-step` (section 7 “Evidence
  Chains”), the identity-profile flex column (a flex child needs `min-width: 0` or it refuses
  to shrink), and wide nested metadata tables inside `.kv-table` (an auto-layout table sizes
  to its widest cell — `table-layout: fixed` plus a scrollable wrapper contains it).
  Check narrow viewports too: 1024px surfaces column-count overflow that 1280px hides.
- Contrast (the PR #28 white-on-white bug class): compute the WCAG luminance ratio of each
  text node's `color` against the nearest ancestor with an opaque `backgroundColor`, skipping
  ancestors with a `background-image` (the report header uses a gradient and produces false
  positives).
- Always reproduce overflow at ~1280px. A maximized window on a 1600px screen gives a
  ~1585px viewport where the old bugs do **not** reproduce; `wmctrl -r :ACTIVE: -e 0,0,0,1300,1180`
  gets you to a realistic desktop width.

## Old-vs-new evidence for report changes

Re-render the *same* DB with the base branch — much stronger than screenshots of the new
output alone, and it takes no extra live run:

```bash
git worktree add /tmp/gih-main origin/main
cd /tmp/gih-main && PYTHONPATH=. python3 -m src.cli --db /tmp/t-user.db \
  report --id INV-xxxx --format html -o /tmp/rep/user-OLDMAIN.html
```

Cheap machine assertions on the rendered HTML that catch metadata-quality regressions:
`grep` the `<td>` cells for literal `[]`, `{}`, `None`, and for floats with 5+ decimals.

## Verifying correlation

Tool output only reaches a report if it is linked to an *identity-anchor* artifact
(`phone`, `email`, `username`, `image`, `fullname` — see `IDENTITY_ARTIFACT_TYPES` in
`src/correlation/linker.py`). An investigation seeded *only* with `--ip` therefore forms no
identity and its findings appear on no profile; with an email/username seed that reaches the
same IP they are attributed. Check both layers:

```python
import sqlite3
c = sqlite3.connect('/tmp/verify.db'); c.row_factory = sqlite3.Row
inv = c.execute("select investigation_id from investigations order by rowid desc limit 1").fetchone()[0]
print(dict(c.execute("select artifact_type,count(*) from artifacts where investigation_id=? group by 1", (inv,)).fetchall()))
# then compare against identity.tool_findings / identity.open_ports / .geolocations in the JSON report
```

`IdentityProfile` exposes `tool_findings: list[dict]` plus typed fields
(`domains`, `subdomains`, `ip_addresses`, `dns_records`, `open_ports`, `hosts`,
`historical_urls`, `web_technologies`, `geolocations`, `device_info`) and a `tools_used`
property. Assert on those, not on an older `tool_finding_sections` API.

## Secrets Needed

None for the flow above. `shodan` requires an API key (`shodan init`) and the Google Dorks
API path needs `GOOGLE_API_KEY` / `GOOGLE_CX`; without them those branches are skipped and
should be reported as untested rather than passing.

## Testing a keyed API tool (e.g. LeakOSINT) with no real token

Tools reached over HTTP with a credential (`ToolInfo(api_based=True, api_key_envs=(...))` in
`src/utils/tool_checker.py`) can be tested end-to-end **without** a real key. Do not ask for one;
stub the transport instead. All such integrations obtain their session from
`src.utils.http_client.get_http_session`, so wrapping that one function intercepts the keyed
tool while leaving the rest of the investigation live.

Recipe — a wrapper that runs the *real* CLI (`from src.cli import cli; cli()`) after patching:

```python
import os, sys
os.environ.setdefault("LEAKOSINT_API_TOKEN", "FAKETOKEN-CANARY-9c1f4b7e")  # unique canary
import src.utils.http_client as hc
_real = hc.get_http_session
class _W:
    def __init__(s, ses): s._s = ses
    def __getattr__(s, n): return getattr(s._s, n)
    def post(s, url, *a, **kw):
        if "leakosintapi.com" in str(url):
            return StubResponse(PAYLOAD)      # or raise requests.exceptions.ReadTimeout(...)
        return s._s.post(url, *a, **kw)
hc.get_http_session = lambda: _W(_real())
from src.cli import cli; cli()
```
Run it as `LEAK_MODE=records PYTHONPATH=. python3 /tmp/leakstub_cli.py --db /tmp/x.db investigate ...`.
Patching the module attribute works because the integrations import the helper *inside* the
function; modules that imported it at top level keep the real session, which is what you want.
Drive the failure matrix from one env var: successful records, empty `List`, HTTP-200-with-error
field, non-200, non-JSON (`.json()` raising `ValueError`), and a transport exception.
Set `MIN_REQUEST_INTERVAL = 0` only in unit tests — through the CLI the 1 req/s throttle is fine.

Assertions worth automating for such a tool:
- token-absent run: `env -u <VAR1> -u <VAR2>` → tool row is `available=no / not_installed`,
  struck through (`tool-row-off`, `status-not_installed`), and the tool's report section is absent
  entirely (grep the section title, count == 0) rather than rendering empty.
- failure modes: exit code 0, `grep -c Traceback` == 0, artifact count for the new type == 0, and
  **no empty section** — grep for the section's card class (e.g. `class="card leak-card"`), not
  just the title, because the CSS block contains the class name and inflates a naive grep.
- credential non-disclosure: grep the unique canary across every report (html/json/csv), `logs/*`,
  and `select value, metadata from artifacts` + `audit_trail.details`. Expect 0 everywhere.
- with a fake token present, an API *failure* currently shows up only as
  `silent_or_not_dispatched` in Tool Run Status — that state does not distinguish "errored" from
  "never dispatched", so read the log to confirm which happened.

Make one stubbed field value very long (200+ chars) and one empty: it exposes both the
`overflow-wrap` handling and the `-` empty-value rendering, and it is what surfaces squeezed
table columns in the inline executive/technical/legal templates (those use plain `<table>` with
no fixed layout, so a long value can collapse the label column and wrap headers mid-word).

Note: this box has **no `.venv`** — use plain `python3` with `PYTHONPATH=.`; the external tools
are already on the system PATH.

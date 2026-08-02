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
- **There is no CLI flag for the executive/technical/legal templates.** Only `standard` comes
  out of the CLI. Render the others through the public API:
  ```python
  from src.reporting.html_report import generate_html_report
  for t in ("standard","executive","technical","legal"):
      generate_html_report(conn, inv_id, f"/tmp/report_{t}.html", template_type=t)
  ```
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

## Devin Secrets Needed

None for the flow above. `shodan` requires an API key (`shodan init`) and the Google Dorks
API path needs `GOOGLE_API_KEY` / `GOOGLE_CX`; without them those branches are skipped and
should be reported as untested rather than passing.

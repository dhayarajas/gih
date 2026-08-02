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

## Inspecting results

DB: `~/.ghost_hunter/investigations.db`. Tables: `investigations`, `artifacts`,
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

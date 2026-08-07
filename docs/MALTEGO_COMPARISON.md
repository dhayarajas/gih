# Ghost Identity Hunter vs. Maltego — Functional Comparison

**Author:** Dhayanidhi Rajasekaran
**Date:** 2026-08-07
**Subjects:** Ghost Identity Hunter (`dhayarajas/gih`, `main`) vs. the Maltego platform (Maltego Graph Desktop/Browser, Search, Monitor, Evidence, Hunchly, Data Hub)

## 1. Scope and method

Maltego capabilities were taken from the vendor's own product, pricing and knowledge-base documentation (`maltego.com/products`, `docs.maltego.com` articles on entities, transforms, machines, collections, layouts/views, collaboration, import/export). Ghost Identity Hunter (gih) capabilities were read from the source: `src/cli.py`, `src/orchestrator.py`, `src/modules/`, `src/plugins/builtins/` (23 plugins), `src/correlation/`, `src/graph/visualizer.py`, `src/reporting/`, `docs/TOOL_COVERAGE.md`, `docs/EXTERNAL_TOOLS.md`.

The two products are not the same class of thing, and the comparison is only useful if that is stated up front:

- **Maltego** is a commercial, GUI-first *link-analysis platform*. The analyst drives it: pick an entity, run a transform, look at the graph, decide the next step. Its value is the Data Hub (120+ commercial and OSINT data providers behind one credit balance) and the interactive graph.
- **gih** is a free, CLI-first *automated attribution pipeline*. The operator supplies seeds once; a depth-limited BFS runs modules, external tools and plugins, correlates the results into identity profiles with confidence and risk scores, and emits a report. Its value is unattended breadth-first enrichment plus a finished, defensible document.

Put plainly: Maltego is a workbench, gih is a batch job. Several "missing" features below are missing because gih chose automation over interactivity, not because they were overlooked.

## 2. Capability matrix

Legend: **Full** = comparable capability; **Partial** = present but narrower; **None** = absent; **N/A** = not applicable to the product's model.

| # | Capability | Maltego | gih | Notes |
|---|---|---|---|---|
| 1 | Data model / ontology | Full — typed entity ontology, custom entity creation, base64/composed properties, icon manager | Partial | gih has ~20 artifact types (`username`, `email`, `phone`, `domain`, `subdomain`, `ip_address`, `image`, `open_port`, `leak_record`, …) fixed in code; no user-defined types, no icon management |
| 2 | Data acquisition | Full — Data Hub, 120+ providers, OAuth/API-key transform settings, credit metering | Partial | 15 integrated external CLI tools + 23 plugins + built-in phone/email/username/image/breach modules + Google Dorks + LeakOSINT. Free, no credits, but no commercial datasets |
| 3 | Extensibility | Full — Transform SDK (local + TDS/iTDS servers), pagination, middlewares, OAuth, distribution to a whole org | Partial | `OSINTPlugin` base class, auto-discovery from `src/plugins/builtins/`, `docs/plugin_development.md`; in-process Python only, no distribution server, no per-org publishing |
| 4 | Automation / macros | Full — Machines (pipelines, parallel paths, filters), scripting language | Partial (different model) | gih's BFS orchestrator *is* the automation and needs no scripting, but the sequence is not user-programmable: you cannot express "domain → MX → IP → netblock, then filter" without editing code |
| 5 | Interactive graph analysis | Full — block/hierarchical/circular/organic/interactive-organic layouts, freeze/refresh, collections to simplify large graphs, pin/unpin, detail + property views | Partial | pyvis HTML graph (`src/graph/visualizer.py`) with `get_graph_stats`; a single force-directed view, no layout choice, no collections, no pinning, no in-graph drill-down |
| 6 | Alternative views | Full — map view, histogram, table/list views, AI Assistant (Browser) | Partial | Report has a geolocation section, platform-presence matrix and tables, but no map tiles and no histogram/pivot view |
| 7 | Manual analyst edits | Full — create entities, draw manual links, notes, overlays | None | gih's graph is a rendering of the DB; there is no UI to add an entity, draw a link or annotate a node. Comments exist only as a report-level input (`load_comments`) |
| 8 | Entity clustering / identity resolution | Partial — visual collections group *same-type* entities; attribution is the analyst's judgement | **Full (gih stronger)** | `correlate_identities` builds a NetworkX graph, takes connected components, and produces named identity profiles with weighted confidence (`compute_link_confidence`), risk indicators and risk levels (`compute_identity_risk_score`, `classify_risk_level`). Maltego has no equivalent automatic "this is one person, 78% confidence" output |
| 9 | Risk scoring | None (out of scope) | **Full (gih only)** | Composite risk score from accumulated indicators, per identity, surfaced in every report template |
| 10 | Persistence / storage | Full — graphs saved as files; Maltego Cases for storing investigations; graph recovery | Partial | SQLite (`src/storage/database.py`) with investigations, artifacts, links, platform presences and an audit trail; optional Neo4j backend. No case-management layer, no crash-recovery of an in-flight run |
| 11 | Cross-case correlation | Partial — requires re-running transforms or an external store | **Full (gih)** | `build_cross_investigation` correlates artifacts across investigations; Neo4j backend adds persistent cross-investigation Cypher queries |
| 12 | Change tracking over time | Full — Maltego Monitor (real-time social monitoring, dashboards, sentiment) | Partial | `build_delta_report` diffs an investigation against a previous run. No monitoring, no scheduling, no alerting |
| 13 | Evidence preservation | Full — Hunchly page capture with metadata and chain of custody; Maltego Evidence for social media | Partial | `build_evidence_chains` records provenance/derivation of each artifact, and the audit trail logs the run — but no page capture, no hashed originals, no custody chain |
| 14 | Reporting | Partial — Generate Report, export graph to table/XML/image | **Full (gih stronger)** | Four HTML templates (standard/executive/technical/legal), JSON, CSV, PDF (via pandoc), 15 toggleable sections, per-report branding/watermark, custom CSS, actionable recommendations, orphan findings, tool-run status, `--redact` masking |
| 15 | Redaction / data minimisation | None documented | **Full (gih only)** | `redact_payload` masks emails/phones and leaked records end-to-end across HTML and JSON |
| 16 | Collaboration | Full — shared graphs, collaborative sessions, incremental layout to preserve peers' layout, org admin/billing | **None** | Single-operator tool; sharing means sending a file |
| 17 | Interoperability | Full — import 3rd-party tables with tabular mappings, export XML/table/image, config import/export | Partial | JSON and CSV export are consumable by SIEM/CTI; no graph-exchange format, no tabular import of external spreadsheets |
| 18 | Deployment | Full — desktop client, browser platform, hosted servers, multi-region | Partial | Local Python, Docker, Kali Docker/VM; CLI only, no server or web UI |
| 19 | Access control / multi-tenancy | Full — Maltego Admin, roles, seats, per-org data access | None | Filesystem permissions only |
| 20 | Training / support | Full — Maltego Academy, 7-day support | None | Repository docs only |
| 21 | Licensing cost | Basic free (200–1000 credits); Entry €3,000/yr; Professional €7,500/yr for ≤5 seats; Enterprise on quote | **Free (MIT), $0 infra** | gih's own README: standard laptop, no cloud, no cost |
| 22 | Graph scale | Full — collections and interactive-organic layout exist specifically for 4,000+ entity graphs | Partial | pyvis rendering degrades on large graphs; Neo4j backend handles storage scale but not visualisation |

**Score:** of 22 capability areas — gih is comparable or better in 7 (identity resolution, risk scoring, cross-case correlation, reporting, redaction, cost, and automation-without-scripting), partial in 10, and absent in 5 (manual graph editing, collaboration, access control, training/support, monitoring-grade change tracking).

## 3. Where gih genuinely wins

1. **It answers the question, not just draws it.** Maltego shows you a graph and leaves attribution to you. gih emits identity profiles with a confidence score, risk indicators, a risk level, an evidence chain per artifact, and a list of unattributed findings to chase. That is the whole point of the tool and Maltego has no counterpart.
2. **Deliverable quality.** Four audience-specific templates (executive/technical/legal/standard), branding, watermark, section selection, and a `--redact` mode. Maltego's "Generate Report" is an export, not a document you hand to counsel.
3. **Zero marginal cost.** No credits. A Maltego transform against a commercial dataset consumes budget per run; a gih investigation costs nothing, which makes wide, repeated, exploratory sweeps practical.
4. **Unattended operation.** One command with several seeds produces a finished report. In Maltego the equivalent needs a Machine plus an analyst watching the graph.
5. **Machine-readable output by default.** JSON with `summary`, `identities`, `artifacts`, `links`, `evidence_chains`, `tool_metrics` — drop-in for a SIEM/CTI pipeline.

## 4. Where Maltego is clearly ahead

1. **Data breadth.** 120+ providers behind one login is the product. gih reaches only free/public sources plus whatever CLI tools are installed; the LeakOSINT plugin is the first paid dataset it can consume, and only one.
2. **Interactivity.** Layout choice, collections for big graphs, pin/unpin, detail and property views, manual entities and links, notes. gih's pyvis graph is read-only and one-layout.
3. **Analyst-programmable automation.** Machines let an investigator compose and share a pivot chain without touching the product's source. gih requires a code change.
4. **Team operation.** Shared graphs, collaborative sessions, seats, roles, admin and billing. gih is single-user by construction.
5. **Evidentiary capture.** Hunchly's page archiving with chain of custody, and Maltego Evidence for social media, are legal-grade. gih records provenance metadata, not the artifact itself — a real gap given it ships a "legal" report template.
6. **Continuous monitoring.** Maltego Monitor watches sources in real time; gih only diffs on demand.

## 5. Recommended roadmap (highest value first)

| Priority | Gap | Proposed work | Rough effort |
|---|---|---|---|
| 1 | No evidence preservation behind the legal template | Store a hashed snapshot (raw tool output / fetched page) per artifact and reference it from the evidence chain | Medium |
| 2 | Read-only, single-layout graph | Add layout choice and node grouping to the pyvis output; group by artifact type above a node threshold (Maltego's "collections" idea) | Medium |
| 3 | Automation not user-programmable | A declarative pivot-chain config (YAML: type → plugin → filter) so operators compose sequences without editing `orchestrator.py` | Medium |
| 4 | No scheduled re-runs | Wrap `investigate` + `build_delta_report` in a scheduled mode that reports only what changed | Small |
| 5 | No tabular import | Import a CSV/spreadsheet of selectors as seeds, with column→artifact-type mapping | Small |
| 6 | Fixed ontology | Allow artifact types (and their badges/report handling) to be declared in config rather than code | Medium |
| 7 | Single-operator | Multi-user story: either a small web UI over the existing SQLite/Neo4j layer, or a documented shared-Neo4j workflow | Large |
| 8 | Narrow paid-data coverage | Generalise the LeakOSINT pattern into a keyed-API plugin family (HIBP paid tier, Shodan, IPinfo, crypto) with a shared credential resolver and quota handling | Medium |

## 6. Verdict

gih is not a Maltego replacement and should not be positioned as one: it lacks the data breadth, the interactive graph, the collaboration layer and the evidentiary capture that justify Maltego's licence. What it does have is the piece Maltego deliberately leaves to the analyst — automatic identity resolution with confidence and risk scoring — wrapped in reporting that is, feature for feature, better than Maltego's export.

The honest positioning is **complementary**: gih as the free, automated first pass that turns a handful of selectors into scored profiles and a hand-off-ready report, with Maltego (or a human analyst) taking over for deep interactive pivots against commercial data. The roadmap above closes the gaps that undermine gih's own claims first (evidence preservation under a legal template, graph usability), before chasing parity in areas where parity is neither cheap nor necessary.

# Ghost Identity Hunter — Architecture

Ghost Identity Hunter (GIH) is an OSINT identity-attribution framework. It takes seed
artifacts (a phone number, email, username, full name, IP address or image), expands them
breadth-first through OSINT modules, plugins and external tools, persists everything to
SQLite, correlates the result into identity profiles and renders HTML/JSON reports.

- Low-level design per subsystem: [LLD.md](LLD.md)
- Which external tools are declared, implemented and invoked: [TOOL_COVERAGE.md](TOOL_COVERAGE.md)

## Layers

| Layer | Location | Responsibility |
| --- | --- | --- |
| Interface | `src/cli.py`, `src/api/workflow_api.py` | Click CLI and Flask REST API; build seeds and `InvestigationConfig` |
| Orchestration | `src/orchestrator.py` | Depth-limited BFS over artifacts, parallel per level, serialized DB writes, runtime/artifact budgets |
| Collection | `src/modules/*`, `src/plugins/*` | Native OSINT modules, plugin system, external tool subprocess integrations |
| Correlation | `src/correlation/linker.py`, `src/correlation/scorer.py`, `src/modules/correlation.py`, `src/modules/correlation_neo4j.py` | Identity graph, confidence and risk scoring, optional Neo4j backend |
| Storage | `src/storage/database.py` | SQLite schema and all reads/writes |
| Presentation | `src/reporting/html_report.py`, `src/graph/visualizer.py` | Four HTML templates, JSON report, interactive graph |
| Support | `src/config/loader.py`, `src/utils/tool_checker.py`, `src/utils/http_client.py` | YAML configuration, cached tool availability, HTTP session handling |
| Analysis extras | `src/analysis/*`, `src/collaboration/comments.py` | Pattern, statistical and trend analysis; investigation comments |

## Overall architecture

```mermaid
graph TD
    CLI["CLI (src/cli.py)"]
    API["REST API (src/api/workflow_api.py)"]
    ORCH["Orchestrator BFS (src/orchestrator.py)"]
    CFG["Config loader (src/config/loader.py)"]
    TC["Tool checker cache (src/utils/tool_checker.py)"]
    MOD["OSINT modules (src/modules)"]
    PLG["Plugin manager (src/plugins)"]
    EXT["External tool integrations (src/modules/external_tools.py)"]
    DB["SQLite storage (src/storage/database.py)"]
    COR["Correlation engine (src/correlation/linker.py)"]
    NEO["Neo4j backend (src/modules/correlation_neo4j.py)"]
    REP["Reporting (src/reporting/html_report.py)"]
    VIZ["Graph visualizer (src/graph/visualizer.py)"]

    CLI --> ORCH
    API --> ORCH
    CFG --> ORCH
    CFG --> EXT
    ORCH --> MOD
    ORCH --> PLG
    ORCH --> EXT
    TC --> EXT
    TC --> ORCH
    MOD --> ORCH
    PLG --> ORCH
    EXT --> ORCH
    ORCH --> DB
    DB --> COR
    COR --> NEO
    COR --> REP
    DB --> REP
    DB --> VIZ
    VIZ --> REP
```

## Orchestration layer

```mermaid
graph LR
    SEEDS["Seed artifacts"]
    LEVEL["BFS level queue"]
    POOL["ThreadPoolExecutor (config orchestrator.max_parallel_workers)"]
    PROC["_process_artifact"]
    RESULT["ArtifactProcessResult"]
    WRITE["Serial write phase (main thread)"]
    BUDGET["Runtime deadline and artifact budget"]

    SEEDS --> LEVEL
    LEVEL --> POOL
    POOL --> PROC
    PROC --> RESULT
    RESULT --> WRITE
    WRITE --> LEVEL
    BUDGET --> LEVEL
```

## Collection layer

```mermaid
graph TD
    ART["Artifact (type, value, depth)"]
    PHONE["phone_osint.analyze_phone"]
    EMAIL["email_osint.analyze_email + breach_check"]
    USER["username_search.search_username"]
    NAME["image_match.search_and_match_identity"]
    IMG["image_search.analyze_image"]
    DORK["google_dorks.run_google_dorks_search"]
    TOOLS["_process_external_tools"]
    PLUGINS["PluginManager.execute_plugins_for_artifact"]

    ART --> PHONE
    ART --> EMAIL
    ART --> USER
    ART --> NAME
    ART --> IMG
    ART --> TOOLS
    ART --> PLUGINS
    USER --> DORK
```

## External tools layer

```mermaid
graph TD
    DISPATCH["run_tool_analysis(tool, analysis, target)"]
    TABLE["ANALYSIS_METHODS dispatch table"]
    RUN["ExternalToolsIntegration.run_tool (subprocess, configured timeout)"]
    PARSE["Per-tool parser to artifacts_discovered"]
    NORM["_normalize_tool_artifacts (orchestrator)"]
    PRES["platform_presence rows"]
    STORE["artifacts + artifact_links"]

    DISPATCH --> TABLE
    TABLE --> RUN
    RUN --> PARSE
    PARSE --> NORM
    NORM --> PRES
    NORM --> STORE
```

## Correlation and reporting layer

```mermaid
graph TD
    ARTS["artifacts"]
    LINKS["artifact_links"]
    PRES["platform_presence"]
    GRAPH["NetworkX identity graph"]
    COMP["Connected components"]
    PROFILE["IdentityProfile"]
    FIND["Tool findings walk (_collect_tool_findings)"]
    SCORE["scorer.compute_identity_risk_score"]
    HTML["HTML report (standard, executive, technical, legal)"]
    JSON["JSON report"]

    ARTS --> GRAPH
    LINKS --> GRAPH
    GRAPH --> COMP
    COMP --> PROFILE
    PRES --> PROFILE
    ARTS --> FIND
    LINKS --> FIND
    FIND --> PROFILE
    PROFILE --> SCORE
    PROFILE --> HTML
    PROFILE --> JSON
```

## Data model

The schema is created by `_init_schema` in `src/storage/database.py` (called from
`get_connection`). All tables are keyed
by `investigation_id`; the `comments` table is created on demand by
`src/collaboration/comments.py`.

```mermaid
erDiagram
    investigations ||--o{ artifacts : "contains"
    investigations ||--o{ artifact_links : "contains"
    investigations ||--o{ platform_presence : "contains"
    investigations ||--o{ investigation_metadata : "contains"
    investigations ||--o{ audit_trail : "contains"
    investigations ||--o{ comments : "contains"
    artifacts ||--o{ artifact_links : "source"
    artifacts ||--o{ artifact_links : "target"
    artifacts ||--o{ platform_presence : "evidence for"
    artifacts ||--o{ comments : "annotated by"

    investigations {
        TEXT investigation_id PK
        TEXT created_at
        TEXT title
        TEXT description
        TEXT status
    }
    artifacts {
        TEXT artifact_id PK
        TEXT investigation_id FK
        TEXT artifact_type
        TEXT value
        TEXT source
        REAL confidence
        TEXT metadata
        TEXT discovered_at
        INTEGER depth
    }
    artifact_links {
        TEXT link_id PK
        TEXT investigation_id FK
        TEXT source_artifact FK
        TEXT target_artifact FK
        TEXT link_type
        REAL confidence
        TEXT evidence
    }
    platform_presence {
        TEXT presence_id PK
        TEXT investigation_id FK
        TEXT artifact_id FK
        TEXT platform_name
        TEXT profile_url
        TEXT username
        TEXT display_name
        TEXT bio
        TEXT profile_image_url
        TEXT account_created
        TEXT last_active
        INTEGER follower_count
        INTEGER is_verified
    }
    investigation_metadata {
        TEXT metadata_id PK
        TEXT investigation_id FK
        TEXT key
        TEXT value
        TEXT created_at
    }
    audit_trail {
        TEXT audit_id PK
        TEXT investigation_id FK
        TEXT action
        TEXT entity_type
        TEXT entity_id
        TEXT details
        TEXT performed_at
    }
    comments {
        TEXT comment_id PK
        TEXT investigation_id FK
        TEXT artifact_id FK
        TEXT author
        TEXT content
        TEXT created_at
        TEXT updated_at
        TEXT parent_id
        TEXT comment_type
    }
```

## Artifact taxonomy

`EXPANDABLE_ARTIFACT_TYPES` in `src/orchestrator.py` decides what is re-queued for further
expansion: `phone`, `email`, `username`, `image`, `fullname`, `domain`, `ip_address`.
Everything else (`username_presence`, `open_port`, `dns_a`, `historical_url`,
`gps_coordinates`, `camera_info`, `breach_data`, ...) is stored and linked as a leaf finding
so a single noisy tool cannot drive another round of expensive tool runs.

## Tech stack

| Concern | Technology |
| --- | --- |
| Language | Python 3.10+ |
| CLI | Click |
| REST API | Flask, flask-cors |
| Persistence | SQLite (`sqlite3`, WAL journal) |
| Graph analysis | NetworkX; optional Neo4j via the `neo4j` driver |
| HTTP / scraping | requests, BeautifulSoup |
| Templating | Jinja2 |
| Imaging | Pillow, NumPy; optional `face_recognition` |
| Configuration | PyYAML (`config/config.yaml`) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| External tools | sherlock, maigret, holehe, theHarvester, amass, subfinder, whois, dig, nmap, shodan, exiftool, Wayback CDX API |
| Testing / lint | pytest, ruff |

## Known gaps

- `src/utils/tool_checker.py` declares 35 tools; only 12 have integrations
  (`get_tool_integrations`) and the rest are unimplemented. See
  [TOOL_COVERAGE.md](TOOL_COVERAGE.md).
- Shodan requires an API key and its CLI output is parsed as JSON, so it stays unverified in
  environments without a key.
- The identity graph itself is still built only from `phone`, `email`, `username`, `image`
  and `fullname` artifacts. Tool findings are attached to profiles by walking links
  (`_collect_tool_findings`) rather than by joining the graph, so a finding is only surfaced
  when it is within `MAX_FINDING_HOPS` of an identity artifact.
- `face_recognition` is optional; without it, image matching degrades to URL collection and
  EXIF analysis.
- Google Dorks scraping depends on search-engine HTML and is disabled by default.

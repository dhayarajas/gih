# Ghost Identity Hunter — Low-Level Design

Subsystem-level design derived from the code in `src/`. Every signature, constant and behaviour below was read from the current source; deviations between documented intent and actual behaviour are called out inline and summarised in [§12 Known Gaps](#12-known-gaps).

## Table of Contents

- [1. Entry Points](#1-entry-points)
- [2. Orchestrator](#2-orchestrator)
- [3. OSINT Modules](#3-osint-modules)
- [4. Plugin System](#4-plugin-system)
- [5. External Tools](#5-external-tools)
- [6. Correlation Engine](#6-correlation-engine)
- [7. Storage](#7-storage)
- [8. Reporting and Visualization](#8-reporting-and-visualization)
- [9. Analysis Subsystem](#9-analysis-subsystem)
- [10. Workflow API](#10-workflow-api)
- [11. Collaboration](#11-collaboration)
- [12. Known Gaps](#12-known-gaps)
- [13. Sequence Diagrams](#13-sequence-diagrams)

---

## 1. Entry Points

### 1.1 CLI (`src/cli.py`)

Click group `cli` with options `--verbose/-v` and `--db` (stored in the Click context).

| Command | Key options | Behaviour |
| --- | --- | --- |
| `investigate` | `-p/--phone`, `-e/--email`, `-u/--username`, `-i/--image`, `-n/--name`, `-d/--depth`, `--no-breach`, `--no-username-search`, `--no-images`, `--use-external-tools/--no-external-tools`, `--check-tools`, `--use-neo4j`, `--neo4j-uri/-user/-password/-database`, `--use-google-dorks`, `--google-api-key`, `--google-cx`, `--use-google-api`, `--search-engine`, `--auto-report/--no-auto-report`, `--report-format` | Builds a `seeds` list of `{"type", "value"}` dicts, constructs `InvestigationConfig`, opens a connection with `db.get_connection(db_path)`, calls `run_investigation`, prints a summary and optionally generates reports |
| `report` | `--id`, `--format {html,json,both}`, `--output` | Calls `generate_html_report` and/or `generate_json_report` |
| `graph` | `--id`, `--output` | Calls `generate_interactive_graph` and prints `get_graph_stats` |
| `list` | — | `db.list_investigations` in a table |
| `correlate` | `--id` | `correlate_identities` and prints identity profiles |
| `plugins` | `list`, `info <name>`, `enable <name>`, `disable <name>` | Wraps `PluginRegistry` (see gaps) |

`--check-tools` short-circuits `investigate`: it instantiates `ToolChecker`, prints available and missing tools and returns without running an investigation.

### 1.2 REST API (`src/api/workflow_api.py`)

See [§10](#10-workflow-api).

## 2. Orchestrator

File: `src/orchestrator.py`.

### 2.1 Configuration

```python
MAX_DEPTH = _get_orchestrator_config().get("max_depth", 2)
```

`_get_orchestrator_config()` reads the `orchestrator` block from `config/config.yaml` via `ConfigLoader`, defaulting to `{"bfs_batch_size": 10, "max_depth": 2, "max_concurrent_artifacts": 5}`. The shipped config defines only `bfs_batch_size: 10` and `max_depth: 2`, so `max_concurrent_artifacts` falls back to `5` at the call site.

```python
@dataclass
class InvestigationConfig:
    max_depth: int = MAX_DEPTH
    check_breaches: bool = True
    search_usernames: bool = True
    check_images: bool = True
    verbose: bool = False
    check_external_tools: bool = True
    skip_missing_tools: bool = True
    use_neo4j: bool = False
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    neo4j_database: str = "neo4j"
    use_google_dorks: bool = False
    google_api_key: Optional[str] = None
    google_cx: Optional[str] = None
    use_google_api: bool = False
    search_engine: str = "auto"
```

`InvestigationResult` carries `investigation_id`, `total_artifacts`, `total_links`, `total_platforms`, `risk_indicators`, `identity_profiles` and `correlation_analysis`.

### 2.2 `run_investigation`

```python
def run_investigation(
    conn: sqlite3.Connection,
    seeds: list[dict],
    config: Optional[InvestigationConfig] = None,
    title: Optional[str] = None,
) -> InvestigationResult:
```

Phases:

1. **Tool sweep** — when `config.check_external_tools`, `get_tool_checker().check_all_tools()` runs once and available/missing counts are logged.
2. **Plugin bootstrap** — `PluginRegistry()` + `discover_plugins()`, then `PluginManager(registry)`; failures are logged and the manager is set to `None` (investigation continues without plugins).
3. **Investigation record** — `db.create_investigation(conn, title=...)` returns `INV-xxxxxxxx`.
4. **Seeding** — every seed is inserted at `depth=0` with `source="seed"`, added to `seen` as `"{type}:{value}"` and pushed onto the `deque`.
5. **BFS loop** — see below.
6. **Finalization** — `db.complete_investigation`, count artifacts/links/platform presences, run correlation, persist the correlation summary into `investigation_metadata`, and collect risk indicators.

### 2.3 BFS loop

```python
queue: deque[dict] = deque()
seen: set[str] = set()
...
while queue:
    batch_size = min(max_concurrent, len(queue))
    batch = [queue.popleft() for _ in range(batch_size)]
    ...
```

- **Single-artifact batch** — processed inline on the caller's connection via `_process_artifact`.
- **Multi-artifact batch** — a `ThreadPoolExecutor(max_workers=batch_size)` runs `_process_artifacts_generator`-style workers; each worker opens its **own** `db.get_connection()` so SQLite objects are not shared across threads, and closes it in a `finally` block.
- Results are merged back on the main thread, where dedup and persistence happen.

Dedup and expansion, for each discovered artifact of a processed artifact `current_id` at `current_depth`:

```python
if current_depth < config.max_depth:
    for artifact in discovered:
        key = f"{artifact['type']}:{artifact['value']}"
        if key in seen:
            continue
        seen.add(key)

        new_id = db.add_artifact(
            conn,
            investigation_id=inv_id,
            artifact_type=artifact["type"],
            value=artifact["value"],
            source=artifact.get("source", "discovered"),
            confidence=artifact.get("confidence", 0.8),
            metadata=metadata_value,
            depth=current_depth + 1,
        )

        db.add_link(
            conn,
            investigation_id=inv_id,
            source_artifact=current_id,
            target_artifact=new_id,
            link_type=artifact.get("link_type", "discovered_from"),
            confidence=artifact.get("confidence", 0.8),
            evidence=artifact.get("source", ""),
        )
```

`metadata` values that arrive as dicts (plugin results) are JSON-encoded before insertion. Artifacts discovered at `current_depth == max_depth` are discarded entirely — they are neither persisted nor linked.

### 2.4 `_process_artifact`

```python
def _process_artifact(conn, inv_id, artifact, config, plugin_manager=None) -> list[dict]:
```

Dispatch table:

| `artifact_type` | Handler | Module |
| --- | --- | --- |
| `phone` | `_process_phone` | `phone_osint` |
| `email` | `_process_email` | `email_osint` (+ `breach_check`) |
| `username` | `_process_username` | `username_search` |
| `image` | `_process_image` | `image_search` |
| `fullname` | `_process_fullname` | `image_match` |
| `platform_presence` | none (plugins only) | — |
| anything else | `logger.warning("Unknown artifact type: %s")` | — |

After module dispatch it appends `_process_external_tools(...)` output when `config.check_external_tools`, then `_process_with_plugins(...)` output when a `plugin_manager` exists.

Each `_process_*` helper writes the module's `to_json()` payload into `artifacts.metadata` for the artifact being processed with a direct `UPDATE`, records `platform_presence` rows where applicable, and returns a list of discovered artifact dicts:

| Handler | Discovered types | Link types used |
| --- | --- | --- |
| `_process_phone` | `carrier_info`, `risk_indicator` | `registered_with` (module), `has_risk` |
| `_process_email` | `username` (from platforms and from local part), `breach_data` | `found_in_breach`, `possible_username` |
| `_process_username` | `platform_presence` | default `discovered_from` |
| `_process_image` | `location` (EXIF GPS) | default |
| `_process_fullname` | `image_url`, `identity_match`, `identity_confidence` | default |

### 2.5 `_process_external_tools`

```python
def _process_external_tools(conn, inv_id, artifact, config) -> list[dict]:
```

Returns immediately when `config.check_external_tools` is false. Otherwise, by artifact type:

- `username` — `sherlock` (`username_search`) if `check_tool_availability("sherlock")`; then Google Dorks if `check_google_dorks_availability(config.google_api_key)` (which always returns `True`, so dorking runs regardless of `config.use_google_dorks`).
- `domain` — `theharvester` (`email_harvest` then `subdomain_harvest`), `amass` (`subdomain_enum`), `whois` (`domain_lookup`), `dig` (`dns_lookup`), each behind `check_tool_availability`; then `wayback_machine` (`historical_urls`) unconditionally, since it is an HTTP API rather than a binary.
- `ip_address` — `shodan` (`host_search`), `nmap` (`host_scan`).
- `image` — `exiftool` (`metadata_extract`).
- `email` — no subprocess; synthesises a `domain` artifact from the address with `link_type="domain_of_email"` and confidence `0.7`, which is what feeds the domain branch on the next BFS hop.

The whole body is wrapped in `try/except Exception`, so tool failures degrade to a logged error and an empty list. This is also what currently masks the `run_tool_analysis` defect described in [§5.3](#53-run_tool_analysis).

### 2.6 `_process_with_plugins`

Converts the artifact into a plugin `Artifact` (`source="orchestrator"`, `confidence=1.0`, metadata carrying `artifact_id`), then:

```python
plugin_results = plugin_manager.execute_plugins_for_artifact(
    artifact=plugin_artifact,
    parallel=True,
    max_workers=5
)
```

Only results with `status.value == "success"` contribute; each plugin artifact becomes a discovered dict with `source=f"plugin:{result.plugin_name}"` and `link_type="discovered_from"`.

### 2.7 Correlation and finalization

- Non-Neo4j path: `correlation.analyze_correlation(artifacts, links)` (lightweight metrics only).
- Neo4j path (`config.use_neo4j`): `Neo4jCorrelation(uri, user, password, database)`; artifacts and links are pushed to Neo4j and analysed with Cypher, with fallback to the NetworkX path on failure.
- The resulting dict is stored as `investigation_metadata` key `correlation_analysis`.
- `risk_indicators` are collected by scanning artifact metadata for `risk_indicators` entries and de-duplicated.

## 3. OSINT Modules

All modules live in `src/modules/` and follow the same contract: an `analyze_*`/`search_*` function returning a dataclass with `to_dict()`/`to_json()`, plus `get_discovered_artifacts(...)` returning `list[dict]` for the orchestrator.

### 3.1 `phone_osint.py`

- **Input**: raw phone string. **Library**: `phonenumbers` (`geocoder`, `carrier`, `timezone`).
- Parses with no region, retries with `"US"`, then validates. Invalid input yields `risk_indicators = ["invalid_number_format"]` or `["invalid_number"]`.
- Populates `PhoneAnalysis(number, valid, formatted_international, formatted_national, country_code, country, region, carrier_name, line_type, timezones, is_voip, is_disposable, risk_indicators)`.
- Line type is mapped from `phonenumbers.PhoneNumberType` to strings (`mobile`, `fixed_line`, `voip`, `toll_free`, …). VoIP carriers (`VOIP_CARRIERS`) and burner services (`DISPOSABLE_SERVICES`) add `voip_carrier_detected` / `disposable_number_service`.
- **Discovered artifacts**: `carrier_info` (`link_type="registered_with"`, confidence `0.9`) when valid and the carrier is known.

### 3.2 `email_osint.py`

- **Input**: email address. Validates format, splits local part and domain, classifies domain against `DISPOSABLE_DOMAINS`, `PRIVACY_PROVIDERS` and a free-provider set.
- External checks (`check_gravatar`, `check_github_email`, `check_hibp_breaches`) run in a `ThreadPoolExecutor`; extra platform probes cover GitHub, Twitter/X, Instagram and Reddit.
- `EmailAnalysis` carries `valid_format`, `domain`, `local_part`, `is_disposable`, `is_privacy_provider`, `is_corporate`, `mx_records`, `platforms_found`, `breaches`, `breach_count`, `has_gravatar`, `gravatar_url`, `risk_indicators`.
- **Discovered artifacts**: `username` (confidence `0.9`) for each platform profile with a username.
- **Gap**: the parallel external-check block is nested inside the `is_corporate` branch, so Gravatar/GitHub/HIBP lookups are skipped for free-provider addresses (gmail, outlook, …).

### 3.3 `username_search.py`

- Platform definitions come from `config/config.yaml` (`username_search.platforms`, 12 entries: GitHub, GitLab, Reddit, Twitter/X, Instagram, LinkedIn, Keybase, HackerNews, Medium, Pinterest, Steam, Mastodon).
- `_check_platform` uses the shared HTTP session with `allow_redirects=False` and one of four check strategies: `api_status`, `api_json`, `api_json_array`, `web_status`. Results are memoised in a bounded process-level dict (`_platform_check_cache`, FIFO eviction).
- `search_username` fans out over platforms with a `ThreadPoolExecutor` sized from config; `search_usernames_batch` fans out over usernames. `generate_username_variants` produces fuzzy variants (not used by the orchestrator path).
- **Discovered artifacts**: one `platform_presence` per found platform, value = profile URL, confidence `0.85`, metadata = serialised `PlatformResult`.

### 3.4 `image_search.py`

- EXIF extraction with Pillow (camera make/model, software, timestamps, GPS), MD5/SHA1/SHA256 hashing, dimension and format reporting, and reverse-search URL construction (Google, Yandex, TinEye, Bing).
- **Discovered artifacts**: `location` (`"lat,lon"`, confidence `0.8`) when EXIF GPS is present.

### 3.5 `image_match.py`

- Name-driven image discovery plus optional face matching (`face_recognition` + `numpy`, both optional imports).
- `search_and_match_identity(full_name, max_results)` returns an `IdentityMatchResult` with `images`, `face_matches`, `overall_probability`.
- **Discovered artifacts**: `image_url` per found image, and `face_match` entries where `match_probability > 0.7`. The orchestrator additionally emits `identity_match` and `identity_confidence` artifacts from the same result.

### 3.6 `breach_check.py`

- `check_email_breaches(email, api_key=None)` queries `https://haveibeenpwned.com/api/v3/breachedaccount/{email}` when an API key is supplied, handling 200/404/401/429 explicitly.
- **Without an API key it returns mock breach data** and sets `result.error` to a "using mock data" message. The orchestrator calls it without a key, so out-of-the-box breach artifacts are illustrative, not real.
- Also provides k-anonymity password exposure checks against the Pwned Passwords range API.
- **Discovered artifacts**: `breach_data` per breach with a domain, confidence `0.95` when verified else `0.7`; the orchestrator rewrites `link_type` to `found_in_breach`.

### 3.7 `google_dorks.py`

- `GoogleDorksSearch` holds eight `DorkPattern` templates (`simple_search`, `social_platforms`, `profile_pages`, `documents`, `forum_mentions`, `combined_search`, `developer_platforms`, `professional_networks`) with per-pattern confidence.
- Execution: patterns are truncated to `max_patterns` (default 3 from config), executed in a thread pool, and routed by `_determine_search_engine()` to Google scraping (the `auto` default), DuckDuckGo, or the Google Custom Search API when `use_api` and credentials are present. Retries use exponential backoff with jitter; results are cached on disk when `cache_dir` is set; total results are capped by `max_results_per_search`.
- `run_google_dorks_search(...)` flattens `DorkResult.artifacts_discovered` across patterns; `check_google_dorks_availability(...)` returns `True` unconditionally.

### 3.8 `external_tools.py`

See [§5](#5-external-tools).

### 3.9 `correlation.py` and `correlation_neo4j.py`

- `correlation.analyze_correlation(artifacts, links)` builds a NetworkX graph in memory and returns `CorrelationAnalysis(artifacts_analyzed, links_found, connected_components, largest_component_size, confidence_scores, risk_indicators)`. It is the summary used by the orchestrator; the full profile logic lives in `src/correlation/linker.py`.
- `correlation_neo4j.Neo4jCorrelation` mirrors that interface over the bolt driver: node/relationship upserts, Cypher-based component analysis, and cross-investigation queries. It is only used when `InvestigationConfig.use_neo4j` is set, and it falls back to the NetworkX path on any driver error.

## 4. Plugin System

### 4.1 `src/plugins/base.py`

```python
class PluginStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    SKIPPED = "skipped"

@dataclass
class PluginConfig:
    enabled: bool = True
    timeout: int = 30
    max_retries: int = 3
    api_key: Optional[str] = None
    custom_params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Artifact:
    type: str
    value: str
    source: str
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PluginResult:
    plugin_name: str
    status: PluginStatus
    artifacts: List[Artifact] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
```

`OSINTPlugin` is the ABC (there is no separate `PluginBase` class). Abstract methods: `get_name`, `get_version`, `get_description`, `get_supported_artifact_types`, `is_available`, `execute`. Concrete helpers: `validate_artifact`, `preprocess_artifact`, `postprocess_result`, and dependency declarations (`get_required_dependencies`, `get_optional_dependencies`).

### 4.2 `PluginRegistry` (`src/plugins/registry.py`)

- `register(plugin_class)` stores the class under its `__name__`.
- `discover_plugins(package="src.plugins.builtins")` walks `src/plugins/builtins/*.py`, imports each module with `importlib`, and registers every `OSINTPlugin` subclass that is not the ABC itself.
- `get_plugin_instance(name, config)` lazily instantiates and caches plugin objects.
- `get_plugins_by_artifact_type(artifact_type)` and `get_available_plugins()` filter by `get_supported_artifact_types()` and `is_available()`.

### 4.3 `PluginManager` (`src/plugins/manager.py`)

Execution of a single plugin:

1. Check the plugin is registered and configuration-enabled (`ConfigLoader.get_plugin_config(<registered class name>)`).
2. Instantiate through the registry with a `PluginConfig`.
3. `is_available()` gate → `PluginStatus.SKIPPED` when unavailable.
4. `validate_artifact` → `preprocess_artifact` → `execute` → `postprocess_result`.
5. Record execution time and update per-plugin statistics (`executions`, `successes`, `failures`, `total_time`).

`execute_plugins_for_artifact(artifact, parallel=True, max_workers=5)` selects all plugins whose supported types include the artifact type and runs them serially or in a `ThreadPoolExecutor`. `execute_plugins_for_artifacts(...)` loops over artifacts. `aggregate_findings(results)` de-duplicates artifacts on the `(type, value, source)` triple and returns aggregate counts.

### 4.4 Built-in plugins (`src/plugins/builtins/`)

| Class | `get_name()` | Supported types | Availability | Backing implementation |
| --- | --- | --- | --- | --- |
| `UsernameSearchPlugin` | `Username Search` | `username` | always | `username_search.search_username` |
| `EmailBreachPlugin` | `Email Breach Check` | `email` | always | `email_osint.analyze_email` breach fields |
| `PhoneValidationPlugin` | `Phone Validation` | `phone` | always | `phone_osint.analyze_phone` |
| `GoogleDorksPlugin` | `Google Dorks` | `username` | always | `google_dorks.run_google_dorks_search` |
| `SherlockPlugin` | `Sherlock` | `username` | `check_tool_availability("sherlock")` | `sherlock --output /dev/stdout --format json` subprocess |
| `TheHarvesterPlugin` | `theHarvester` | `domain` | `check_tool_availability("theharvester")` | `theHarvester` subprocess |
| `WhoisPlugin` | `Whois` | `domain`, `ip` | `check_tool_availability("whois")` | `whois` subprocess |
| `DigPlugin` | `Dig` | `domain` | `check_tool_availability("dig")` | `dig` subprocess |
| `ShodanPlugin` | `Shodan` | `ip`, `domain` | `check_tool_availability("shodan")` | `shodan` CLI subprocess |
| `ProfileImagePlugin` | `profile_image` | `platform_presence` | `bs4` importable | HTML scraping for avatar URLs |
| `ImageMatchPlugin` | `image_match` | `fullname` | `face_recognition` importable | `image_match.search_and_match_identity` |

All plugins return `PluginResult` and convert failures into `PluginStatus.FAILURE` with an `error` string rather than raising.

## 5. External Tools

### 5.1 `ToolChecker` (`src/utils/tool_checker.py`)

- Holds 35 `ToolInfo` entries: `sherlock`, `maigret`, `social_analyzer`, `holehe`, `emailharvester`, `theharvester`, `whois`, `dig`, `amass`, `subfinder`, `sublist3r`, `nmap`, `masscan`, `whatweb`, `wappalyzer`, `recon-ng`, `spiderfoot`, `osrframework`, `shodan`, `ghunt`, `photon`, `metagoofil`, `exiftool`, `wayback_machine`, `etherscan`, `google_dorks`, `geonames`, `curl`, `wget`, `nslookup`, `nikto`, `sqlmap`, `tor_browser`, `flagfox`, `user_agent_switcher`.
- Availability is resolved with `shutil.which` plus an optional version probe, cached per process. `check_all_tools()`, `get_available_tools()`, `get_missing_tools()` and `print_tool_status()` support the CLI's `--check-tools`.
- `check_tool_availability(name)` is the module-level convenience used by the orchestrator and by tool-backed plugins. `skip_if_not_available(name)` is a decorator that returns a skipped `ToolResult` instead of executing.

### 5.2 Implemented integrations

`ExternalToolsIntegration` provides `run_tool(tool_name, command, timeout=60)` (a `subprocess.run` wrapper capturing stdout/stderr, exit code and duration into `ToolResult`), plus JSON and regex-based artifact extraction helpers.

`get_tool_integrations()` returns exactly nine singletons:

```python
{
    "sherlock": _sherlock,
    "theharvester": _theharvester,
    "shodan": _shodan,
    "amass": _amass,
    "whois": _whois,
    "dig": _dig,
    "nmap": _nmap,
    "exiftool": _exiftool,
    "wayback_machine": _wayback,
}
```

| Tool | Method | Command / transport | Artifacts produced |
| --- | --- | --- | --- |
| `sherlock` | `search_username` | `sherlock <user> --json --folderoutput /tmp` | `platform_presence` |
| `theharvester` | `harvest_email`, `harvest_subdomains` | `theHarvester -d <domain> -b google -e all` / `-h all` | `email`, `domain` |
| `shodan` | `search_host` | `shodan host <ip>` | host/service facts |
| `amass` | `enumerate_subdomains` | `amass enum -passive -d <domain>` | `domain` |
| `whois` | `lookup_domain` | `whois <domain>` | registrar, dates, `email` |
| `dig` | `dns_lookup` | `dig <domain> <type> +short` | `ip_address`, DNS records |
| `nmap` | `scan_host` | `nmap` with a common-ports profile | open ports/services |
| `exiftool` | `extract_metadata` | `exiftool -json <file>` | EXIF metadata, `location` |
| `wayback_machine` | `get_historical_urls` | HTTP GET to the Wayback CDX API (no binary) | historical `url` entries |

Everything else in the `ToolChecker` registry is **detection-only**: it can be reported as installed or missing, but no code path executes it.

### 5.3 `run_tool_analysis`

```python
def run_tool_analysis(tool_name: str, analysis_type: str, target: str) -> ToolResult:
```

It looks up the integration, then builds a dispatch dictionary that dereferences **all** integration methods for **all** tools off the single selected `integration` object:

```python
analysis_methods = {
    "sherlock": {"username_search": integration.search_username},
    "theharvester": {"email_harvest": integration.harvest_email, ...},
    ...
}
```

Because each integration class implements only its own method, building this dictionary raises `AttributeError` for every tool (verified: `run_tool_analysis("wayback_machine", "historical_urls", "example.com")` raises `'WaybackMachineIntegration' object has no attribute 'search_username'`). The orchestrator's broad `except Exception` swallows it, so external-tool discovery currently contributes no artifacts. Fixing this requires resolving the method lazily, for example `getattr(integration, method_name)` only for the selected tool.

## 6. Correlation Engine

### 6.1 `src/correlation/linker.py`

Constants:

```python
IDENTITY_ARTIFACT_TYPES = {"phone", "email", "username", "image", "fullname"}
MIN_ARTIFACT_CONFIDENCE = 0.3
```

`build_identity_graph(conn, investigation_id) -> nx.Graph`:

1. Read artifacts and links from SQLite.
2. Filter with `_is_identity_artifact`: type must be in the allow list, `confidence >= 0.3`, value must not match noise patterns (meta/derived values), usernames and emails must pass syntactic validation.
3. Add surviving artifacts as nodes carrying type, value, confidence, source, depth.
4. Add `artifact_links` as **undirected** edges with `link_type` and `confidence` attributes; edges referencing filtered-out nodes are skipped.

`correlate_identities(conn, investigation_id) -> CorrelationResult`:

1. `nx.connected_components(graph)` produces candidate clusters.
2. Each cluster becomes an `IdentityProfile(profile_id, phones, emails, usernames, images, platforms, risk_indicators, confidence, artifact_count)`; `profile_id` is `IDENTITY-001`, `IDENTITY-002`, …
3. Node values are bucketed by type into `phones`, `emails`, `usernames`, `images`. `platforms` come from `platform_presence` nodes and from the `platform_presence` table for the cluster's artifacts.
4. `_compute_confidence` blends artifact-type diversity, cross-type link ratio and mean edge confidence.
5. `_collect_risk_indicators` reads `risk_indicators` out of artifact metadata JSON.
6. Weak or noise-only components are folded into a single `IDENTITY-NOISE` profile instead of being reported as identities.
7. Profiles are sorted by `artifact_count` descending.

**Documented limitations**

- `fullname` artifacts pass the identity filter and contribute to `artifact_count` and confidence, but there is no `fullnames` field on `IdentityProfile`, so full names never surface in a profile. Profiles effectively expose phone, email, username and image identities plus derived platforms.
- The graph is `nx.Graph` and clustering uses `connected_components`; the code comments and CLI text refer to weakly connected components, but link direction is not preserved.

### 6.2 `src/correlation/scorer.py`

Base link scores:

| Link type | Score |
| --- | --- |
| `exact_match` | 1.0 |
| `registered_with` | 0.9 |
| `breach_linked`, `found_in_breach` | 0.8 |
| `discovered_from`, `image_match` | 0.7 |
| `username_pattern` | 0.6 |
| `possible_username`, `email_local_part` | 0.5 |
| `temporal_match` | 0.4 |
| `has_risk` | 0.3 |

`compute_link_confidence(link_type, source_reliability, data_age_days)` multiplies the base score by source reliability and applies freshness decay: `×0.8` beyond one year, `×0.6` beyond two years, clamped to `1.0`.

`compute_identity_risk_score(risk_indicators)` sums per-indicator weights and caps at `1.0`; `classify_risk_level(score)` maps to `critical` (≥0.8), `high` (≥0.6), `medium` (≥0.4), `low` (≥0.2), `minimal` (<0.2).

## 7. Storage

File: `src/storage/database.py`. Full ER diagram in [ARCHITECTURE.md §5](ARCHITECTURE.md#5-data-model).

### 7.1 Connection

`get_connection(db_path=None)`:

- Default path `~/.ghost_hunter/investigations.db`; parent directories are created.
- `sqlite3.connect(..., check_same_thread=False)` with `row_factory = sqlite3.Row`.
- `PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`.
- Calls `_init_schema(conn)` on every connection (`CREATE TABLE IF NOT EXISTS` + indexes), so the schema is self-healing.

### 7.2 Tables

| Table | Columns |
| --- | --- |
| `investigations` | `investigation_id` PK, `created_at`, `title`, `description`, `status` (default `in_progress`) |
| `artifacts` | `artifact_id` PK, `investigation_id` FK, `artifact_type`, `value`, `source`, `confidence` (default 1.0), `metadata` (JSON text), `discovered_at`, `depth` |
| `artifact_links` | `link_id` PK, `investigation_id` FK, `source_artifact` FK, `target_artifact` FK, `link_type`, `confidence`, `evidence` |
| `platform_presence` | `presence_id` PK, `investigation_id` FK, `artifact_id` FK, `platform_name`, `profile_url`, `username`, `display_name`, `bio`, `profile_image_url`, `account_created`, `last_active`, `follower_count`, `is_verified` |
| `investigation_metadata` | `metadata_id` PK, `investigation_id` FK, `key`, `value`, `created_at` |
| `audit_trail` | `audit_id` PK, `investigation_id` FK, `action`, `entity_type`, `entity_id`, `details`, `performed_at` |

Indexes cover `artifacts(investigation_id)`, `artifacts(artifact_type)`, `artifact_links(investigation_id)` and `platform_presence(investigation_id)`.

### 7.3 Key functions

| Function | Notes |
| --- | --- |
| `create_investigation(conn, title=None, description=None)` | Generates `INV-` + 8 hex chars, inserts with `status="in_progress"` |
| `complete_investigation(conn, investigation_id)` | Sets `status="completed"` |
| `get_investigation`, `list_investigations` | Row-dict reads, list ordered by `created_at DESC` |
| `add_artifact(...)` | Returns the existing `artifact_id` when `(investigation_id, artifact_type, value)` already exists, otherwise inserts `ART-xxxxxxxx` |
| `add_artifacts_bulk(...)` | `executemany` insert path for batches |
| `get_artifacts(conn, investigation_id, artifact_type=None)` | Optional type filter |
| `add_link(...)` | Dedups on `(investigation_id, source_artifact, target_artifact)`, otherwise inserts `LNK-xxxxxxxx` |
| `get_links(conn, investigation_id)` | Raw link rows |
| `add_platform_presence(...)` | Inserts `PRS-xxxxxxxx` with optional profile fields |
| `get_platform_presences(conn, investigation_id)` | Presence rows for reporting |
| `add_audit_log(...)`, `get_audit_trail(...)` | Available but not called during investigations |

## 8. Reporting and Visualization

### 8.1 `generate_html_report`

```python
def generate_html_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
    template_type: str = "standard",
) -> str:
```

Steps:

1. Read investigation, artifacts, links, platform presences and audit trail from SQLite.
2. `correlate_identities(conn, investigation_id)` for identity profiles; per-profile risk score and level from `scorer`.
3. Build derived sections: investigation timeline, key findings, confidence metrics, risk matrix, recommendations, priority queue, geographic data, platform heatmap, correlation strength, verification status, anomaly detection and automatic escalation flags.
4. `_generate_embedded_graph(...)` calls `generate_interactive_graph` into a temporary file and inlines the resulting HTML.
5. `_select_template(template_type)` chooses between `HTML_TEMPLATE` (standard), `EXECUTIVE_TEMPLATE`, `TECHNICAL_TEMPLATE` and `LEGAL_TEMPLATE` — all module-level strings, not files on disk.
6. Render and write:

```python
env = Environment(loader=BaseLoader())
template = env.from_string(template_content)
html = template.render(...)
```

Default output path is `reports/{investigation_id}_report.html`; the function returns the path written.

### 8.2 `generate_json_report`

```python
def generate_json_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    output_path: Optional[str] = None,
) -> str:
```

Serialises `metadata` (generator, version, timestamp), `investigation`, `summary` counts, `identities` (from the same correlation call), `artifacts`, `links`, `platform_presences` and graph node/edge counts to `reports/{investigation_id}_report.json`, returning the path.

### 8.3 `src/graph/visualizer.py`

- `generate_interactive_graph(conn, investigation_id, output_path=None)` builds the identity graph via `build_identity_graph`, converts it into a pyvis `Network` (forceAtlas2Based physics, per-type node styling, edge width scaled by confidence) and writes standalone HTML to `reports/{investigation_id}_graph.html`.
- `get_graph_stats(conn, investigation_id)` returns node and edge counts, connected components, density, artifact-type distribution and degree statistics.
- Node/edge styling in this module uses colour, which is a runtime visual concern and independent of the colourless Mermaid diagrams in this documentation set.

## 9. Analysis Subsystem

| Component | Entry points | Behaviour |
| --- | --- | --- |
| `PatternRecognizer` (`pattern_recognition.py`) | `analyze_all_investigations()`, `find_recurring_artifacts(min_frequency=2)`, `get_investigation_patterns(id)` | SQL aggregation across all investigations producing `Pattern(pattern_type, pattern_value, frequency, investigations, first_seen, last_seen)` groups for artifacts, platforms and risks, plus pairwise investigation similarity scores |
| `TrendAnalyzer` (`trend_analysis.py`) | `analyze_trends(baseline_days=30, analysis_days=7)`, `compare_to_baseline(investigation_id)` | Computes per-period metrics from SQLite, derives `Trend(metric, baseline_value, current_value, change_percent, direction, significance, timeframe)` and flags emerging threats |
| `StatisticalAnalyzer` (`statistical_analysis.py`) | `calculate_confidence_interval`, `test_significance`, `calculate_sample_size`, `analyze_distribution`, `compare_means` | Pure computation over caller-supplied numeric lists, with internal t/z score tables and an approximate p-value; no database access |

## 10. Workflow API

`WorkflowAPI(host="0.0.0.0", port=5000, debug=False)` builds a Flask app with CORS enabled and registers routes in `_setup_routes`. `_authenticate()` requires an `X-API-Key` header and, when `api_keys` is non-empty, membership in that set; `add_api_key(key)` populates it and `create_api_server(...)` is the module-level factory.

| Route | Method | Handler behaviour |
| --- | --- | --- |
| `/api/v1/health` | GET | Static status payload (no auth) |
| `/api/v1/investigations` | POST | Builds `InvestigationConfig` from the JSON `config` block and runs `run_investigation` synchronously; returns 201 with counts |
| `/api/v1/investigations` | GET | `list_investigations` |
| `/api/v1/investigations/<id>` | GET | `get_investigation`, 404 when absent |
| `/api/v1/investigations/<id>/report` | GET | `?format=json` → `generate_json_report`, otherwise `generate_html_report` |
| `/api/v1/investigations/<id>/artifacts` | GET | Direct SQL over `artifacts` |
| `/api/v1/investigations/<id>/links` | GET | Direct SQL over `artifact_links` |
| `/api/v1/investigations/<id>/risk` | GET | Direct SQL over a `risk_indicators` table |

Defects in this layer are listed in [§12](#12-known-gaps); the API is the least code-consistent subsystem in the repository.

## 11. Collaboration

`CommentManager(db_path=None)` creates the `comments` table on construction (`CREATE TABLE IF NOT EXISTS`, foreign keys to `investigations`, `artifacts` and self-referencing `parent_id`). Every method opens and closes its own connection through `get_connection`.

| Method | Purpose |
| --- | --- |
| `add_comment(investigation_id, content, author="system", artifact_id=None, parent_id=None, comment_type="general")` | Inserts a UUID4-keyed comment, returns the ID |
| `get_investigation_comments(investigation_id)` | Chronological `Comment` list |
| `get_artifact_comments(artifact_id)` | Comments attached to one artifact |
| `update_comment(comment_id, content, author)` | Updates content and `updated_at`; returns whether a row changed |
| `delete_comment(comment_id)` | Hard delete; returns whether a row changed |
| `get_comment_thread(comment_id)` | Direct replies (single level) |
| `get_comment_count(investigation_id)` | Count for summaries |

`Comment` mirrors the table columns. The manager is not wired into the CLI, orchestrator or API — it is a library-level facility.

## 12. Known Gaps

| # | Area | Gap |
| --- | --- | --- |
| 1 | External tools | `run_tool_analysis` dereferences every tool's method on the selected integration and raises `AttributeError` before dispatch; the orchestrator's `except Exception` hides it, so no external tool currently yields artifacts |
| 2 | External tools | 35 tools are declared in `ToolChecker`, 9 have integrations; the remainder are detection-only |
| 3 | Correlation | `IdentityProfile` exposes only phones, emails, usernames, images and platforms; `fullname` artifacts join the graph but never appear on a profile |
| 4 | Correlation | Undirected `nx.Graph` and `connected_components`, despite "weakly connected components" wording elsewhere |
| 5 | Breach data | `check_email_breaches` returns mock breaches when no HIBP key is configured, and the orchestrator never passes one |
| 6 | Email OSINT | Gravatar, GitHub and HIBP checks are nested under the `is_corporate` branch and are skipped for free-provider domains |
| 7 | Google Dorks | `check_google_dorks_availability` always returns `True`, so dorking runs for usernames even when `--use-google-dorks` is not passed |
| 8 | Orchestrator | BFS completion log lives inside the `while` loop; `processed_count` is double-incremented on the single-artifact path |
| 9 | Orchestrator | Dedup via `seen` is applied after concurrent workers return, so intra-batch duplicates rely on `add_artifact`'s non-transactional existence check |
| 10 | Storage | `investigation_metadata` inserts omit the `metadata_id` primary key |
| 11 | Storage | `audit_trail` helpers exist and reports read them, but nothing writes audit rows |
| 12 | API | `InvestigationConfig(use_external_tools=...)` is not a valid field (`check_external_tools`), the `risk_indicators` table does not exist, `artifact_links` columns are misnamed, connections are closed before report generation, and `generate_json_report`'s return value is a path being `jsonify`d |
| 13 | CLI | `plugins list/info` call `registry.get_plugin`, `plugin.version`, `plugin.description` and `plugin.is_enabled()`, none of which exist; `plugins enable/disable` only mutate memory |
| 14 | Plugins | `PluginManager` reads config by class name while `config.yaml` uses snake_case tool names, so per-plugin YAML settings never apply; `get_plugin_config` also maps `timeout` onto `plugin_settings.rate_limit_seconds` (0.1 s in the shipped config) |
| 15 | Reporting | `_select_template` and `_generate_key_findings` are each defined twice in `html_report.py` |

## 13. Sequence Diagrams

Runtime sequences live in [SEQUENCE_DIAGRAMS.md](SEQUENCE_DIAGRAMS.md):

- [End-to-end investigation](SEQUENCE_DIAGRAMS.md#1-end-to-end-investigation)
- [Username investigation path](SEQUENCE_DIAGRAMS.md#2-username-investigation-path)
- [Domain investigation path](SEQUENCE_DIAGRAMS.md#3-domain-investigation-path)
- [Report generation path](SEQUENCE_DIAGRAMS.md#4-report-generation-path)

## Related Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) — system context, layers, data model, technology stack
- [README.md](README.md) — documentation index

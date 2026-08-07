# Ghost Identity Hunter — Sequence Diagrams

Runtime sequences for the main flows, matching the code in `src/`. All diagrams are Mermaid `sequenceDiagram` blocks with double-quoted labels and no colours.

## Table of Contents

- [1. End-to-End Investigation](#1-end-to-end-investigation)
- [2. Username Investigation Path](#2-username-investigation-path)
- [3. Domain Investigation Path](#3-domain-investigation-path)
- [4. Report Generation Path](#4-report-generation-path)
- [5. Notes and Caveats](#5-notes-and-caveats)

---

## 1. End-to-End Investigation

CLI `investigate` through BFS expansion, persistence, correlation and report generation.

```mermaid
sequenceDiagram
    autonumber
    actor User as "Investigator"
    participant CLI as "src/cli.py investigate"
    participant Orch as "src/orchestrator.py run_investigation"
    participant Tools as "ToolChecker"
    participant Reg as "PluginRegistry / PluginManager"
    participant DB as "src/storage/database.py (SQLite)"
    participant Mod as "OSINT module (_process_artifact)"
    participant Ext as "_process_external_tools"
    participant Proc as "External binary (subprocess)"
    participant Corr as "correlation.analyze_correlation"
    participant Rep as "generate_html_report / generate_json_report"

    User->>CLI: "ghost-hunter investigate -e email -u username"
    CLI->>DB: "get_connection(db_path)"
    CLI->>Orch: "run_investigation(conn, seeds, config, title)"

    opt "config.check_external_tools"
        Orch->>Tools: "check_all_tools()"
        Tools-->>Orch: "available and missing tool lists"
    end

    Orch->>Reg: "discover_plugins() and build PluginManager"
    Reg-->>Orch: "manager or None on failure"

    Orch->>DB: "create_investigation(title)"
    DB-->>Orch: "investigation_id INV-xxxxxxxx"

    loop "for each seed"
        Orch->>DB: "add_artifact(depth=0, source='seed')"
        DB-->>Orch: "artifact_id"
        Orch->>Orch: "seen.add('type:value') and queue.append(...)"
    end

    loop "while queue is not empty"
        Orch->>Orch: "pop batch of min(max_concurrent, len(queue)) items"

        alt "batch of one"
            Orch->>Mod: "_process_artifact(conn, inv_id, artifact, config, manager)"
        else "batch of many"
            Orch->>Orch: "ThreadPoolExecutor workers, one DB connection each"
            Orch->>Mod: "_process_artifact(worker_conn, ...)"
        end

        Mod->>DB: "UPDATE artifacts SET metadata = analysis JSON"
        Mod->>DB: "add_platform_presence(...) where applicable"

        Mod->>Ext: "_process_external_tools(artifact)"
        Ext->>Tools: "check_tool_availability(tool)"
        Tools-->>Ext: "True or False"
        opt "tool available"
            Ext->>Proc: "run_tool_analysis(tool, analysis_type, target)"
            Proc-->>Ext: "ToolResult with artifacts (see caveats)"
        end
        Ext-->>Mod: "external artifacts"

        opt "plugin manager present"
            Mod->>Reg: "execute_plugins_for_artifact(parallel=True, max_workers=5)"
            Reg-->>Mod: "PluginResult list"
        end

        Mod-->>Orch: "discovered artifact dicts"

        loop "for each discovered artifact when depth < max_depth"
            alt "key already in seen"
                Orch->>Orch: "skip duplicate"
            else "new key"
                Orch->>DB: "add_artifact(depth = current_depth + 1)"
                DB-->>Orch: "new_artifact_id"
                Orch->>DB: "add_link(current_id, new_artifact_id, link_type)"
                Orch->>Orch: "queue.append(new artifact)"
            end
        end
    end

    Orch->>DB: "complete_investigation(investigation_id)"
    Orch->>DB: "get_artifacts / get_links / get_platform_presences"
    DB-->>Orch: "rows for summary counts"
    Orch->>Corr: "analyze_correlation(artifacts, links)"
    Corr-->>Orch: "CorrelationAnalysis"
    Orch->>DB: "INSERT investigation_metadata key 'correlation_analysis'"
    Orch-->>CLI: "InvestigationResult"

    opt "auto report enabled"
        CLI->>Rep: "generate_html_report / generate_json_report"
        Rep-->>CLI: "output file paths"
    end
    CLI-->>User: "summary and report paths"
```

## 2. Username Investigation Path

Username seed: built-in platform search, Sherlock and Google Dorks.

```mermaid
sequenceDiagram
    autonumber
    participant Orch as "orchestrator._process_artifact"
    participant UP as "_process_username"
    participant US as "modules/username_search"
    participant HTTP as "utils/http_client session"
    participant DB as "storage/database"
    participant Ext as "_process_external_tools"
    participant TC as "utils/tool_checker"
    participant SH as "sherlock (subprocess)"
    participant GD as "modules/google_dorks"
    participant SE as "Search engine (Google, DuckDuckGo or CSE API)"
    participant PM as "PluginManager"

    Orch->>UP: "_process_username(artifact, value)"
    UP->>US: "search_username(value)"

    par "one worker per configured platform"
        US->>HTTP: "GET platform url_template (allow_redirects=False)"
        HTTP-->>US: "status code and optional JSON body"
    end
    US-->>UP: "UsernameSearchResult(platforms_found, not_found, errors)"

    UP->>DB: "UPDATE artifacts SET metadata = search JSON"
    loop "for each found platform"
        UP->>DB: "add_platform_presence(platform, profile_url, username)"
    end
    UP-->>Orch: "platform_presence artifacts (confidence 0.85)"

    Orch->>Ext: "_process_external_tools(username artifact)"
    Ext->>TC: "check_tool_availability('sherlock')"
    alt "sherlock installed"
        Ext->>SH: "run_tool_analysis('sherlock', 'username_search', value)"
        SH-->>Ext: "ToolResult with platform_presence artifacts"
    else "sherlock missing"
        Ext->>Ext: "skip sherlock"
    end

    Ext->>GD: "check_google_dorks_availability(api_key) then run_google_dorks_search(...)"
    GD->>GD: "select up to max_patterns dork templates"
    par "dork patterns in a thread pool"
        GD->>SE: "execute dork query with retry and backoff"
        SE-->>GD: "result URLs"
    end
    GD-->>Ext: "discovered artifacts from dork results"
    Ext-->>Orch: "external artifacts"

    Orch->>PM: "execute_plugins_for_artifact(username artifact)"
    PM-->>Orch: "UsernameSearchPlugin, GoogleDorksPlugin, SherlockPlugin results"
    Orch->>DB: "add_artifact and add_link for new artifacts"
```

## 3. Domain Investigation Path

Domain artifacts are synthesised from emails, then expanded with the domain tool chain.

```mermaid
sequenceDiagram
    autonumber
    participant Orch as "orchestrator BFS"
    participant EP as "_process_email"
    participant Ext as "_process_external_tools"
    participant TC as "utils/tool_checker"
    participant TH as "theHarvester (subprocess)"
    participant AM as "amass (subprocess)"
    participant WH as "whois (subprocess)"
    participant WB as "Wayback CDX API (HTTP)"
    participant DB as "storage/database"

    Orch->>EP: "process email artifact"
    EP-->>Orch: "username and breach artifacts"
    Orch->>Ext: "_process_external_tools(email artifact)"
    Ext-->>Orch: "domain artifact (link_type 'domain_of_email', confidence 0.7)"
    Orch->>DB: "add_artifact(domain) and add_link(email -> domain)"

    Note over Orch: "next BFS hop processes the domain artifact"

    Orch->>Ext: "_process_external_tools(domain artifact)"
    Ext->>TC: "check_tool_availability('theharvester')"
    opt "available"
        Ext->>TH: "run_tool_analysis('theharvester', 'email_harvest', domain)"
        TH-->>Ext: "email artifacts"
        Ext->>TH: "run_tool_analysis('theharvester', 'subdomain_harvest', domain)"
        TH-->>Ext: "subdomain artifacts"
    end

    Ext->>TC: "check_tool_availability('amass')"
    opt "available"
        Ext->>AM: "run_tool_analysis('amass', 'subdomain_enum', domain)"
        AM-->>Ext: "subdomain artifacts"
    end

    Ext->>TC: "check_tool_availability('whois')"
    opt "available"
        Ext->>WH: "run_tool_analysis('whois', 'domain_lookup', domain)"
        WH-->>Ext: "registrar, dates, contact emails"
    end

    Ext->>WB: "run_tool_analysis('wayback_machine', 'historical_urls', domain)"
    WB-->>Ext: "historical URL entries"

    Ext-->>Orch: "aggregated domain artifacts"
    Orch->>DB: "add_artifact and add_link per new artifact when depth < max_depth"
```

## 4. Report Generation Path

```mermaid
sequenceDiagram
    autonumber
    actor User as "Investigator"
    participant CLI as "src/cli.py report"
    participant Rep as "reporting/html_report.py"
    participant DB as "storage/database"
    participant Corr as "correlation/linker.correlate_identities"
    participant Score as "correlation/scorer"
    participant Viz as "graph/visualizer.generate_interactive_graph"
    participant J2 as "Jinja2 Environment(BaseLoader)"
    participant FS as "reports/ directory"

    User->>CLI: "ghost-hunter report --id INV-xxxxxxxx --format both"
    CLI->>DB: "get_connection(db_path)"

    CLI->>Rep: "generate_html_report(conn, investigation_id, output_path, template_type)"
    Rep->>DB: "get_investigation / get_artifacts / get_links / get_platform_presences / get_audit_trail"
    DB-->>Rep: "investigation rows"

    Rep->>Corr: "correlate_identities(conn, investigation_id)"
    Corr->>DB: "read artifacts and artifact_links"
    Corr->>Corr: "build_identity_graph and connected_components"
    Corr-->>Rep: "CorrelationResult with IdentityProfile list"

    Rep->>Score: "compute_identity_risk_score and classify_risk_level"
    Score-->>Rep: "risk score and level per profile"

    Rep->>Rep: "build timeline, key findings, risk matrix, heatmap, recommendations"
    Rep->>Viz: "_generate_embedded_graph via generate_interactive_graph"
    Viz->>Corr: "build_identity_graph"
    Viz-->>Rep: "standalone pyvis HTML for inlining"

    Rep->>J2: "from_string(selected template).render(context)"
    J2-->>Rep: "rendered HTML"
    Rep->>FS: "write reports/{id}_report.html"
    Rep-->>CLI: "html path"

    opt "format json or both"
        CLI->>Rep: "generate_json_report(conn, investigation_id)"
        Rep->>DB: "re-read investigation data"
        Rep->>Corr: "correlate_identities"
        Rep->>FS: "write reports/{id}_report.json"
        Rep-->>CLI: "json path"
    end

    CLI-->>User: "report file paths"
```

## 5. Notes and Caveats

- **External tool dispatch**: `run_tool_analysis` currently raises `AttributeError` while building its dispatch table, and the orchestrator swallows the exception, so in practice the subprocess interactions in diagrams 1 and 3 produce no artifacts until that function is fixed. See [LLD §5.3](LLD.md#53-run_tool_analysis).
- **Google Dorks gating**: `check_google_dorks_availability` always returns `True`, so the dork branch in diagram 2 runs for every username regardless of `--use-google-dorks`.
- **Breach data**: without a HaveIBeenPwned API key, `check_email_breaches` returns mock breaches, which is the default path in diagram 3.
- **Depth cutoff**: artifacts discovered when `current_depth == max_depth` are dropped before persistence, so the final BFS hop performs collection without storing new nodes.
- **Correlation direction**: `correlate_identities` uses an undirected graph, so the `source_artifact` / `target_artifact` orientation persisted by `add_link` does not affect clustering.

## Related Documents

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [LLD.md](LLD.md)
- [README.md](README.md)

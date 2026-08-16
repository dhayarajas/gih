"""
Ghost Identity Hunter CLI - OSINT Investigation Tool

PURPOSE:
--------
This module provides the command-line interface for Ghost Identity Hunter, an automated
OSINT investigation platform that correlates fragmented digital identities into unified
attribution profiles.

FUNCTIONALITY:
--------------
- CLI command parsing and validation using Click framework
- Investigation orchestration through BFS (Breadth-First Search) pipeline
- Identity correlation and graph analysis
- Report generation in HTML, PDF, and JSON formats
- Investigation management (list, create, retrieve, delete)

COMMANDS:
---------
- investigate: Start new OSINT investigation from seed artifacts
- list: List all investigations in database
- report: Generate investigation reports
- graph: Create interactive identity graph visualizations
- correlate: Run identity correlation on existing investigations

USAGE EXAMPLES:
--------------
# Start investigation with email and phone
python src/cli.py investigate --email "user@example.com" --phone "+1234567890"

# List all investigations
python src/cli.py list

# Generate HTML report
python src/cli.py report --id INV-12345678

# Create interactive graph
python src/cli.py graph --id INV-12345678 --output graph.html

DEPENDENCIES:
-------------
- click: CLI framework for command parsing
- pathlib: Path handling for database files
- src.orchestrator: Investigation pipeline management
- src.correlation: Identity graph analysis
- src.graph: Graph visualization
- src.reporting: Report generation
- src.storage: Database operations

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
2.0 - Production Ready Implementation
"""

import logging
import os
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

import click
from tabulate import tabulate

from src.modules.external_tools import get_tool_coverage
from src.orchestrator import (
    InvestigationAborted,
    InvestigationConfig,
    InvestigationResult,
    run_investigation,
)
from src.correlation.linker import correlate_identities
from src.correlation.scorer import compute_identity_risk_score, classify_risk_level
from src.graph.visualizer import LAYOUTS, generate_interactive_graph, get_graph_stats
from src.reporting.html_report import generate_html_report, generate_json_report
from src.storage.database import get_connection, list_investigations, get_investigation
from src.plugins.manager import PluginRegistry, PluginManager
from src.config.loader import get_config
from src.utils.matching import get_match_policy
from src.utils.text import ControlSafeFormatter


def setup_logging(verbose: bool = False) -> None:
    """Configure logging to output to both console and file."""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Create log file with timestamp
    import getpass
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f"{getpass.getuser()}_{timestamp}.log"
    
    # Configure logging format
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%H:%M:%S"
    
    # A tool prints whatever the target served it, and those bytes reach log
    # records through the values built from them; escaped here, the log file
    # stays a text file that grep and a reviewer can still read.
    formatter = ControlSafeFormatter(fmt=log_format, datefmt=date_format)
    handlers: list[logging.Handler] = [
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout),
    ]
    for handler in handlers:
        handler.setFormatter(formatter)

    # Configure root logger
    logging.basicConfig(level=level, handlers=handlers)
    
    logging.info("Logging to file: %s", log_file)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--db", "db_path", type=click.Path(), default=None, help="Database path")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, db_path: Optional[str]) -> None:
    """Ghost Identity Hunter - OSINT Investigation Tool.

    Link fragmented digital identities into unified attribution profiles.
    """
    setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["db_path"] = Path(db_path) if db_path else None


def _json_output_path(report_output: Optional[str], report_format: str) -> Optional[str]:
    """Keep --report-format both from writing the JSON over the HTML.

    Both generators honour --report-output verbatim, so a single path would
    leave the caller with a .html file containing JSON.
    """
    if not report_output or report_format != "both":
        return report_output

    path = Path(report_output)
    json_path = path.with_suffix(".json")
    if json_path == path:
        json_path = path.with_name(f"{path.stem}_data.json")

    return str(json_path)


def _shareable_copy(conn, investigation_id: str, html_path: str,
                    template_type: str, sections: Optional[str],
                    compare_id: Optional[str] = None) -> Optional[str]:
    """Write a masked twin of a report next to it.

    A toggle inside the report could only unmask what the file already holds,
    so the shareable version is a second file generated with the values
    removed. The working copy stays complete.
    """
    path = Path(html_path)
    redacted = path.with_name(f"{path.stem}_redacted{path.suffix}")
    try:
        return generate_html_report(
            conn,
            investigation_id,
            str(redacted),
            template_type=template_type,
            sections=sections,
            redact=True,
            compare_id=compare_id,
        )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        # The working report is already written; a failure here must not undo it.
        logging.getLogger(__name__).warning("Shareable copy not written: %s", exc)
        return None


def _partial_result(conn, investigation_id: str) -> InvestigationResult:
    """Summarise an investigation from what it managed to store."""
    from src.storage import database as dbmod

    return InvestigationResult(
        investigation_id=investigation_id,
        total_artifacts=len(dbmod.get_artifacts(conn, investigation_id)),
        total_links=len(dbmod.get_links(conn, investigation_id)),
        total_platforms=len(dbmod.get_platform_presences(conn, investigation_id)),
    )


def _print_tool_coverage() -> None:
    """Print the availability and integration status of every declared OSINT tool."""
    coverage = get_tool_coverage()
    rows = [
        [
            name,
            "yes" if info["available"] else "no",
            "yes" if info["integrated"] else "no",
            ", ".join(info["artifact_types"]) or "-",
            info["reason"] or "-",
        ]
        for name, info in sorted(coverage.items())
    ]

    click.echo("\nTool coverage (integration status):")
    click.echo(tabulate(rows, headers=["Tool", "Available", "Integrated", "Artifact types", "Note"]))

    integrated = sum(1 for info in coverage.values() if info["integrated"])
    usable = sum(1 for info in coverage.values() if info["integrated"] and info["available"])
    click.echo(f"\nIntegrated: {integrated}/{len(coverage)}  |  Integrated and available now: {usable}")


@cli.command()
@click.option("--phone", "-p", multiple=True, help="Phone number to investigate")
@click.option("--email", "-e", multiple=True, help="Email address to investigate")
@click.option("--username", "-u", multiple=True, help="Username to investigate")
@click.option("--full-name", "-n", "full_name", multiple=True, help="Full name to investigate (image-based identity matching)")
@click.option("--image", "-i", multiple=True, help="Image file path to investigate")
@click.option("--domain", "-d", multiple=True, help="Domain to investigate")
@click.option("--ip", multiple=True, help="IP address to investigate")
@click.option("--title", "-t", default=None, help="Investigation title")
@click.option("--depth", default=2, help="Max investigation depth (default: 2)")
@click.option("--no-breach", is_flag=True, help="Skip breach checks")
@click.option("--no-username-search", is_flag=True, help="Skip username platform searches")
@click.option("--auto-report/--no-auto-report", default=None, help="Auto-generate report after investigation (default from config)")
@click.option("--report-format", type=click.Choice(["html", "json", "both", "pdf", "csv"]), default=None, help="Report format for auto-generation")
@click.option("--report-output", default=None, help="Custom output path for auto-generated report")
@click.option("--report-template", type=click.Choice(["standard", "executive", "technical", "legal"]), default=None, help="HTML report template (default: standard / config)")
@click.option("--report-sections", default=None, help="Comma-separated standard-template sections to include")
@click.option("--redact-report", is_flag=True, help="Mask sensitive values in auto-generated reports")
@click.option("--shareable-copy/--no-shareable-copy", default=True,
              help="Also write a masked <name>_redacted.html next to the report (default: on)")
@click.option("--use-external-tools", is_flag=True, default=True, help="Use external OSINT tools if available (default: enabled)")
@click.option("--no-external-tools", is_flag=True, help="Skip external OSINT tools")
@click.option("--check-tools", is_flag=True, help="Check available external tools")
@click.option("--strict-match/--no-strict-match", default=None,
              help="Only record findings that carry the target's exact value (default from config)")
@click.option("--use-neo4j", is_flag=True, help="Use Neo4j for graph correlation (requires Neo4j database)")
@click.option("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j connection URI (default: bolt://localhost:7687)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username (default: neo4j)")
@click.option("--neo4j-password", default="password", help="Neo4j password (default: password)")
@click.option("--neo4j-database", default="neo4j", help="Neo4j database name (default: neo4j)")
@click.option("--use-google-dorks", is_flag=True, help="Use Google Dorks for advanced username discovery")
@click.option("--google-api-key", default=lambda: os.environ.get("GOOGLE_API_KEY"), help="Google Custom Search API key (optional, can be set via GOOGLE_API_KEY env var)")
@click.option("--google-cx", default=lambda: os.environ.get("GOOGLE_CX"), help="Google Custom Search Engine ID (optional, can be set via GOOGLE_CX env var)")
@click.option("--use-google-api", is_flag=True, help="Use Google API instead of web scraping (requires API key)")
@click.option("--search-engine", default="auto", type=click.Choice(["auto", "duckduckgo", "google", "bing"], case_sensitive=False), help="Search engine for Google Dorks (auto, duckduckgo, google, bing)")
@click.pass_context
def investigate(
    ctx: click.Context,
    phone: tuple,
    email: tuple,
    username: tuple,
    full_name: tuple,
    image: tuple,
    domain: tuple,
    ip: tuple,
    title: Optional[str],
    depth: int,
    no_breach: bool,
    no_username_search: bool,
    auto_report: Optional[bool],
    report_format: Optional[str],
    report_output: Optional[str],
    report_template: Optional[str],
    report_sections: Optional[str],
    redact_report: bool,
    shareable_copy: bool,
    use_external_tools: bool,
    no_external_tools: bool,
    check_tools: bool,
    strict_match: Optional[bool],
    use_neo4j: bool,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
    use_google_dorks: bool,
    google_api_key: Optional[str],
    google_cx: Optional[str],
    use_google_api: bool,
    search_engine: str,
) -> None:
    """Start a new OSINT investigation from seed artifacts.

    Examples:
        ghost-hunter investigate --phone "+1-555-0123"
        ghost-hunter investigate --email "suspect@example.com"
        ghost-hunter investigate -p "+1-555-0123" -e "suspect@example.com" -u "john_doe"
        ghost-hunter investigate --full-name "Jane Doe"
    """
    # Validate input
    if (
        not phone and not email and not username and not full_name
        and not image and not domain and not ip and not check_tools
    ):
        click.echo(
            "Error: At least one seed artifact required "
            "(--phone, --email, --username, --full-name, --image, --domain, "
            "or --ip) or use --check-tools"
        )
        sys.exit(1)

    # Check external tools if requested
    if check_tools:
        from src.utils.tool_checker import get_tool_checker
        tool_checker = get_tool_checker()
        tool_checker.check_all_tools()
        tool_checker.print_status()
        _print_tool_coverage()
        return

    # Build seed list
    seeds = []
    for p in phone:
        seeds.append({"type": "phone", "value": p})
    for e in email:
        seeds.append({"type": "email", "value": e})
    for u in username:
        seeds.append({"type": "username", "value": u})
    for n in full_name:
        seeds.append({"type": "fullname", "value": n})
    for i in image:
        if not Path(i).exists():
            click.echo(f"Warning: Image file not found: {i}")
            continue
        seeds.append({"type": "image", "value": str(Path(i).resolve())})
    for d in domain:
        seeds.append({"type": "domain", "value": d})
    for address in ip:
        seeds.append({"type": "ip_address", "value": address})

    if not seeds:
        click.echo("Error: No valid seed artifacts provided")
        sys.exit(1)

    # Configure investigation
    match_policy = get_match_policy()
    if strict_match is not None:
        match_policy = replace(match_policy, enabled=strict_match)

    config = InvestigationConfig(
        match_policy=match_policy,
        max_depth=depth,
        check_breaches=not no_breach,
        search_usernames=not no_username_search,
        verbose=ctx.obj["verbose"],
        check_external_tools=use_external_tools and not no_external_tools,
        skip_missing_tools=True,
        use_neo4j=use_neo4j,
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        neo4j_database=neo4j_database,
        use_google_dorks=use_google_dorks,
        google_api_key=google_api_key,
        google_cx=google_cx,
        use_google_api=use_google_api,
        search_engine=search_engine,
    )

    # Resolve reporting defaults from config.yaml
    from src.reporting.report_data import load_reporting_config
    reporting_cfg = load_reporting_config()
    if auto_report is None:
        auto_report = reporting_cfg.get("auto_generate", True)
    if report_format is None:
        report_format = reporting_cfg.get("default_format") or "html"
    if report_template is None:
        report_template = reporting_cfg.get("template") or "standard"

    click.echo(f"Starting investigation with {len(seeds)} seed artifact(s)...")
    click.echo(f"  Depth limit: {depth}")
    click.echo(f"  Breach checks: {'disabled' if no_breach else 'enabled'}")
    click.echo(f"  Username search: {'disabled' if no_username_search else 'enabled'}")
    click.echo(f"  External OSINT tools: {'enabled' if config.check_external_tools else 'disabled'}")
    click.echo(f"  Graph correlation: {'Neo4j' if config.use_neo4j else 'NetworkX'}")
    click.echo(f"  Google Dorks: {'enabled' if config.use_google_dorks else 'disabled'}")
    if config.use_google_dorks:
        click.echo(f"  Search engine: {config.search_engine}")
    click.echo(f"  Auto-report: {'disabled' if not auto_report else 'enabled'}")
    if auto_report:
        click.echo(f"  Report format: {report_format}")
        click.echo(f"  Report template: {report_template}")
    click.echo()

    # Run investigation
    conn = get_connection(ctx.obj.get("db_path"))
    try:
        try:
            result = run_investigation(conn, seeds, config, title=title)
            heading = f"Investigation Complete: {result.investigation_id}"
        except InvestigationAborted as aborted:
            if not aborted.investigation_id:
                raise
            # Findings are stored as they are made, so the run stopping is no
            # reason to throw away what it already found.
            result = _partial_result(conn, aborted.investigation_id)
            heading = f"Investigation Stopped Early: {result.investigation_id}"
            click.echo(f"\n⚠ The run stopped early: {aborted}")
            click.echo("  Reporting on what it found before it stopped.")

        click.echo(f"\n{'=' * 60}")
        click.echo(heading)
        click.echo(f"{'=' * 60}")
        click.echo(f"  Artifacts discovered: {result.total_artifacts}")
        click.echo(f"  Connections found:    {result.total_links}")
        click.echo(f"  Platform presences:   {result.total_platforms}")

        if result.risk_indicators:
            click.echo("\n  Risk Indicators:")
            for indicator in sorted(set(result.risk_indicators))[:10]:
                click.echo(f"    - {indicator}")

        # Auto-generate report if enabled
        if auto_report:
            click.echo(f"\n{'=' * 60}")
            click.echo("Auto-generating investigation report...")
            click.echo(f"{'=' * 60}")
            
            try:
                from src.reporting.html_report import generate_html_report, generate_json_report
                from src.reporting.exports import (
                    export_artifacts_csv,
                    export_presences_csv,
                    generate_pdf_from_html,
                )
                from src.reporting.report_data import default_output_path
                from src.storage import database as dbmod

                out_dir = reporting_cfg.get("output_dir") or "./reports"
                html_path = None

                if report_format in ("html", "both", "pdf"):
                    html_out = report_output
                    if report_format == "pdf" and report_output and str(report_output).endswith(".pdf"):
                        html_out = str(Path(report_output).with_suffix(".html"))
                    html_path = generate_html_report(
                        conn,
                        result.investigation_id,
                        output_path=html_out,
                        template_type=report_template,
                        sections=report_sections,
                        redact=redact_report,
                    )
                    click.echo(f"✓ HTML report saved: {html_path}")
                    if not redact_report and shareable_copy:
                        masked = _shareable_copy(
                            conn, result.investigation_id, html_path,
                            report_template, report_sections,
                        )
                        if masked:
                            click.echo(f"✓ Shareable (masked) copy: {masked}")

                if report_format in ("json", "both"):
                    json_path = generate_json_report(
                        conn,
                        result.investigation_id,
                        output_path=_json_output_path(report_output, report_format),
                        redact=redact_report,
                    )
                    click.echo(f"✓ JSON report saved: {json_path}")

                if report_format == "pdf":
                    pdf_out = report_output if report_output and str(report_output).endswith(".pdf") else None
                    if not pdf_out:
                        pdf_out = default_output_path(result.investigation_id, ".pdf", out_dir)
                    try:
                        pdf_path = generate_pdf_from_html(html_path, pdf_out)
                        click.echo(f"✓ PDF report saved: {pdf_path}")
                    except (RuntimeError, FileNotFoundError) as exc:
                        click.echo(f"PDF export failed: {exc}")
                        click.echo(f"The HTML report is still available: {html_path}")

                if report_format == "csv":
                    arts = dbmod.get_artifacts(conn, result.investigation_id)
                    pres = dbmod.get_platform_presences(conn, result.investigation_id)
                    csv_base = Path(report_output) if report_output else Path(
                        default_output_path(result.investigation_id, "", out_dir)
                    )
                    if csv_base.suffix:
                        arts_csv = csv_base.with_name(csv_base.stem + "_artifacts.csv")
                        pres_csv = csv_base.with_name(csv_base.stem + "_presences.csv")
                    else:
                        arts_csv = Path(str(csv_base) + "_artifacts.csv")
                        pres_csv = Path(str(csv_base) + "_presences.csv")
                    click.echo(f"✓ Artifacts CSV: {export_artifacts_csv(arts, str(arts_csv))}")
                    click.echo(f"✓ Presences CSV: {export_presences_csv(pres, str(pres_csv))}")
                
                click.echo(f"\nReport generation complete!")
                
            except Exception as e:
                click.echo(f"⚠ Report generation failed: {e}")
                if ctx.obj.get("verbose"):
                    import traceback
                    traceback.print_exc()

        click.echo(f"\nTo view the report:  ghost-hunter report --id {result.investigation_id}")
        click.echo(f"To view the graph:   ghost-hunter graph --id {result.investigation_id}")

    finally:
        conn.close()


@cli.command()
@click.option("--id", "investigation_id", required=True, help="Investigation ID")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "both", "pdf", "csv"]), default="html")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--template", "template_type", type=click.Choice(["standard", "executive", "technical", "legal"]), default="standard", help="HTML template (default: standard)")
@click.option("--sections", default=None, help="Comma-separated sections for the standard template")
@click.option("--redact", is_flag=True, help="Mask phones, emails, images, and profile URLs")
@click.option("--shareable-copy/--no-shareable-copy", default=True,
              help="Also write a masked <name>_redacted.html next to the report (default: on)")
@click.option("--compare", "compare_id", default=None,
              help="Prior investigation ID for the changes section, or 'auto' for the "
                   "previous run of the same seeds")
@click.pass_context
def report(ctx: click.Context, investigation_id: str, fmt: str, output: Optional[str],
           template_type: str, sections: Optional[str], redact: bool,
           shareable_copy: bool, compare_id: Optional[str]) -> None:
    """Generate a report for a completed investigation.

    Examples:
        ghost-hunter report --id INV-abc123
        ghost-hunter report --id INV-abc123 --format json
        ghost-hunter report --id INV-abc123 --format both -o ./reports/
        ghost-hunter report --id INV-abc123 --template standard --redact
        ghost-hunter report --id INV-abc123 --compare INV-old --format pdf
        ghost-hunter report --id INV-abc123 --compare auto
    """
    conn = get_connection(ctx.obj.get("db_path"))
    try:
        inv = get_investigation(conn, investigation_id)
        if not inv:
            click.echo(f"Error: Investigation '{investigation_id}' not found")
            sys.exit(1)

        from src.reporting.html_report import generate_html_report, generate_json_report
        from src.reporting.exports import (
            export_artifacts_csv,
            export_presences_csv,
            generate_pdf_from_html,
        )
        from src.reporting.report_data import default_output_path, load_reporting_config
        from src.storage import database as dbmod

        out_dir = load_reporting_config().get("output_dir") or "./reports"
        html_path = None

        if fmt in ("html", "both", "pdf"):
            html_path_arg = output if output and fmt == "html" else None
            if output and fmt == "both":
                html_path_arg = str(Path(output) / f"{investigation_id}_report.html")
            if output and fmt == "pdf" and str(output).endswith(".pdf"):
                html_path_arg = str(Path(output).with_suffix(".html"))
            html_path = generate_html_report(
                conn,
                investigation_id,
                html_path_arg,
                template_type=template_type,
                sections=sections,
                redact=redact,
                compare_id=compare_id,
            )
            click.echo(f"HTML report: {html_path}")
            if not redact and shareable_copy:
                masked = _shareable_copy(
                    conn, investigation_id, html_path,
                    template_type, sections, compare_id,
                )
                if masked:
                    click.echo(f"Shareable (masked) copy: {masked}")

        if fmt in ("json", "both"):
            json_path = output if output and fmt == "json" else None
            if output and fmt == "both":
                json_path = str(Path(output) / f"{investigation_id}_report.json")
            path = generate_json_report(
                conn, investigation_id, json_path, redact=redact, compare_id=compare_id
            )
            click.echo(f"JSON report: {path}")

        if fmt == "pdf":
            pdf_out = output if output and str(output).endswith(".pdf") else default_output_path(
                investigation_id, ".pdf", out_dir
            )
            try:
                path = generate_pdf_from_html(html_path, pdf_out)
                click.echo(f"PDF report: {path}")
            except (RuntimeError, FileNotFoundError) as exc:
                click.echo(f"PDF export failed: {exc}")
                click.echo(f"The HTML report is still available: {html_path}")
                sys.exit(1)

        if fmt == "csv":
            arts = dbmod.get_artifacts(conn, investigation_id)
            pres = dbmod.get_platform_presences(conn, investigation_id)
            base = Path(output) if output else Path(default_output_path(investigation_id, "", out_dir))
            if base.suffix:
                arts_csv = base.with_name(base.stem + "_artifacts.csv")
                pres_csv = base.with_name(base.stem + "_presences.csv")
            else:
                arts_csv = Path(str(base) + "_artifacts.csv")
                pres_csv = Path(str(base) + "_presences.csv")
            click.echo(f"Artifacts CSV: {export_artifacts_csv(arts, str(arts_csv))}")
            click.echo(f"Presences CSV: {export_presences_csv(pres, str(pres_csv))}")

    finally:
        conn.close()




@cli.command()
@click.option("--id", "investigation_id", required=True, help="Investigation ID")
@click.option("--output", "-o", default=None, help="Output HTML file path")
@click.option("--layout", type=click.Choice(LAYOUTS), default=None,
              help="Node layout (default: graph.layout in config)")
@click.option("--collection-threshold", type=int, default=None,
              help="Collapse same-type leaf neighbours into one node at this count; 0 disables")
@click.pass_context
def graph(ctx: click.Context, investigation_id: str, output: Optional[str],
          layout: Optional[str], collection_threshold: Optional[int]) -> None:
    """Generate an interactive identity graph visualization.

    Clicking a node opens that artifact in the report; clicking a collection
    node expands the artifacts it stands for.

    Examples:
        ghost-hunter graph --id INV-abc123
        ghost-hunter graph --id INV-abc123 -o ./graph.html
        ghost-hunter graph --id INV-abc123 --layout hierarchical
        ghost-hunter graph --id INV-abc123 --collection-threshold 0
    """
    conn = get_connection(ctx.obj.get("db_path"))
    try:
        inv = get_investigation(conn, investigation_id)
        if not inv:
            click.echo(f"Error: Investigation '{investigation_id}' not found")
            sys.exit(1)

        # Generate graph
        path = generate_interactive_graph(
            conn, investigation_id, output,
            layout=layout, collection_threshold=collection_threshold,
        )
        if path:
            click.echo(f"Interactive graph: {path}")
        else:
            click.echo("No graph data to visualize")

        # Show stats
        stats = get_graph_stats(conn, investigation_id)
        click.echo("\nGraph Statistics:")
        click.echo(f"  Nodes: {stats['nodes']}")
        click.echo(f"  Edges: {stats['edges']}")
        click.echo(f"  Components: {stats['connected_components']}")
        click.echo(f"  Density: {stats['density']}")
        if "type_distribution" in stats:
            click.echo(f"  Type distribution: {stats['type_distribution']}")

    finally:
        conn.close()


@cli.command("list")
@click.pass_context
def list_cmd(ctx: click.Context) -> None:
    """List all investigations.

    Examples:
        ghost-hunter list
    """
    conn = get_connection(ctx.obj.get("db_path"))
    try:
        investigations = list_investigations(conn)
        if not investigations:
            click.echo("No investigations found.")
            return

        click.echo(f"{'ID':<15} {'Status':<12} {'Created':<22} {'Title'}")
        click.echo("-" * 70)
        for inv in investigations:
            click.echo(
                f"{inv['investigation_id']:<15} "
                f"{inv['status']:<12} "
                f"{inv['created_at'][:19]:<22} "
                f"{inv.get('title', '-')}"
            )

    finally:
        conn.close()


@cli.command()
@click.option("--id", "investigation_id", required=True, help="Investigation ID")
@click.pass_context
def correlate(ctx: click.Context, investigation_id: str) -> None:
    """Run identity correlation on an investigation.

    Shows how artifacts are linked into identity profiles.

    Examples:
        ghost-hunter correlate --id INV-abc123
    """
    conn = get_connection(ctx.obj.get("db_path"))
    try:
        inv = get_investigation(conn, investigation_id)
        if not inv:
            click.echo(f"Error: Investigation '{investigation_id}' not found")
            sys.exit(1)

        result = correlate_identities(conn, investigation_id)

        click.echo(f"\nCorrelation Results for {investigation_id}")
        click.echo(f"{'=' * 50}")
        click.echo(f"  Graph: {result.graph_nodes} nodes, {result.graph_edges} edges")
        click.echo(f"  Connected components: {result.connected_components}")
        click.echo(f"  Identity profiles: {len(result.identities)}")
        click.echo()

        for identity in result.identities:
            risk_score = compute_identity_risk_score(identity.risk_indicators)
            risk_level = classify_risk_level(risk_score)

            click.echo(f"  [{identity.profile_id}] ({identity.artifact_count} artifacts)")
            click.echo(f"    Confidence: {identity.confidence:.0%} | Risk: {risk_level}")
            if identity.phones:
                click.echo(f"    Phones: {', '.join(identity.phones)}")
            if identity.emails:
                click.echo(f"    Emails: {', '.join(identity.emails)}")
            if identity.usernames:
                click.echo(f"    Usernames: {', '.join(identity.usernames)}")
            if identity.platforms:
                platforms = [p.get("platform", "?") for p in identity.platforms]
                click.echo(f"    Platforms: {', '.join(platforms)}")
            if identity.risk_indicators:
                click.echo(f"    Risks: {', '.join(identity.risk_indicators[:5])}")
            click.echo()

    finally:
        conn.close()


@cli.command()
@click.option("--id", "investigation_id", required=True, help="Investigation ID")
@click.option("--show-path", is_flag=True, help="Print the stored file path of each capture")
@click.pass_context
def evidence(ctx: click.Context, investigation_id: str, show_path: bool) -> None:
    """Verify the preserved raw output of an investigation's tool runs.

    Each capture is re-hashed and compared against the digest recorded at
    collection time. Exits non-zero if anything was altered or is missing.

    Examples:
        ghost-hunter evidence --id INV-abc123
    """
    from src.reporting.report_data import build_preserved_evidence

    conn = get_connection(ctx.obj.get("db_path"))
    try:
        inv = get_investigation(conn, investigation_id)
        if not inv:
            click.echo(f"Error: Investigation '{investigation_id}' not found")
            sys.exit(1)

        summary = build_preserved_evidence(conn, investigation_id)
        if not summary["enabled"]:
            click.echo(f"No preserved evidence recorded for {investigation_id}")
            return

        click.echo(f"\nPreserved Evidence for {investigation_id}")
        click.echo(f"{'=' * 50}")
        for item in summary["items"]:
            click.echo(
                f"  [{item['status'].upper():8}] {item['captured_at'][:19]} "
                f"{item['tool']:16} {item['byte_size']:>8} B  {item['sha256'][:16]}…"
            )
            if item.get("command"):
                click.echo(f"             {item['command']}")
            if show_path:
                click.echo(f"             {item['stored_path']}")
        click.echo(
            f"\n  {summary['verified']} verified, {summary['modified']} modified, "
            f"{summary['missing']} missing ({summary['total']} total)"
        )
        if not summary["intact"]:
            sys.exit(1)
    finally:
        conn.close()


@cli.group()
def plugins():
    """Plugin management commands."""
    pass


def _resolve_plugin_name(registry: PluginRegistry, wanted: str) -> Optional[str]:
    """Find the registry name of a plugin the user named.

    The registry knows plugins by class name (`SherlockPlugin`) while config.yaml
    and the tools themselves use the tool name (`sherlock`), so both are accepted.
    """
    names = registry.list_plugins()
    if wanted in names:
        return wanted

    target = wanted.replace("_", "").replace("-", "").lower()
    for name in names:
        if name.removesuffix("Plugin").lower() == target:
            return name
        instance = registry.get_plugin_instance(name)
        if instance and instance.get_name().replace("_", "").replace("-", "").lower() == target:
            return name
    return None


@plugins.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed plugin information")
def plugins_list(verbose: bool):
    """List all registered plugins.

    Examples:
        ghost-hunter plugins list
        ghost-hunter plugins list --verbose
    """
    registry = PluginRegistry()
    registry.discover_plugins()
    manager = PluginManager(registry)

    plugin_names = sorted(registry.list_plugins())
    if not plugin_names:
        click.echo("No plugins found.")
        return

    click.echo(f"\nRegistered Plugins ({len(plugin_names)}):")
    click.echo("=" * 50)

    for plugin_name in plugin_names:
        plugin = registry.get_plugin_instance(plugin_name)
        if not plugin:
            continue
        enabled = manager.is_plugin_enabled(plugin_name)
        click.echo(f"  [{'✓' if enabled else '✗'}] {plugin_name} ({plugin.get_name()})")
        click.echo(f"      Enabled in config: {'yes' if enabled else 'no'}")
        click.echo(f"      Artifact types: {', '.join(plugin.get_supported_artifact_types()) or '-'}")
        if verbose:
            click.echo(f"      Version: {plugin.get_version()}")
            click.echo(f"      Description: {plugin.get_description() or '-'}")
            click.echo(f"      Installed now: {'yes' if plugin.is_available() else 'no'}")
            click.echo(f"      Requires: {', '.join(plugin.get_required_dependencies()) or '-'}")
        click.echo()


@plugins.command()
@click.argument("plugin_name")
def info(plugin_name: str):
    """Show detailed information about a specific plugin.

    The plugin may be named by its class (SherlockPlugin) or by its tool name
    as it appears in config.yaml (sherlock).

    Examples:
        ghost-hunter plugins info sherlock
        ghost-hunter plugins info SherlockPlugin
    """
    registry = PluginRegistry()
    registry.discover_plugins()

    resolved = _resolve_plugin_name(registry, plugin_name)
    plugin = registry.get_plugin_instance(resolved) if resolved else None
    if not plugin:
        click.echo(f"Error: Plugin '{plugin_name}' not found")
        sys.exit(1)

    manager = PluginManager(registry)
    enabled = manager.is_plugin_enabled(resolved)

    click.echo(f"\nPlugin: {resolved}")
    click.echo("=" * 50)
    click.echo(f"  Tool name: {plugin.get_name()}")
    click.echo(f"  Version: {plugin.get_version()}")
    click.echo(f"  Description: {plugin.get_description() or '-'}")
    click.echo(f"  Enabled in config: {'yes' if enabled else 'no'}")
    click.echo(f"  Installed now: {'yes' if plugin.is_available() else 'no'}")
    click.echo(f"  Artifact types: {', '.join(plugin.get_supported_artifact_types()) or '-'}")
    click.echo(f"  Requires: {', '.join(plugin.get_required_dependencies()) or '-'}")
    click.echo()


def _report_toggle(plugin_name: str, enabled: bool) -> None:
    """Tell the caller how to switch a plugin on or off.

    The setting lives in config.yaml, which is hand-written and commented, so
    the command points at the edit instead of rewriting the file.
    """
    plugins_config = get_config().list_plugins()
    if plugin_name not in plugins_config:
        click.echo(f"Error: Plugin '{plugin_name}' not found in configuration")
        click.echo(f"Known plugins: {', '.join(sorted(plugins_config))}")
        sys.exit(1)

    current = bool(plugins_config[plugin_name].get("enabled", True))
    word = "enabled" if enabled else "disabled"
    if current == enabled:
        click.echo(f"Plugin '{plugin_name}' is already {word}.")
        return

    click.echo(f"Plugin '{plugin_name}' is currently {'enabled' if current else 'disabled'}.")
    click.echo(
        f"To {'enable' if enabled else 'disable'} it, set plugins.{plugin_name}.enabled: "
        f"{str(enabled).lower()} in config/config.yaml"
    )


@plugins.command()
@click.argument("plugin_name")
def enable(plugin_name: str):
    """Show how to enable a plugin in config.yaml.

    Examples:
        ghost-hunter plugins enable username_search
    """
    _report_toggle(plugin_name, True)


@plugins.command()
@click.argument("plugin_name")
def disable(plugin_name: str):
    """Show how to disable a plugin in config.yaml.

    Examples:
        ghost-hunter plugins disable username_search
    """
    _report_toggle(plugin_name, False)


if __name__ == "__main__":
    cli()

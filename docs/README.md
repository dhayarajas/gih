# Documentation Index

Documentation for Ghost Identity Hunter, an OSINT investigation tool that expands seed identity artifacts into correlated identity profiles.

## Table of Contents

- [Design Documentation](#design-documentation)
- [Development](#development)
- [Tooling and Comparison](#tooling-and-comparison)
- [Deployment and Setup](#deployment-and-setup)
- [Where to Start](#where-to-start)

## Design Documentation

| Document | Contents |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System context, layered overview, overall architecture diagram, per-layer block diagrams, SQLite ER diagram, technology stack, known gaps, source map |
| [FILE_BY_FILE.md](FILE_BY_FILE.md) | Per-file reference: what each source file does, how it works, key APIs, and how files connect in the investigation pipeline |
| [LLD.md](LLD.md) | Low-level design per subsystem: orchestrator, OSINT modules, plugin system, external tools, correlation, storage, reporting and visualization, analysis, API, collaboration |
| [SEQUENCE_DIAGRAMS.md](SEQUENCE_DIAGRAMS.md) | End-to-end investigation, username path, domain path and report generation sequences |

All diagrams use Mermaid and render directly on GitHub.

## Development

| Document | Contents |
| --- | --- |
| [plugin_development.md](plugin_development.md) | Writing new plugins against the `OSINTPlugin` interface |
| [LOCAL_PYTHON_SETUP.md](LOCAL_PYTHON_SETUP.md) | Local Python environment setup |
| [SQLITE_QUERIES.md](SQLITE_QUERIES.md) | Reading the investigation database directly: where the file is, what each table holds, and the queries worth having (per-run findings, links, tool runtimes and exit statuses, cross-run matches, export, deletion) |

## Tooling and Comparison

| Document | Contents |
| --- | --- |
| [TOOL_INSTALLATION.md](TOOL_INSTALLATION.md) | Every tool and service the project uses, with install and verify commands, API-key behaviour, and the Maltego providers it does not cover ([PDF](TOOL_INSTALLATION.pdf)) |
| [TOOL_COMMANDS.md](TOOL_COMMANDS.md) | The exact argv gih builds for each tool, runnable standalone to cross-reference a report, plus what each writes, its timeout, and the tools deliberately not dispatched and why |
| [MALTEGO_COMPARISON.md](MALTEGO_COMPARISON.md) | Functional comparison against the Maltego platform across 22 capability areas, with a prioritised gap roadmap |
| [MALTEGO_PROVIDER_GAP.md](MALTEGO_PROVIDER_GAP.md) | Maltego's published data providers mapped to this project's coverage: covered, partially covered or absent |

## Deployment and Setup

| Document | Contents |
| --- | --- |
| [VM_DEPLOYMENT_GUIDE.md](VM_DEPLOYMENT_GUIDE.md) | VM deployment |
| [KALI_DOCKER_DEPLOYMENT.md](KALI_DOCKER_DEPLOYMENT.md) | Kali Linux Docker deployment |
| [README.docker.md](README.docker.md) | Docker usage |
| [DOCKER_COMMANDS.txt](DOCKER_COMMANDS.txt) | Docker command reference |
| [NEO4J_SETUP_GUIDE.md](NEO4J_SETUP_GUIDE.md) | Optional Neo4j graph backend |

## Where to Start

1. Read [ARCHITECTURE.md](ARCHITECTURE.md) for the layer map and data model.
2. Read [SEQUENCE_DIAGRAMS.md](SEQUENCE_DIAGRAMS.md) to follow one investigation end to end.
3. Use [FILE_BY_FILE.md](FILE_BY_FILE.md) when you need what a specific file does and how it works.
4. Use [LLD.md](LLD.md) for subsystem contracts and known gaps between documented behaviour and current code.

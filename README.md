# Ghost Identity Hunter

An OSINT investigation tool that links fragmented digital identity artifacts (burner phones, disposable emails, stolen profile images, social media accounts) into unified attribution profiles.

## Features

- **Phone OSINT** — Carrier lookup, VoIP/burner detection, line type identification
- **Email OSINT** — Account existence checks, disposable/privacy domain detection, Gravatar, GitHub linkage
- **Username Search** — Check username across 12+ platforms (GitHub, Reddit, Twitter, Instagram, etc.)
- **Image Analysis** — EXIF extraction (camera, GPS, date), file hashing, reverse search link generation
- **Breach Checking** — HaveIBeenPwned integration for credential exposure
- **Identity Correlation** — Graph-based linking using connected components (NetworkX)
- **Confidence Scoring** — Weighted scoring based on link types, data freshness, source reliability
- **Risk Assessment** — Composite risk scoring from accumulated indicators
- **Interactive Visualization** — pyvis-powered HTML graphs showing entity relationships
- **Report Generation** — HTML and JSON reports with identity profiles, platform matrix, evidence chain

## Installation

```bash
git clone https://github.com/dhayarajas/gih.git
cd gih
pip install -e ".[dev]"
```

## Usage

### Start an Investigation

```bash
# Investigate a phone number
ghost-hunter investigate --phone "+1-555-0123"

# Investigate an email
ghost-hunter investigate --email "suspect@example.com"

# Multiple seeds
ghost-hunter investigate -p "+1-555-0123" -e "suspect@example.com" -u "john_doe"

# Investigate a profile image
ghost-hunter investigate --image "/path/to/profile.jpg"

# Skip network-dependent checks
ghost-hunter investigate -e "test@example.com" --no-breach --no-username-search
```

### Generate Reports

```bash
# HTML report
ghost-hunter report --id INV-abc123

# JSON report
ghost-hunter report --id INV-abc123 --format json

# Both formats
ghost-hunter report --id INV-abc123 --format both
```

### Visualize Identity Graph

```bash
ghost-hunter graph --id INV-abc123
```

### List Investigations

```bash
ghost-hunter list
```

### Run Correlation Analysis

```bash
ghost-hunter correlate --id INV-abc123
```

## Architecture

```
Input (phone/email/username/image)
    │
    ▼
Investigation Orchestrator (BFS, depth-limited)
    │
    ├── Phone OSINT Module (phonenumbers library)
    ├── Email OSINT Module (Gravatar, GitHub, HIBP)
    ├── Username Search Module (12+ platforms)
    ├── Image Search Module (EXIF, hashing)
    └── Breach Check Module (HaveIBeenPwned)
    │
    ▼
Identity Correlator (NetworkX connected components)
    │
    ▼
Report Generator (HTML/JSON) + Graph Visualizer (pyvis)
```

## Running Tests

```bash
pytest tests/ -v
```

## Infrastructure

- **Hardware**: Standard laptop (4GB RAM)
- **Cloud**: None required
- **Cost**: $0

## Legal & Ethical Considerations

- Only queries publicly available data — no unauthorized access
- OSINT only — does not perform active exploitation
- Respects API rate limits
- Investigations stored locally, user manages lifecycle

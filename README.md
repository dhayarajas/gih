# Ghost Identity Hunter

An OSINT investigation tool that links fragmented digital identity artifacts (burner phones, disposable emails, stolen profile images, social media accounts) into unified attribution profiles.

## Features

### **Core Investigation Capabilities**
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

### **External OSINT Tools Integration**
- **25+ Pre-integrated Tools** — Sherlock, theHarvester, Shodan, Amass, Nmap, Whois, Dig, ExifTool, Wayback Machine, and more
- **Automatic Tool Detection** — Checks tool availability and gracefully skips missing tools
- **Comprehensive Coverage** — Username search, email harvesting, domain enumeration, network scanning, metadata extraction
- **VM/Docker Ready** — Optimized for Kali Linux VM and Docker container deployment
- **Unified Pipeline** — All tool outputs integrated into investigation workflow

## Installation

### **Standard Installation**
```bash
git clone https://github.com/dhayarajas/gih.git
cd gih
pip install -e ".[dev]"
```

### **Docker Installation (Recommended)**
```bash
# Clone repository
git clone https://github.com/dhayarajas/gih.git
cd gih

# Build and start container
docker-compose up --build

# Or use Kali Linux base image
docker-compose -f docker-compose.kali.yml build
docker-compose -f docker-compose.kali.yml up -d
```

### **Kali Linux VM Deployment**
See [KALI_DOCKER_DEPLOYMENT.md](KALI_DOCKER_DEPLOYMENT.md) for detailed Kali Linux Docker deployment instructions.

## Usage

### **Start an Investigation**

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

# Use external OSINT tools (if available)
ghost-hunter investigate --email "target@example.com" --use-external-tools --verbose
```

### **Check Available External Tools**
```bash
# Check which OSINT tools are installed and available
ghost-hunter investigate --check-tools
```

### **Generate Reports**

```bash
# HTML report
ghost-hunter report --id INV-abc123

# JSON report
ghost-hunter report --id INV-abc123 --format json

# Both formats
ghost-hunter report --id INV-abc123 --format both
```

### **Visualize Identity Graph**

```bash
ghost-hunter graph --id INV-abc123
```

### **List Investigations**

```bash
ghost-hunter list
```

### **Run Correlation Analysis**

```bash
ghost-hunter correlate --id INV-abc123
```

## External OSINT Tools

### **Integrated Tools**
The system automatically detects and uses the following tools when available:

#### **Username Search**
- **Sherlock** — Find usernames across 300+ social networks
- **Maigret** — Username search across multiple platforms
- **Social Analyzer** — Social media username analysis

#### **Email Investigation**
- **Holehe** — Email investigation and account discovery
- **EmailHarvester** — Email harvesting from domains
- **theHarvester** — Email, subdomain and people harvesting

#### **Domain & DNS**
- **Whois** — Domain and IP ownership information
- **Dig** — DNS lookup utility
- **Amass** — Attack surface discovery and enumeration
- **Subfinder** — Fast subdomain enumeration
- **Sublist3r** — Fast subdomains enumeration tool

#### **Network Scanning**
- **Nmap** — Network mapper and security scanner
- **Masscan** — Mass IP port scanner
- **WhatWeb** — Web technology identification
- **Wappalyzer** — Web technology detection

#### **OSINT Frameworks**
- **Recon-ng** — Web reconnaissance framework
- **SpiderFoot** — Open source intelligence automation
- **OSRFramework** — Open Sources Research Framework

#### **Specialized Tools**
- **Shodan** — Search engine for Internet-connected devices
- **GHunt** — Google account investigation tool
- **Photon** — Web crawler for OSINT
- **Metagoofil** — Metadata extraction from documents

#### **Image & Metadata**
- **ExifTool** — Read and write file metadata

#### **Historical Data**
- **Wayback Machine** — Historical web data access

#### **Blockchain & Geolocation**
- **Etherscan** — Blockchain investigation tool
- **GeoNames** — Geographical database and search

### **Tool Availability**
The system gracefully handles missing tools:
- Investigations continue even if tools are not installed
- Detailed logging of available/missing tools
- No failures due to missing dependencies
- Use `--check-tools` to verify tool availability

## Deployment Options

### **Local Installation**
Standard Python installation for development and testing.

### **Docker Deployment**
Containerized deployment for consistent environments:
- **Standard Docker**: Use `docker-compose.yml` for basic deployment
- **Kali Linux Docker**: Use `docker-compose.kali.yml` for full OSINT tool suite

### **Kali Linux VM**
Dedicated VM deployment with all OSINT tools:
- See [VM_DEPLOYMENT_GUIDE.md](VM_DEPLOYMENT_GUIDE.md) for VM setup
- See [KALI_DOCKER_DEPLOYMENT.md](KALI_DOCKER_DEPLOYMENT.md) for Docker on Kali

## Architecture

```
Input (phone/email/username/image)
    │
    ▼
Investigation Orchestrator (BFS, depth-limited)
    │
    ├── Built-in Modules
    │   ├── Phone OSINT Module (phonenumbers library)
    │   ├── Email OSINT Module (Gravatar, GitHub, HIBP)
    │   ├── Username Search Module (12+ platforms)
    │   ├── Image Search Module (EXIF, hashing)
    │   └── Breach Check Module (HaveIBeenPwned)
    │
    ├── External OSINT Tools (if available)
    │   ├── Sherlock (username search)
    │   ├── theHarvester (email/subdomain harvesting)
    │   ├── Shodan (host information)
    │   ├── Amass (subdomain enumeration)
    │   ├── Whois (domain lookup)
    │   ├── Dig (DNS records)
    │   ├── Nmap (network scanning)
    │   ├── ExifTool (metadata extraction)
    │   └── Wayback Machine (historical data)
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

- **Hardware**: Standard laptop (4GB RAM) or VM (8GB RAM recommended)
- **Cloud**: None required
- **Cost**: $0
- **Docker**: Optional but recommended for consistent deployment

## Documentation

- [README.md](README.md) — Main documentation
- [VM_DEPLOYMENT_GUIDE.md](VM_DEPLOYMENT_GUIDE.md) — VM deployment instructions
- [KALI_DOCKER_DEPLOYMENT.md](KALI_DOCKER_DEPLOYMENT.md) — Kali Linux Docker deployment
- [DOCKER_SETUP_GUIDE.html](DOCKER_SETUP_GUIDE.html) — Docker setup guide
- [README.docker.md](README.docker.md) — Docker-specific documentation

## Legal & Ethical Considerations

- Only queries publicly available data — no unauthorized access
- OSINT only — does not perform active exploitation
- Respects API rate limits
- Investigations stored locally, user manages lifecycle
- External tools used responsibly and legally

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests to the main repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Citation

If you use this tool in your research, please cite:

```
Ghost Identity Hunter - OSINT Investigation Tool
https://github.com/dhayarajas/gih
```

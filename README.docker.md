# Ghost Identity Hunter - Docker Deployment

## Quick Start

### Prerequisites
- Docker Desktop installed and running
- Docker Compose (included with Docker Desktop)

### Build and Run

#### Option 1: Standard Docker Compose (Recommended)
```bash
# Clone and navigate to the project
git clone https://github.com/dhayarajas/gih.git
cd gih

# Build and start the container
docker-compose up --build

# Run in detached mode
docker-compose up -d --build
```

#### Option 2: Kali Linux Docker (Full OSINT Suite)
```bash
# Clone and navigate to the project
git clone https://github.com/dhayarajas/gih.git
cd gih

# Build Kali Linux image with full OSINT tool suite
docker-compose -f docker-compose.kali.yml build

# Start container
docker-compose -f docker-compose.kali.yml up -d

# See KALI_DOCKER_DEPLOYMENT.md for detailed instructions
```

#### Option 3: Using Docker directly
```bash
# Build the image
docker build -t ghost-identity-hunter:latest .

# Run the container
docker run -it --rm \
  -v ghost_hunter_data:/home/ghosthunter/.ghost_hunter \
  -v $(pwd)/investigations:/app/investigations \
  ghost-identity-hunter:latest
```

## Usage

### Running Investigations
```bash
# Using docker-compose
docker-compose exec ghost-hunter python -m src.cli investigate \
  --phone "+1234567890" \
  --email "user@example.com" \
  --username "target_user"

# Using docker run
docker run -it --rm \
  -v ghost_hunter_data:/home/ghosthunter/.ghost_hunter \
  -v $(pwd)/investigations:/app/investigations \
  ghost-identity-hunter:latest investigate \
  --phone "+1234567890" \
  --email "user@example.com"

# With external OSINT tools (Kali Docker only)
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate \
  --email "target@example.com" \
  --use-external-tools \
  --verbose
```

### Check Available Tools
```bash
# Check which external OSINT tools are available (Kali Docker only)
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --check-tools
```

### Listing Investigations
```bash
docker-compose exec ghost-hunter python -m src.cli list
```

### Generating Reports
```bash
docker-compose exec ghost-hunter python -m src.cli report <investigation_id>
```

## External OSINT Tools Integration

### Standard Docker
The standard Docker deployment includes built-in OSINT modules but does not include external tools like Sherlock, Nmap, etc. These tools can be added by customizing the Dockerfile.

### Kali Linux Docker
The Kali Linux Docker deployment includes 25+ pre-installed OSINT tools:
- **Username Search**: Sherlock, Maigret, Social Analyzer
- **Email Investigation**: Holehe, EmailHarvester, theHarvester
- **Domain & DNS**: Whois, Dig, Amass, Subfinder, Sublist3r
- **Network Scanning**: Nmap, Masscan, WhatWeb, Wappalyzer
- **OSINT Frameworks**: Recon-ng, SpiderFoot, OSRFramework
- **Specialized Tools**: Shodan, GHunt, Photon, Metagoofil
- **Image & Metadata**: ExifTool
- **Historical Data**: Wayback Machine
- **Blockchain & Geolocation**: Etherscan, GeoNames

The system automatically detects available tools and gracefully skips any that are not installed.

## Data Persistence

- **Database**: Stored in Docker volume `ghost_hunter_data`
- **Reports**: Mounted to `./investigations` directory
- **Configuration**: Environment variables in `docker-compose.yml`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHONPATH` | `/app` | Python module path |
| `GHOST_HUNTER_DB_PATH` | `/home/ghosthunter/.ghost_hunter/investigations.db` | SQLite database location |

## Development

### Building for Development
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

### Accessing Shell
```bash
docker-compose exec ghost-hunter /bin/bash
```

## Troubleshooting

### Docker Daemon Not Running
1. Start Docker Desktop
2. Verify with `docker version`

### Permission Issues
```bash
# On Linux, add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Volume Issues
```bash
# Remove and recreate volumes
docker-compose down -v
docker-compose up --build
```

## Security Notes

- Container runs as non-root user (`ghosthunter`)
- Database stored in persistent Docker volume
- No exposed ports (CLI-only application)
- Minimal base image (`python:3.11-slim`)

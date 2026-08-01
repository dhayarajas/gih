# Ghost Identity Hunter - Kali Linux Docker Deployment

## Overview
This guide provides step-by-step instructions for deploying Ghost Identity Hunter as a Docker container in Kali Linux, leveraging Kali's pre-installed OSINT tools and the containerized environment for isolated investigations.

## Pre-Installed OSINT Tools

The Kali Linux Docker image includes the following 25+ OSINT tools:

### **Username Search Tools**
- **Sherlock** — Find usernames across 300+ social networks
- **Maigret** — Username search across multiple platforms
- **Social Analyzer** — Social media username analysis

### **Email Investigation Tools**
- **Holehe** — Email investigation and account discovery
- **EmailHarvester** — Email harvesting from domains
- **theHarvester** — Email, subdomain and people harvesting

### **Domain & DNS Tools**
- **Whois** — Domain and IP ownership information
- **Dig** — DNS lookup utility
- **Amass** — Attack surface discovery and enumeration
- **Subfinder** — Fast subdomain enumeration
- **Sublist3r** — Fast subdomains enumeration tool
- **Dnsenum** — DNS enumeration tool
- **Dnsrecon** — DNS reconnaissance tool
- **Fierce** — DNS reconnaissance tool

### **Network Scanning Tools**
- **Nmap** — Network mapper and security scanner
- **Masscan** — Mass IP port scanner
- **WhatWeb** — Web technology identification
- **Wappalyzer** — Web technology detection
- **Nikto** — Web server scanner
- **Sqlmap** — SQL injection tool

### **OSINT Frameworks**
- **Recon-ng** — Web reconnaissance framework
- **SpiderFoot** — Open source intelligence automation
- **OSRFramework** — Open Sources Research Framework

### **Specialized Tools**
- **Shodan** — Search engine for Internet-connected devices
- **GHunt** — Google account investigation tool
- **Photon** — Web crawler for OSINT
- **Metagoofil** — Metadata extraction from documents

### **Image & Metadata Tools**
- **ExifTool** — Read and write file metadata

### **Historical Data**
- **Wayback Machine** — Historical web data access (CLI tool)

### **Blockchain & Geolocation**
- **Etherscan** — Blockchain investigation tool
- **GeoNames** — Geographical database and search (via geopy)

### **Web Tools**
- **Gobuster** — Directory brute-forcing tool
- **Dirsearch** — Web path scanner
- **Wfuzz** — Web application fuzzer

### **Additional Utilities**
- **Neo4j** — Graph database for advanced correlation analysis
- **NetworkX** — Graph library for correlation (fallback)
- **Pyvis** — Interactive graph visualization

## Prerequisites

### **System Requirements**
- **OS**: Kali Linux 2023.x or later
- **Docker**: 20.10+ installed and running
- **Docker Compose**: 2.0+ installed
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 20GB minimum for container and data
- **Network**: Stable internet connection

### **Verify Docker Installation**
```bash
# Check Docker version
docker --version

# Check Docker Compose version
docker-compose --version

# Verify Docker is running
docker ps
```

## Quick Start (5 Minutes)

### **Step 1: Clone Repository**
```bash
# Clone the Ghost Identity Hunter repository
git clone https://github.com/dhayarajas/gih.git
cd gih
```

### **Step 2: Build Docker Image**
```bash
# Build the Kali Linux Docker image
docker-compose -f docker-compose.kali.yml build
```

### **Step 3: Start Container**
```bash
# Start the container in detached mode
docker-compose -f docker-compose.kali.yml up -d

# Or run interactively
docker-compose -f docker-compose.kali.yml up
```

### **Step 4: Check Tool Availability**
```bash
# Enter the container
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali bash

# Check available OSINT tools
python -m src.cli investigate --check-tools

# Exit container
exit
```

### **Step 5: Run Investigation**
```bash
# Run investigation from host
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --email "target@example.com" --verbose
```

## Detailed Deployment Steps

### **Step 1: Prepare Kali Linux Environment**

#### **Update System**
```bash
# Update Kali Linux packages
sudo apt update && sudo apt upgrade -y

# Install Docker if not already installed
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group
sudo usermod -aG docker $USER

# Log out and back in for group changes to take effect
# Or use: newgrp docker
```

#### **Verify Docker Installation**
```bash
# Test Docker installation
docker run --rm hello-world

# Check Docker Compose
docker-compose --version
```

### **Step 2: Clone and Prepare Repository**

```bash
# Clone repository
git clone https://github.com/dhayarajas/gih.git
cd gih

# Verify files exist
ls -la Dockerfile.kali docker-compose.kali.yml
```

### **Step 3: Build Docker Image**

```bash
# Build with Docker Compose (recommended)
docker-compose -f docker-compose.kali.yml build

# Or build with Docker directly
docker build -f Dockerfile.kali -t ghost-identity-hunter:kalilinux .
```

**Build Process Details:**
- Downloads Kali Linux base image
- Installs system dependencies and OSINT tools
- Installs Python packages for OSINT tools
- Installs Ghost Identity Hunter dependencies
- Creates non-root user for security
- Sets up persistent data volumes

**Build Time:** 15-30 minutes depending on internet speed

### **Step 4: Configure Docker Compose**

#### **Review Configuration**
```bash
# View docker-compose configuration
cat docker-compose.kali.yml
```

#### **Customize Resources (Optional)**
```yaml
# Edit docker-compose.kali.yml to adjust resource limits
deploy:
  resources:
    limits:
      cpus: '4'        # Increase for better performance
      memory: 8G       # Increase for memory-intensive tools
```

#### **Customize Volume Paths (Optional)**
```yaml
# Edit volume mounts to use your preferred paths
volumes:
  - /path/to/your/data:/home/ghosthunter/.ghost_hunter
  - /path/to/your/investigations:/app/investigations
  - /path/to/your/reports:/app/reports
```

### **Step 5: Start Container**

#### **Start in Detached Mode**
```bash
# Start container in background
docker-compose -f docker-compose.kali.yml up -d

# Check container status
docker-compose -f docker-compose.kali.yml ps

# View container logs
docker-compose -f docker-compose.kali.yml logs -f
```

#### **Start Interactively**
```bash
# Start with interactive shell
docker-compose -f docker-compose.kali.yml up

# This will show logs and allow you to stop with Ctrl+C
```

### **Step 6: Access Container**

#### **Enter Running Container**
```bash
# Enter container shell
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali bash

# Or use docker directly
docker exec -it ghost-hunter-kali bash
```

#### **Verify Environment**
```bash
# Check Python version
python3 --version

# Check Ghost Identity Hunter installation
python -m src.cli --help

# Check tool availability
python -m src.cli investigate --check-tools
```

## Running Investigations

### **Basic Investigation**
```bash
# From host machine
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --email "target@example.com"

# From inside container
python -m src.cli investigate --email "target@example.com"
```

### **Multi-Artifact Investigation**
```bash
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate \
  --email "target@example.com" \
  --phone "+1234567890" \
  --username "target_user" \
  --verbose
```

### **With External OSINT Tools**
```bash
# External tools enabled by default
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate \
  --email "target@example.com" \
  --use-external-tools \
  --verbose
```

### **Domain Investigation**
```bash
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate \
  --username "target" \
  --use-external-tools \
  --verbose
```

## Container Management

### **Start/Stop/Restart**
```bash
# Start container
docker-compose -f docker-compose.kali.yml start

# Stop container
docker-compose -f docker-compose.kali.yml stop

# Restart container
docker-compose -f docker-compose.kali.yml restart

# Stop and remove containers
docker-compose -f docker-compose.kali.yml down
```

### **View Logs**
```bash
# View all logs
docker-compose -f docker-compose.kali.yml logs

# Follow logs in real-time
docker-compose -f docker-compose.kali.yml logs -f

# View specific service logs
docker-compose -f docker-compose.kali.yml logs ghost-hunter-kali
```

### **Container Status**
```bash
# Check container status
docker-compose -f docker-compose.kali.yml ps

# View container details
docker inspect ghost-hunter-kali

# View resource usage
docker stats ghost-hunter-kali
```

### **Access Shell**
```bash
# Enter container shell
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali bash

# Run single command
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali python -m src.cli list
```

## Data Management

### **Persistent Volumes**
```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect gih_ghost_hunter_data

# Backup volume
docker run --rm -v gih_ghost_hunter_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/ghost_hunter_data_backup.tar.gz /data

# Restore volume
docker run --rm -v gih_ghost_hunter_data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/ghost_hunter_data_backup.tar.gz -C /
```

### **Investigation Data**
```bash
# Investigation data is stored in mounted volumes
# On host: ./investigations/
# In container: /app/investigations/

# View investigations from host
ls -la investigations/

# Copy investigations from container
docker cp ghost-hunter-kali:/app/investigations ./local_investigations
```

### **Report Generation**
```bash
# Reports are stored in ./reports/ on host
ls -la reports/

# Generate report for specific investigation
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli report --id INV-XXXXXXXX --format both
```

## Troubleshooting

### **Build Issues**
```bash
# Clear Docker cache and rebuild
docker system prune -a
docker-compose -f docker-compose.kali.yml build --no-cache
```

### **Container Won't Start**
```bash
# Check container logs
docker-compose -f docker-compose.kali.yml logs

# Check for port conflicts
docker-compose -f docker-compose.kali.yml config

# Remove and recreate container
docker-compose -f docker-compose.kali.yml down
docker-compose -f docker-compose.kali.yml up -d
```

### **Permission Issues**
```bash
# Fix volume permissions
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  chown -R ghosthunter:ghosthunter /home/ghosthunter/.ghost_hunter

# Fix host directory permissions
sudo chown -R $USER:$USER investigations reports
```

### **Tool Not Found**
```bash
# Enter container and check tool
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali bash
which sherlock
which nmap

# Rebuild container if tools missing
docker-compose -f docker-compose.kali.yml down
docker-compose -f docker-compose.kali.yml build --no-cache
docker-compose -f docker-compose.kali.yml up -d
```

### **Memory Issues**
```bash
# Increase memory limit in docker-compose.kali.yml
# Then restart container
docker-compose -f docker-compose.kali.yml down
docker-compose -f docker-compose.kali.yml up -d

# Or run with increased limits
docker-compose -f docker-compose.kali.yml up -d --scale ghost-hunter-kali=1
```

## Advanced Configuration

### **Custom Tool Installation**
```bash
# Enter container
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali bash

# Install additional tools
sudo apt update
sudo apt install -y additional-tool

# Install Python tools
pip3 install additional-python-tool

# Exit and commit changes to image
exit
docker commit ghost-hunter-kali ghost-identity-hunter:custom
```

### **API Key Configuration**
```bash
# Create config directory
mkdir -p config

# Add API keys to config file
cat > config/api_keys.conf << EOF
SHODAN_API_KEY=your_shodan_api_key
HIBP_API_KEY=your_hibp_api_key
EOF

# Mount config in docker-compose.kali.yml
volumes:
  - ./config:/app/config:ro
```

### **Network Configuration**
```bash
# Add custom network in docker-compose.kali.yml
networks:
  ghost_hunter_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### **Proxy Configuration**
```bash
# Add proxy environment variables
environment:
  - HTTP_PROXY=http://proxy-server:port
  - HTTPS_PROXY=http://proxy-server:port
  - NO_PROXY=localhost,127.0.0.1
```

## Performance Optimization

### **Resource Allocation**
```yaml
# Optimize for performance in docker-compose.kali.yml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 8G
    reservations:
      cpus: '2'
      memory: 4G
```

### **Parallel Investigations**
```bash
# Run multiple investigations in parallel
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --email "target1@example.com" &

docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --email "target2@example.com" &

wait
```

### **Cache Optimization**
```bash
# Use Docker build cache for faster rebuilds
docker-compose -f docker-compose.kali.yml build

# Clear cache only when needed
docker-compose -f docker-compose.kali.yml build --no-cache
```

## Security Considerations

### **Container Isolation**
```yaml
# Enable security options in docker-compose.kali.yml
security_opt:
  - no-new-privileges:true
  - apparmor:docker-default
```

### **Read-Only Filesystem**
```yaml
# Enable read-only root filesystem
read_only: true
tmpfs:
  - /tmp
  - /home/ghosthunter/.ghost_hunter
```

### **User Privileges**
```bash
# Container runs as non-root user 'ghosthunter'
# Verify user inside container
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali whoami
```

### **Network Security**
```bash
# Use custom network for isolation
docker network create ghost_hunter_isolated

# Update docker-compose.kali.yml to use custom network
networks:
  ghost_hunter_isolated:
    external: true
```

## Maintenance

### **Update Container**
```bash
# Pull latest changes
git pull origin main

# Rebuild container
docker-compose -f docker-compose.kali.yml down
docker-compose -f docker-compose.kali.yml build
docker-compose -f docker-compose.kali.yml up -d
```

### **Clean Up**
```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Complete cleanup
docker system prune -a
```

### **Backup Strategy**
```bash
# Backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  tar czf /tmp/backup_$DATE.tar.gz /home/ghosthunter/.ghost_hunter /app/investigations
docker cp ghost-hunter-kali:/tmp/backup_$DATE.tar.gz ./backups/
```

## Usage Examples

### **Daily Investigation Workflow**
```bash
# Start container
docker-compose -f docker-compose.kali.yml up -d

# Check tool availability
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --check-tools

# Run investigation
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli investigate --email "target@example.com" --auto-report

# View results
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli list

# Generate reports
docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
  python -m src.cli report --id INV-XXXXXXXX --format both

# Stop container
docker-compose -f docker-compose.kali.yml down
```

### **Batch Processing**
```bash
# Process multiple targets
for email in target1@example.com target2@example.com target3@example.com; do
  docker-compose -f docker-compose.kali.yml exec ghost-hunter-kali \
    python -m src.cli investigate --email "$email" --auto-report
done
```

## Next Steps

1. **Deploy**: Follow the steps above to deploy in Kali Linux
2. **Verify**: Check tool availability with `--check-tools`
3. **Test**: Run test investigations to validate functionality
4. **Configure**: Customize based on your specific requirements
5. **Automate**: Set up scheduled investigations if needed

The Docker deployment provides a clean, isolated environment with all OSINT tools pre-installed, ensuring consistent and reproducible investigations.

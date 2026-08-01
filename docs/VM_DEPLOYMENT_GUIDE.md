# Ghost Identity Hunter - VM Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying Ghost Identity Hunter in a dedicated virtual machine environment with all OSINT tools installed for comprehensive digital identity investigations.

## Why Use a Dedicated VM?

### **Security Benefits**
- **Isolation**: Separate investigation environment from your main system
- **Containment**: Prevents potential malware spread from OSINT activities
- **Privacy**: Keeps investigation data isolated from personal/work systems
- **Anonymity**: Can be configured with VPN/proxy for enhanced privacy

### **Operational Benefits**
- **Tool Availability**: All OSINT tools pre-installed and configured
- **Consistency**: Reproducible investigation environment
- **Resource Management**: Dedicated resources for intensive investigations
- **Backup**: Easy to snapshot and restore VM states

### **Docker Alternative**
For maximum portability and ease of deployment, consider using Docker containers:
- **Standard Docker**: Basic deployment with core tools
- **Kali Linux Docker**: Full OSINT tool suite in container
- See [KALI_DOCKER_DEPLOYMENT.md](KALI_DOCKER_DEPLOYMENT.md) for Docker deployment

## VM Requirements

### **Hardware Requirements**
- **CPU**: 4+ cores recommended (for parallel OSINT operations)
- **RAM**: 8GB minimum, 16GB recommended (for memory-intensive tools)
- **Storage**: 100GB minimum (for tool installations and investigation data)
- **Network**: Stable internet connection (for API calls and web scraping)

### **Software Requirements**
- **OS**: Ubuntu 22.04 LTS or Kali Linux 2023.x recommended
- **Python**: 3.10+ (Ghost Identity Hunter requires Python 3.10+)
- **Docker**: Optional, but recommended for containerization

## VM Setup Options

### **Option 1: Kali Linux (Recommended)**
Kali Linux comes pre-installed with most OSINT tools and is optimized for security research.

```bash
# Download Kali Linux VM image
wget https://cdimage.kali.org/kali-2023.4/kali-linux-2023.4-vmware-amd64.7z

# Extract and import into your hypervisor (VMware/VirtualBox)
# Follow your hypervisor's import instructions
```

### **Option 2: Ubuntu 22.04 + Manual Tool Installation**
Clean Ubuntu installation with manual OSINT tool installation.

```bash
# Download Ubuntu 22.04 LTS Server ISO
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso

# Create VM with your hypervisor
# Install Ubuntu with standard configuration
```

### **Option 3: Docker-Based Deployment (Recommended)**
Use Docker containers for maximum portability and reproducibility.

#### **Standard Docker Deployment**
```bash
# Use existing Docker setup
docker-compose up --build
```

#### **Kali Linux Docker Deployment**
```bash
# Use Kali Linux base image with full OSINT tool suite
docker-compose -f docker-compose.kali.yml build
docker-compose -f docker-compose.kali.yml up -d

# See KALI_DOCKER_DEPLOYMENT.md for detailed instructions
```

**Benefits of Docker Deployment:**
- Pre-configured environment with all dependencies
- Isolated investigation environment
- Easy deployment and scaling
- Consistent results across systems
- Simple backup and restore

## OSINT Tools Installation

### **Core Network Tools**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install basic network tools
sudo apt install -y nmap curl wget whois dnsutils netcat-openbsd

# Install advanced network tools
sudo apt install -y masscan nikto sqlmap
```

### **DNS and Domain Tools**
```bash
# Install DNS tools
sudo apt install -y dnsenum dnsrecon fierce subfinder

# Install subdomain enumeration tools
sudo apt install -y sublist3r amass

# Install from GitHub if not in repos
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip3 install -r requirements.txt
```

### **OSINT Frameworks**
```bash
# Install theHarvester
sudo apt install -y theharvester

# Install Sherlock (username search)
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
sudo pip3 install -r requirements.txt
sudo pip3 install sherlock

# Install Recon-ng
sudo apt install -y recon-ng

# Install Maltego (requires separate download)
wget https://www.maltego.com/downloads/Maltego-ce-latest.deb
sudo dpkg -i Maltego-ce-latest.deb
```

### **API and Cloud Tools**
```bash
# Install Shodan CLI
pip3 install shodan

# Configure Shodan API key
shodan init YOUR_API_KEY

# Install cloud enumeration tools
sudo apt install -y cloudenum enum4linux
```

### **Web Scraping and Analysis**
```bash
# Install web scraping tools
sudo apt install -y python3-requests python3-beautifulsoup4
sudo apt install -y python3-selenium chromium-browser

# Install additional scraping tools
sudo apt install -y gobuster dirsearch wfuzz
```

## Ghost Identity Hunter Installation

### **Clone Repository**
```bash
# Clone the repository
git clone https://github.com/dhayarajas/gih.git
cd gih

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .
```

### **Configure Tool Checker**
The tool checker will automatically detect which OSINT tools are installed in your VM.

```python
# Test tool availability
python3 -c "
from src.utils.tool_checker import get_tool_checker
tool_checker = get_tool_checker()
tool_checker.check_all_tools()
tool_checker.print_status()
"
```

### **Verify Installation**
```bash
# Test basic functionality
python -m src.cli --help

# Run test investigation
python -m src.cli investigate --email "test@example.com" --title "VM Test"
```

## VM Configuration

### **Network Configuration**
```bash
# Configure static IP if needed
sudo nano /etc/netplan/00-installer-config.yaml

# Apply network configuration
sudo netplan apply

# Test network connectivity
ping -c 4 google.com
```

### **VPN Configuration (Optional)**
```bash
# Install OpenVPN
sudo apt install -y openvpn

# Connect to VPN
sudo openvpn --config /path/to/vpn-config.ovpn

# Verify VPN connection
curl ifconfig.me
```

### **Proxy Configuration (Optional)**
```bash
# Set environment variables for proxy
export HTTP_PROXY=http://proxy-server:port
export HTTPS_PROXY=http://proxy-server:port

# Configure for Ghost Identity Hunter
export GHOST_HUNTER_PROXY=http://proxy-server:port
```

## Investigation Workflow

### **1. Prepare VM Environment**
```bash
# Start VM and login
# Activate virtual environment
cd /path/to/gih
source venv/bin/activate

# Check tool availability
python3 -c "
from src.utils.tool_checker import get_tool_checker
tool_checker = get_tool_checker()
available = tool_checker.get_available_tools()
print(f'Available tools: {len(available)}')
"
```

### **2. Run Investigation**
```bash
# Basic investigation
python -m src.cli investigate --email "target@example.com" --verbose

# Multi-artifact investigation
python -m src.cli investigate \
  --email "target@example.com" \
  --phone "+1234567890" \
  --username "target_user" \
  --verbose

# Deep investigation with external tools
python -m src.cli investigate \
  --email "target@example.com" \
  --depth 3 \
  --check-external-tools \
  --verbose
```

### **3. Review Results**
```bash
# List investigations
python -m src.cli list

# Generate reports
python -m src.cli report --id INV-XXXXXXXX --format both

# View identity graph
python -m src.cli graph --id INV-XXXXXXXX
```

### **4. Export Results**
```bash
# Copy investigation data from VM
scp user@vm-ip:/path/to/gih/investigations/* ./local-backup/

# Or use shared folder if configured
# Copy reports to shared folder
cp INV-XXXXXXXX_report.* /mnt/shared/
```

## VM Maintenance

### **Regular Updates**
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update OSINT tools
# Update individual tools or use package manager

# Update Ghost Identity Hunter
cd /path/to/gih
git pull origin main
pip install -e .
```

### **Backup Strategy**
```bash
# Create VM snapshot before major investigations
# Use your hypervisor's snapshot feature

# Backup investigation data
tar -czf investigations-backup-$(date +%Y%m%d).tar.gz investigations/

# Backup configuration
tar -czf config-backup-$(date +%Y%m%d).tar.gz .config/
```

### **Performance Optimization**
```bash
# Monitor system resources
htop

# Clean up old investigation data
find investigations/ -name "*.db" -mtime +30 -delete

# Clear Python cache
find . -type d -name "__pycache__" -exec rm -rf {} +
```

## Troubleshooting

### **Tool Not Found Errors**
```bash
# Check if tool is installed
which toolname

# Install missing tool
sudo apt install toolname

# Or install from source
git clone https://github.com/tool/repo.git
cd repo
sudo python3 setup.py install
```

### **Permission Issues**
```bash
# Add user to necessary groups
sudo usermod -aG docker $USER
sudo usermod -aG wireshark $USER

# Reboot for group changes to take effect
sudo reboot
```

### **Network Issues**
```bash
# Test DNS resolution
nslookup google.com

# Test connectivity
ping -c 4 8.8.8.8

# Check firewall rules
sudo ufw status
```

### **Python Environment Issues**
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Security Considerations

### **VM Isolation**
- Keep VM isolated from host network when possible
- Use dedicated network adapter for investigations
- Disable shared folders when not needed
- Regularly update VM OS and tools

### **Data Protection**
- Encrypt investigation data at rest
- Use secure deletion for sensitive data
- Regularly backup investigation results
- Follow data retention policies

### **Operational Security**
- Use VPN for investigations when appropriate
- Rotate API keys regularly
- Monitor for unusual VM activity
- Document investigation purposes and scope

## Advanced Configuration

### **Custom Tool Integration**
When you have the OSINT tool list from your PDF, you can integrate custom tools:

```python
# Add custom tool to tool checker
from src.utils.tool_checker import ToolInfo

custom_tool = ToolInfo(
    name="custom_osint_tool",
    command="custom_tool",
    description="Custom OSINT tool from PDF"
)
tool_checker.tools["custom_osint_tool"] = custom_tool
```

### **Parallel Processing**
```bash
# Run multiple investigations in parallel
python -m src.cli investigate --email "target1@example.com" &
python -m src.cli investigate --email "target2@example.com" &
python -m src.cli investigate --email "target3@example.com" &
wait
```

### **Scheduled Investigations**
```bash
# Add to crontab for scheduled investigations
crontab -e

# Add daily investigation at 2 AM
0 2 * * * cd /path/to/gih && source venv/bin/activate && python -m src.cli investigate --email "target@example.com"
```

## Performance Tips

### **Resource Allocation**
- Allocate sufficient RAM for memory-intensive tools
- Use multiple CPU cores for parallel processing
- Ensure sufficient disk space for investigation data
- Monitor resource usage during investigations

### **Tool Optimization**
- Configure tools for optimal performance
- Use appropriate timeout settings
- Limit concurrent API calls to avoid rate limiting
- Cache results when appropriate

## Next Steps

1. **Set up VM** using one of the recommended options
2. **Install OSINT tools** from your PDF list
3. **Deploy Ghost Identity Hunter** in the VM
4. **Test tool availability** using the tool checker
5. **Run test investigations** to verify functionality
6. **Provide tool list** from PDF for custom integration

The tool availability checker will automatically detect which tools are installed in your VM and gracefully handle any missing tools, ensuring investigations can proceed even if some tools are unavailable.

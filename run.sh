#!/bin/bash
# Ghost Identity Hunter - Standalone Run Script (Linux/Mac)
# This script provides an easy way to run Ghost Identity Hunter

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Creating one...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created.${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source venv/bin/activate

# Check if dependencies are installed
if ! python -c "import click" 2>/dev/null; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -e ".[dev]"
    echo -e "${GREEN}Dependencies installed.${NC}"
fi

# Run the CLI with provided arguments
echo -e "${BLUE}Running Ghost Identity Hunter...${NC}"
python -m src.cli "$@"

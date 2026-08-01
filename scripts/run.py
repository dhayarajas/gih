#!/usr/bin/env python3
"""
Ghost Identity Hunter - Standalone Run Script

This script provides a simple interface to run Ghost Identity Hunter
without needing to remember Python module commands.

Usage:
    python run.py [command] [options]

Commands:
    investigate    Start a new investigation
    list          List all investigations
    report        Generate reports
    graph         Visualize identity graphs
    correlate     Run correlation analysis
    check-tools   Check available external tools
    help          Show this help message

Examples:
    python run.py investigate --email "target@example.com"
    python run.py investigate -p "+1234567890" -e "target@example.com"
    python run.py list
    python run.py report --id INV-abc123
    python run.py check-tools
"""

import sys
import os
import subprocess
from pathlib import Path

# Add the project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def main():
    """Main entry point for the standalone run script."""
    
    # Check if virtual environment is active
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    
    if not in_venv:
        print("⚠️  Warning: Not running in a virtual environment")
        print("   It's recommended to use a virtual environment for Ghost Identity Hunter")
        print("   Create one with: python -m venv venv")
        print("   Activate it with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)")
        print()
    
    # Check if dependencies are installed
    try:
        import click
        import networkx
        import neo4j
    except ImportError as e:
        print(f"❌ Error: Missing dependencies - {e}")
        print("   Install dependencies with: pip install -e \".[dev]\"")
        sys.exit(1)
    
    # Run the CLI module
    try:
        from src.cli import cli
        cli()
    except Exception as e:
        print(f"❌ Error running Ghost Identity Hunter: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

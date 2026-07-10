@echo off
REM Ghost Identity Hunter - Standalone Run Script (Windows)
REM This script provides an easy way to run Ghost Identity Hunter on Windows

setlocal enabledelayedexpansion

REM Project directory
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check if virtual environment exists
if not exist "venv\" (
    echo [YELLOW]Virtual environment not found. Creating one...[NC]
    python -m venv venv
    echo [GREEN]Virtual environment created.[NC]
)

REM Activate virtual environment
echo [BLUE]Activating virtual environment...[NC]
call venv\Scripts\activate.bat

REM Check if dependencies are installed
python -c "import click" >nul 2>&1
if errorlevel 1 (
    echo [YELLOW]Installing dependencies...[NC]
    pip install -e ".[dev]"
    echo [GREEN]Dependencies installed.[NC]
)

REM Run the CLI with provided arguments
echo [BLUE]Running Ghost Identity Hunter...[NC]
python -m src.cli %*

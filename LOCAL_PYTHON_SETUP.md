# Local Python Setup Documentation

## Problem Description

Your local system had Python installations with broken pip dependencies due to expat library compatibility issues. This prevented:
- Creating virtual environments
- Installing Python packages
- Running Ghost Identity Hunter locally

### Specific Issues Encountered:
- Python 3.14.6: pip was broken with expat library errors
- Python 3.11.15: pip was broken with expat library errors  
- System `python` command was not available
- Multiple Python versions were conflicting

## Solution Implemented

We used **pyenv** to install a clean Python environment and make it available system-wide.

## Step-by-Step Process

### 1. Install pyenv
```bash
brew install pyenv
```
**Purpose**: pyenv is a Python version manager that allows installing multiple Python versions without system conflicts.

### 2. Install Python 3.10.20
```bash
pyenv install 3.10.20
```
**Purpose**: Install a stable Python version with working pip and dependencies.

### 3. Set Local Python Version for Project
```bash
cd /Users/dhaya/CSCD/Capstone/gih
pyenv local 3.10.20
```
**Purpose**: Set Python 3.10.20 as the default for this specific project (creates `.python-version` file).

### 4. Install Project Dependencies
```bash
pyenv exec pip install -r requirements.txt
```
**Purpose**: Install all required Python packages for Ghost Identity Hunter.

### 5. Configure pyenv System-Wide
```bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc
```
**Purpose**: Add pyenv to your shell configuration so it loads automatically in new terminal sessions.

### 6. Set Global Python Version
```bash
pyenv global 3.10.20
```
**Purpose**: Make Python 3.10.20 the default for all projects and system commands.

### 7. Apply Configuration
```bash
source ~/.zshrc
```
**Purpose**: Reload shell configuration to apply pyenv changes immediately.

## Verification Steps

### Check Python Installation
```bash
python --version
# Expected output: Python 3.10.20

python3 --version
# Expected output: Python 3.10.20

which python
# Expected output: /Users/dhaya/.pyenv/shims/python

which python3
# Expected output: /Users/dhaya/.pyenv/shims/python3
```

### Check Ghost Identity Hunter
```bash
cd /Users/dhaya/CSCD/Capstone/gih
python -m src.cli --help
# Expected output: Ghost Identity Hunter CLI help
```

## What Changed on Your System

### Files Modified:
1. **`~/.zshrc`** - Added pyenv configuration lines
2. **`~/.pyenv/versions/3.10.20/`** - Installed Python 3.10.20
3. **`/Users/dhaya/CSCD/Capstone/gih/.python-version`** - Project-specific Python version
4. **`~/.pyenv/version`** - Global Python version setting

### Environment Variables Added:
- `PYENV_ROOT="$HOME/.pyenv"`
- `PATH="$PYENV_ROOT/bin:$PATH"`
- pyenv initialization function

## How pyenv Works

### Architecture:
- **pyenv shims**: Lightweight executables that redirect to the correct Python version
- **Version selection**: Based on `.python-version` files (local) or global settings
- **Clean isolation**: Each Python version is installed separately in `~/.pyenv/versions/`

### Version Priority:
1. **Local**: `.python-version` file in current directory
2. **Global**: `~/.pyenv/version` file
3. **System**: Falls back to system Python if no pyenv version is set

## Managing Python Versions

### List Available Versions
```bash
pyenv versions
```

### Install New Python Version
```bash
pyenv install 3.11.0
```

### Set Global Version
```bash
pyenv global 3.11.0
```

### Set Project-Specific Version
```bash
cd /path/to/project
pyenv local 3.10.20
```

### Uninstall Python Version
```bash
pyenv uninstall 3.11.0
```

## Troubleshooting

### Python Command Not Found
```bash
# Reload shell configuration
source ~/.zshrc

# Or restart your terminal
```

### Wrong Python Version
```bash
# Check current version
pyenv version

# Check which version is being used
python --version

# Reset to desired version
pyenv global 3.10.20
```

### Package Installation Issues
```bash
# Use pyenv to ensure correct Python version
pyenv exec pip install <package>

# Or activate pyenv environment
pyenv shell 3.10.20
pip install <package>
```

## Benefits of This Setup

1. **Clean Environment**: No conflicts with system Python
2. **Version Control**: Easy switching between Python versions
3. **Project Isolation**: Different projects can use different Python versions
4. **System Compatibility**: `python` and `python3` commands work for all programs
5. **Easy Management**: Simple commands to install and manage versions

## For Ghost Identity Hunter

### Running the Application:
```bash
cd /Users/dhaya/CSCD/Capstone/gih

# Using python command
python -m src.cli investigate --email "target@example.com"

# Using python3 command
python3 -m src.cli investigate --email "target@example.com"

# Using pyenv explicitly
pyenv exec python -m src.cli investigate --email "target@example.com"
```

### All commands work identically:
- `python -m src.cli ...`
- `python3 -m src.cli ...`
- `pyenv exec python -m src.cli ...`

## Summary

Your system now has:
- **pyenv** installed and configured
- **Python 3.10.20** as the global default
- **Working pip** for package installation
- **System-wide Python access** via `python` and `python3` commands
- **Ghost Identity Hunter** ready to run locally
- **Google API environment variables** configured in ~/.zshrc

The setup is clean, maintainable, and won't interfere with other programs on your machine.

## Google API Configuration

### Environment Variables Added:
Your `~/.zshrc` now includes:
```bash
export GOOGLE_API_KEY=""
export GOOGLE_CX=""
```

### How to Add Your Credentials:
1. Open your `~/.zshrc` file
2. Find the Google API lines
3. Replace the empty strings with your actual credentials:
```bash
export GOOGLE_API_KEY="your_actual_api_key_here"
export GOOGLE_CX="your_actual_cx_id_here"
```

### Reload Configuration:
```bash
source ~/.zshrc
```

### Usage:
After setting the credentials, you can use Google Dorks without specifying them each time:
```bash
python -m src.cli investigate --username "target_user" --use-google-dorks --use-google-api
```

The CLI will automatically pick up the credentials from your environment variables.

## Additional Resources

- [pyenv GitHub Repository](https://github.com/pyenv/pyenv)
- [pyenv Documentation](https://github.com/pyenv/pyenv#basic-github-checkout)
- [Python Version Management](https://realpython.com/intro-to-pyenv/)

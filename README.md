# 🔍 Refine Vibe Code

A powerful CLI tool that analyzes your codebase for AI-generated code patterns, security vulnerabilities, and code quality issues. Perfect for developers who want to maintain professional code standards.

## 🚀 Installation

### Global Installation
Install `refine` globally as a standalone tool:

#### pipx
```bash
pipx install refine-vibe-code
```

#### With uv
The fastest way to use `refine` is with [uv](https://www.google.com/search?q=https://astral.sh/uv/). If you don't have it yet, install it with one command:
`curl -LsSf https://astral.sh/uv/install.sh | sh`

```bash
uv tool install refine-vibe-code
uv tool update-shell
```

### homebrew
```bash
brew tap CarlosMenke/homebrew-tap
brew install refine-vibe-code
```

### Install from Source

Use this if you want to modify the code or contribute:

```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code

# Setup and run instantly
uv run refine

```

### Traditional Install (pip)

If you prefer standard Python tools:

```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code
pip install .

```

## Configuration Examples

### Config generation
If you run refine for the first time, it will auto generate the config
```bash
# Generate global config
refine
# To use it
refine scan DIR_NAME
```

### LLM Integration (for deeper analysis)
For the best results, configure an LLM provider:

If you want to use a free LLM, with high usage limits and good results, we recommend google gemini-2-flash model. Get API keys here:
https://aistudio.google.com/api-keys

### Manual configuration
You can also adjust the behavior of refine manually.
You have to run refine (once) and then you can edit the config at `~/config/refine/refine.toml`
For available Models look at the config.

## 🚀 Usage Examples

#### Quick Start
```bash
# Scan current directory (default behavior)
refine scan

# Scan a specific directory or file
refine scan /path/to/your/project
refine scan specific_file.py
```

#### File Selection
```bash
# Include specific file types
refine scan --include "*.py" --include "*.js" --include "*.ts"

# Exclude common build/test directories
refine scan --exclude "node_modules/" --exclude "__pycache__/" --exclude ".git/"

# Scan only Python files, exclude test files
refine scan --include "*.py" --exclude "*test*.py" --exclude "*spec*.py"

# Scan specific directories only
refine scan src/ tests/ --include "*.py"
```

#### Output Formats
```bash
# Rich terminal output (default, with colors and formatting)
refine scan

# Plain text output (for scripts or logs)
refine scan --format plain

# JSON output (for integration with other tools)
refine scan --format json

# Verbose output (detailed information)
refine scan --verbose
```

#### Scanning Modes
```bash
# Fast classical analysis only (no LLM required)
refine scan --classical-only

# Deep analysis with LLM (requires API key)
refine scan --llm-only
```

#### Auto-Fix Mode
```bash
# Automatically fix simple issues (safe line deletions for removeing commets only)
refine scan --fix
```

#### CI/CD Integration
```bash
# Exit with error code on issues (for CI/CD)
refine scan --format json | jq '.has_issues'

# Generate reports for CI/CD
refine scan --format json > scan_results.json

# Strict mode - fail on any issues
refine scan --classical-only --exclude "*test*" || exit 1
```

#### Development Workflow
```bash
# Pre-commit hook - fast classical check
refine scan --classical-only --format plain

# Code review - detailed analysis
refine scan --verbose --debug --include "*.py"

# Security audit - focus on vulnerabilities
refine scan --classical-only --include "*.py" --include "*.js"
```

### CI/CD Integration

#### GitHub Actions
Add this to your `.github/workflows/ci.yml`:

```yaml
name: Code Quality Check

on: [push, pull_request]

jobs:
  code-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh

      - name: Run Refine Vibe Code Check
        run: |
          # Fast classical check for CI
          ~/.local/bin/uvx refine-vibe-code scan --classical-only --format json --exclude "*test*" --exclude "*spec*" || exit 1

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: refine-scan-results
          path: scan_results.json
```

#### Pre-commit Hook
Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/CarlosMenke/refine-vibe-code
    rev: v0.1.0  # Use the latest version
    hooks:
      - id: refine-scan
        name: Refine Vibe Code Check
        entry: uvx refine-vibe-code scan --classical-only --format plain
        language: system
        files: \.(py|js|ts)$
        exclude: ^(tests/|.*test\.|.*spec\.)
```
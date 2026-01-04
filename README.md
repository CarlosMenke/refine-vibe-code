# 🔍 Refine Vibe Code

A powerful CLI tool that analyzes your codebase for AI-generated code patterns, security vulnerabilities, and code quality issues. Perfect for developers who want to maintain professional code standards.

## ✨ Quick Start (2 minutes setup)

### pipx

### homebrew

### 1. Install from source

#### With uv (recommended)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

# TODO: CHECK IF IT WORKS
**Option A: Install globally (recommended)**
```bash
uv tool install refine-vibe-code
```

**Option B: Install from source**
```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code
uv venv .venv && source .venv/bin/activate && uv sync
uv run refine
```

#### With pip
```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git && cd refine-vibe-code
python -m venv .venv && source .venv/bin/activate && pip install .
```

### LLM Integration (for deeper analysis)

For the best results, configure an LLM provider:
**Google Gemini**:
```toml
# In your refine.toml
[llm]
provider = "google"
model = "gemini-2.0-flash-exp"
api_key = "your-google-api-key"
```

## 🚀 Usage Examples

### Basic scanning
```bash
# Scan current directory with rich output (default)
refine scan

# Scan with JSON output for CI/CD integration
refine scan --format json

# Scan specific files only
refine scan --include "*.py" --include "*.js"

# Skip certain directories
refine scan --exclude "node_modules/" --exclude "*.min.js"
```

### Configuration (optional but recommended)
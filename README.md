# 🔍 Refine Vibe Code

A powerful CLI tool that analyzes your codebase for AI-generated code patterns, security vulnerabilities, and code quality issues. Perfect for developers who want to maintain professional code standards.

## 🚀 Installation


### pipx
coming, soon

### homebrew (MacOS)
coming, soon


The fastest way to use `refine` is with [uv](https://www.google.com/search?q=https://astral.sh/uv/). If you don't have it yet, install it with one command:
`curl -LsSf https://astral.sh/uv/install.sh | sh`

### 1. Quick Install (Recommended)

Install `refine` globally as a standalone tool:

```bash
uv tool install refine-vibe-code

```

### 2. Install from Source

Use this if you want to modify the code or contribute:

```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code

# Setup and run instantly
uv run refine

```

### 3. Traditional Install (pip)

If you prefer standard Python tools:

```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code
pip install .

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

# Scan specific files only
refine scan --include "*.py" --include "*.js"

# Skip certain directories
refine scan --exclude "node_modules/" --exclude "*.min.js"
```

### Configuration (optional but recommended)
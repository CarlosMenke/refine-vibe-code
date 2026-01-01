# 🔍 Refine Vibe Code

A powerful CLI tool that analyzes your codebase for AI-generated code patterns, security vulnerabilities, and code quality issues. Perfect for developers who want to maintain professional code standards.

## ✨ Quick Start (2 minutes setup)

### 1. Install uv (if you don't have it)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Install Refine Vibe Code

**Option A: Install globally (recommended)**
```bash
uv tool install refine-vibe-code
```

**Option B: Install from source**
```bash
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code
uv sync
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
### 3. Scan your code

```bash
# Scan current directory
refine scan

# Or scan a specific folder
refine scan /path/to/your/project

# Get help
refine --help
```

That's it! 🎉 Your code will be analyzed and you'll see a detailed report of any issues found.

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

For advanced usage, create a `refine.toml` configuration file:

```bash
# Generate a default config file
refine init
```

Then edit `refine.toml` to customize:
- Which checks to run
- File patterns to include/exclude
- LLM provider settings (OpenAI, Google Gemini)
- Output preferences

## 🛡️ What It Checks

### Security Issues
- **Hardcoded Secrets**: API keys, passwords, tokens in your code
- **SQL Injection**: Vulnerable database queries
- **Dangerous AI Logic**: Unsafe AI/ML practices
- **Dependency Validation**: Malicious or outdated packages

### Code Quality
- **AI-Generated Code**: Detects patterns typical of AI-generated content
- **Comment Quality**: Identifies useless or redundant comments
- **Naming Conventions**: Checks for AI-generated naming patterns
- **Edge Cases**: Finds potential bugs and missing error handling
- **Package Issues**: Import problems, missing files, etc.

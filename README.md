# Refine Vibe Code

A CLI tool for professional programmers to identify AI-generated code patterns, bad coding practices, and potential issues in their codebase.

## Features

- **AI Code Detection**: Identify code patterns typical of AI-generated content
- **Classical Analysis**: Fast AST-based checks for common issues
- **LLM-Powered Analysis**: Deep reasoning checks using OpenAI, GitHub Models, or local Ollama/Llama.cpp
- **Multiple Output Formats**: Rich terminal output, JSON, or plain text
- **Configurable**: TOML-based configuration with environment variable support
- **Extensible**: Plugin architecture for custom checkers

## Installation

### From Source

```bash
git clone https://github.com/yourusername/refine-vibe-code.git
cd refine-vibe-code
pip install -e .
```

### Using uv (Recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install the package
uv pip install -e .
```

## Quick Start

### Basic Usage

```bash
# Scan current directory
refine scan

# Scan specific file or directory
refine scan /path/to/your/code

# Use configuration file
refine scan --config my-config.toml

# Output as JSON
refine scan --format json

# Verbose output
refine scan --verbose
```

### Configuration

Create a `refine.toml` file in your project root:

```toml
[llm]
provider = "openai"
model = "gpt-4"
# api_key = "your-api-key"  # or set OPENAI_API_KEY env var

[checkers]
enabled = ["package_check", "boilerplate", "edge_cases", "naming_vibe"]
classical_only = false

[scan]
include_patterns = ["*.py", "*.js", "*.ts"]
exclude_patterns = ["__pycache__/", "node_modules/"]
```

Or generate a default configuration:

```bash
refine init
```

## Checkers

### Classical Checkers (Fast, AST-based)

- **package_check**: Python packaging and import issues
- **boilerplate**: Common boilerplate code patterns

### LLM Checkers (Deep Analysis)

- **edge_cases**: Potential bugs, edge cases, and security issues
- **naming_vibe**: Naming conventions and code style analysis

## LLM Providers

### OpenAI (Default)

```toml
[llm]
provider = "openai"
model = "gpt-4"
api_key = "your-openai-api-key"
```

### Local Ollama

```toml
[llm]
provider = "local"
model = "codellama:7b"
base_url = "http://localhost:11434"
```

## Output Formats

### Rich (Default)

Beautiful terminal output with colors, tables, and formatting.

### JSON

Machine-readable output for CI/CD integration:

```bash
refine scan --format json > results.json
```

### Plain Text

Simple text output for scripts and automation.

## Examples

### Scan with Classical Checkers Only

```bash
refine scan --classical-only
```

### Scan Specific File Types

```bash
refine scan --include "*.py" --include "*.js"
```

### Exclude Directories

```bash
refine scan --exclude "tests/" --exclude "build/"
```

### CI/CD Integration

```bash
# Exit with error code if issues found
refine scan --format json | jq '.findings | length > 0' && exit 1 || exit 0
```

## Development

### Setup

```bash
# Install in development mode
uv pip install -e ".[dev]"

# Run tests
pytest

# Run with sample data
refine scan tests/fixtures/
```

### Adding New Checkers

1. Create a new checker class inheriting from `BaseChecker`
2. Implement `check_file()` method
3. Add it to `get_all_checkers()` in `checkers/base.py`

### Project Structure

```
src/refine/
├── main.py              # CLI entry point
├── config/              # Configuration management
├── core/                # Orchestration logic
├── checkers/            # Analysis modules
│   ├── base.py         # Abstract checker base
│   ├── classical/      # Fast AST-based checks
│   └── llm/            # Deep LLM-based checks
├── providers/           # LLM client providers
└── ui/                  # Terminal formatting
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Roadmap

- [ ] Support for more programming languages
- [ ] Custom checker plugins
- [ ] Integration with popular IDEs
- [ ] Web-based interface
- [ ] Performance optimizations
- [ ] More LLM providers (Claude, Gemini, etc.)

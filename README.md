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
git clone https://github.com/CarlosMenke/refine-vibe-code.git
cd refine-vibe-code

# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install the package
uv venv .venv
source .venv/bin/activate
uv sync
uv run refine
```

## Quick Start

### Basic Usage

```bash
# Scan current directory
uv run refine scan

```

### Configuration

Create a `refine.toml` file in your project root:
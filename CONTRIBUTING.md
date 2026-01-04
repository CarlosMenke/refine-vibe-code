# Contributing to Refine Vibe Code

Thank you for your interest in contributing to Refine Vibe Code! We welcome contributions from the community.

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/refine-vibe-code.git`
3. Install dependencies: `uv sync`
4. Create a feature branch: `git checkout -b feature/your-feature-name`

## Code Style

This project uses:
- **Ruff** for code formatting and linting
- **Conventional commits** for commit messages
- **Type hints** throughout the codebase

### Running Quality Checks

```bash
# Format code
uv run ruff format .

# Lint code
uv run ruff check . --fix

# Type checking (if configured)
uv run mypy src/
```

## Commit Message Format

We follow [Conventional Commits](https://conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

Scopes:
- `core`: Core functionality
- `checkers`: Code analysis checkers
- `ui`: User interface
- `config`: Configuration
- `docs`: Documentation

## Testing

Run the test suite:
```bash
uv run pytest
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Follow the commit message format
4. Create a pull request with a clear description

## Reporting Issues

When reporting bugs, please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Any relevant configuration

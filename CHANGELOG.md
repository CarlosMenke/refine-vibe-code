# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2025-01-04

### Added
- Interactive API key setup with provider and model selection
- Improved thread safety in analysis functions

### Changed
- Enhanced TOML configuration generation and formatting
- Updated model recommendations and configuration examples

### Dependencies
- Updated uv.lock dependencies

## [0.1.1] - 2025-01-04

### Added
- Anthropic Claude LLM provider support
- Comprehensive model recommendations and integration guide
- Pipx and Homebrew installation instructions

### Dependencies
- Added anthropic package dependency

## [0.1.0] - 2025-01-04

### Added
- Initial release of Refine Vibe Code
- CLI tool for analyzing code quality and AI-generated patterns
- Support for multiple LLM providers (OpenAI, Google Gemini)
- Comprehensive checker system with classical and AI-powered analysis
- Parallel processing for improved performance
- Rich terminal output with progress indicators
- Configuration file support (refine.toml)
- Multiple output formats (rich text, JSON)

### Features
- **Code Analysis Checkers:**
  - Boilerplate code detection
  - Hardcoded secrets detection
  - SQL injection vulnerability scanning
  - Package dependency validation
  - AI-generated code pattern recognition
  - Comment quality analysis
  - Naming convention validation
  - Edge case detection

- **LLM Integration:**
  - Configurable LLM providers
  - Advanced chunking for large files
  - Parallel LLM processing
  - Error handling and fallbacks

- **Performance:**
  - Multi-threaded file scanning
  - Parallel LLM analysis
  - Memory-efficient chunking

### Documentation
- Comprehensive README with installation and usage examples
- Contributing guidelines
- MIT license

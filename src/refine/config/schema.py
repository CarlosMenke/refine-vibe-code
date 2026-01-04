"""Pydantic models for configuration validation."""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Dict, Any
from pathlib import Path


class ScanConfig(BaseModel):
    """Configuration for scanning behavior."""

    include_patterns: List[str] = Field(
        default=["*.py", "*requirements*.txt"],
        description="File patterns to include in scanning",
    )
    exclude_patterns: List[str] = Field(
        default=["__pycache__/", "*.pyc", "node_modules/", ".git/", ".venv/", ".env/", "build/", "dist/"],
        description="File patterns to exclude from scanning",
    )
    max_file_size: int = Field(
        default=1024 * 1024,  # 1MB
        description="Maximum file size to scan in bytes",
    )
    max_files: int = Field(
        default=1000,
        description="Maximum number of files to scan",
    )


class LLMConfig(BaseModel):
    """Configuration for LLM providers."""

    provider: str = Field(
        default="google",
        description="LLM provider to use (openai, google, claude)",
    )
    model: str = Field(
        default="gemini-2.0-flash-exp",
        description="Model name to use",
    )
    api_key: Optional[str] = Field(
        default=None,
        description="API key for the LLM provider",
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Base URL for the LLM API",
    )
    temperature: float = Field(
        default=0.1,
        description="Temperature for LLM responses",
        ge=0.0,
        le=2.0,
    )
    max_tokens: int = Field(
        default=100000,
        description="Maximum tokens for LLM responses",
    )
    timeout: int = Field(
        default=60,
        description="Timeout for LLM requests in seconds",
    )


class ChunkingConfig(BaseModel):
    """Configuration for code chunking behavior."""

    max_chunk_lines: int = Field(
        default=500,
        description="Maximum number of lines per chunk (larger = fewer API calls but higher latency per call)",
        ge=50,
        le=1500,
    )
    parallel_chunks: bool = Field(
        default=True,
        description="Process chunks in parallel to reduce total scan time",
    )
    max_parallel_requests: int = Field(
        default=10,
        description="Maximum number of parallel API requests",
        ge=1,
        le=10,
    )
    use_ast_boundaries: bool = Field(
        default=True,
        description="Split chunks at function/class boundaries instead of line counts",
    )
    stack_small_files: bool = Field(
        default=True,
        description="Combine small files into single chunks to reduce API requests",
    )
    stack_threshold: float = Field(
        default=0.5,
        description="Stack files if total is under this fraction of max_chunk_lines (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )


class CheckersConfig(BaseModel):
    """Configuration for checkers."""

    enabled: List[str] = Field(
        default=[
            # Security Issues
            "hardcoded_secrets",
            "sql_injection",
            "dangerous_ai_logic",

            # Code Quality
            "vibe_naming",
            "comment_quality",
            "edge_cases",

            # Package & Dependencies
            "package_check",
            "dependency_validation",

            # Best Practices
            "boilerplate",
        ],
        description="List of enabled checkers",
    )
    classical_only: bool = Field(
        default=False,
        description="Only run classical (AST-based) checkers",
    )
    llm_only: bool = Field(
        default=False,
        description="Only run LLM-based checkers",
    )


class OutputConfig(BaseModel):
    """Configuration for output formatting."""

    format: str = Field(
        default="rich",
        description="Output format (rich, json, plain)",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )
    show_fixes: bool = Field(
        default=True,
        description="Show suggested fixes",
    )
    color: bool = Field(
        default=True,
        description="Enable colored output",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug output with detailed analysis information",
    )


class RefineConfig(BaseModel):
    """Main configuration model for Refine Vibe Code."""

    scan: ScanConfig = Field(default_factory=ScanConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    checkers: CheckersConfig = Field(default_factory=CheckersConfig)
    chunking: ChunkingConfig = Field(default_factory=ChunkingConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    model_config = ConfigDict(
        env_prefix="REFINE_",
        env_nested_delimiter="__",
    )

    @field_validator('llm')
    @classmethod
    def validate_llm_config(cls, v):
        """Validate LLM configuration."""
        if v.provider not in ["openai", "google", "claude"]:
            raise ValueError(f"Unsupported LLM provider: {v.provider}")
        return v

    @field_validator('output')
    @classmethod
    def validate_output_config(cls, v):
        """Validate output configuration."""
        if v.format not in ["rich", "json", "plain"]:
            raise ValueError(f"Unsupported output format: {v.format}")
        return v

    def model_dump_toml(self) -> str:
        """Dump configuration as TOML string with comments and structure."""
        import tomli_w

        # Create TOML with comments and proper structure
        toml_content = """# Example configuration file for Refine Vibe Code
# Copy this file to your project root or use --config option

[scan]
# File patterns to include in scanning
include_patterns = {include_patterns}

# File patterns to exclude from scanning
exclude_patterns = {exclude_patterns}

[checkers]
# List of enabled checkers
enabled = {enabled}

# Only run classical (AST-based) checkers
classical_only = {classical_only}

# Only run LLM-based checkers
llm_only = {llm_only}

[chunking]
# Maximum lines per chunk (larger = fewer API calls, faster scans)
max_chunk_lines = {max_chunk_lines}

# Process chunks in parallel (significant speedup for large files)
parallel_chunks = {parallel_chunks}

# Maximum parallel API requests (4 is a good balance for rate limits)
max_parallel_requests = {max_parallel_requests}

# Use AST-based boundaries (function/class) instead of line counts
use_ast_boundaries = {use_ast_boundaries}

# Combine small files into single chunks to reduce API requests
stack_small_files = {stack_small_files}

# Stack files if total is under this fraction of max_chunk_lines (0.0-1.0)
stack_threshold = {stack_threshold}

[llm]
# LLM provider (openai, google, claude)
provider = "{provider}"

# Model name to use (see examples below for different providers)
model = "{model}"

# API key (can also be set via OPENAI_API_KEY, GOOGLE_API_KEY, ANTHROPIC_API_KEY environment variables)
api_key = "{api_key}"

# Temperature for responses (0.0 = deterministic, 2.0 = creative)
temperature = {temperature}

# Maximum tokens in response
max_tokens = {max_tokens}

# Request timeout in seconds
timeout = {timeout}

# LLM Integration Examples:
#
# OpenAI Models:
# provider = "openai"
# model = "gpt-4o"                    # Latest GPT-4 optimized model, great for code analysis
# model = "gpt-4o-mini"               # Cost-effective GPT-4 model, fast and reliable
# model = "gpt-4-turbo"               # Previous generation, good balance of speed/cost
# model = "gpt-3.5-turbo"             # Fastest and cheapest, good for simple checks
#
# Google Gemini Models:
# provider = "google"
# model = "gemini-2.0-flash-exp"      # Latest experimental model, most advanced
# model = "gemini-1.5-pro"            # Stable production model, good performance
# model = "gemini-1.5-flash"          # Fast and cost-effective model
#
# Anthropic Claude Models:
# provider = "claude"
# model = "claude-3-5-sonnet-20241022" # Latest Claude model, excellent for code analysis
# model = "claude-3-5-haiku-20241022"  # Fast and cost-effective model

[output]
# Output format (rich, json, plain)
format = "{format}"

# Enable verbose output
verbose = {verbose}

# Show suggested fixes
show_fixes = {show_fixes}

# Enable colored output
color = {color}
""".format(
            include_patterns=self.scan.include_patterns,
            exclude_patterns=self.scan.exclude_patterns,
            enabled=self.checkers.enabled,
            classical_only=self.checkers.classical_only,
            llm_only=self.checkers.llm_only,
            max_chunk_lines=self.chunking.max_chunk_lines,
            parallel_chunks=self.chunking.parallel_chunks,
            max_parallel_requests=self.chunking.max_parallel_requests,
            use_ast_boundaries=self.chunking.use_ast_boundaries,
            stack_small_files=self.chunking.stack_small_files,
            stack_threshold=self.chunking.stack_threshold,
            provider=self.llm.provider,
            model=self.llm.model,
            api_key=self.llm.api_key or "",
            temperature=self.llm.temperature,
            max_tokens=self.llm.max_tokens,
            timeout=self.llm.timeout,
            format=self.output.format,
            verbose=self.output.verbose,
            show_fixes=self.output.show_fixes,
            color=self.output.color,
        )

        return toml_content






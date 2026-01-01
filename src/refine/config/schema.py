"""Pydantic models for configuration validation."""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Dict, Any
from pathlib import Path


class ScanConfig(BaseModel):
    """Configuration for scanning behavior."""

    include_patterns: List[str] = Field(
        default=["*.py", "*.js", "*.ts", "*.java", "*.cpp", "*.c", "*.go", "*.rs",
                "requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg",
                "Pipfile", "Pipfile.lock", "package.json", "package-lock.json", "yarn.lock"],
        description="File patterns to include in scanning",
    )
    exclude_patterns: List[str] = Field(
        default=["__pycache__/", "*.pyc", "node_modules/", ".git/", "venv/", ".env/"],
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
        default="openai",
        description="LLM provider to use (openai, google)",
    )
    model: str = Field(
        default="gpt-4",
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
        default=1000,
        description="Maximum tokens for LLM responses",
    )
    timeout: int = Field(
        default=30,
        description="Timeout for LLM requests in seconds",
    )


class CheckersConfig(BaseModel):
    """Configuration for checkers."""

    enabled: List[str] = Field(
        default=[
            "package_check",
            "boilerplate",
            "dependency_validation",
            "edge_cases",
            "naming_vibe",
            "comment_quality",
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


class RefineConfig(BaseModel):
    """Main configuration model for Refine Vibe Code."""

    scan: ScanConfig = Field(default_factory=ScanConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    checkers: CheckersConfig = Field(default_factory=CheckersConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    model_config = ConfigDict(
        env_prefix="REFINE_",
        env_nested_delimiter="__",
    )

    @field_validator('llm')
    @classmethod
    def validate_llm_config(cls, v):
        """Validate LLM configuration."""
        if v.provider not in ["openai", "google"]:
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
        """Dump configuration as TOML string."""
        import tomli_w

        # Convert to dict and handle nested models
        data = self.model_dump()

        # Custom serialization for better TOML formatting
        toml_data = {
            "scan": {
                "include_patterns": self.scan.include_patterns,
                "exclude_patterns": self.scan.exclude_patterns,
                "max_file_size": self.scan.max_file_size,
                "max_files": self.scan.max_files,
            },
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
                "timeout": self.llm.timeout,
            },
            "checkers": {
                "enabled": self.checkers.enabled,
                "classical_only": self.checkers.classical_only,
                "llm_only": self.checkers.llm_only,
            },
            "output": {
                "format": self.output.format,
                "verbose": self.output.verbose,
                "show_fixes": self.output.show_fixes,
                "color": self.output.color,
            },
        }

        # Remove None values for cleaner TOML
        def clean_dict(d):
            return {k: v for k, v in d.items() if v is not None}

        toml_data = {k: clean_dict(v) for k, v in toml_data.items()}

        return tomli_w.dumps(toml_data)






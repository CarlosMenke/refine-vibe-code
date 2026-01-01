"""Unit tests for configuration system."""

import pytest
from pathlib import Path
from src.refine.config.schema import RefineConfig
from src.refine.config.loader import load_config


class TestRefineConfig:
    """Test RefineConfig class."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RefineConfig()

        assert config.scan.include_patterns == [
            "*.py", "*.js", "*.ts", "*.java", "*.cpp", "*.c", "*.go", "*.rs"
        ]
        assert config.llm.provider == "openai"
        assert config.llm.model == "gpt-4"
        assert config.llm.temperature == 0.1
        assert config.checkers.enabled == [
            "package_check", "boilerplate", "edge_cases", "naming_vibe", "comment_quality"
        ]

    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        config = RefineConfig(llm={"provider": "openai"})
        assert config.llm.provider == "openai"

        # Invalid provider should raise error
        with pytest.raises(ValueError):
            RefineConfig(llm={"provider": "invalid"})

    def test_config_toml_serialization(self):
        """Test TOML serialization."""
        config = RefineConfig()
        toml_str = config.model_dump_toml()

        assert isinstance(toml_str, str)
        assert "[scan]" in toml_str
        assert "[llm]" in toml_str
        assert "[checkers]" in toml_str
        assert "[output]" in toml_str


class TestConfigLoader:
    """Test configuration loader."""

    def test_load_default_config(self):
        """Test loading default configuration."""
        config = load_config()
        assert isinstance(config, RefineConfig)

    def test_load_config_from_file(self, tmp_path: Path):
        """Test loading configuration from TOML file."""
        config_file = tmp_path / "test_config.toml"
        config_file.write_text("""
[llm]
provider = "local"
model = "llama2"

[checkers]
enabled = ["package_check", "boilerplate"]
""")

        config = load_config(config_file)
        assert config.llm.provider == "local"
        assert config.llm.model == "llama2"
        assert config.checkers.enabled == ["package_check", "boilerplate"]






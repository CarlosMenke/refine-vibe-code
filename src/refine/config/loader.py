"""Configuration loader that merges default, file-based, and env configs."""

import os
from pathlib import Path
from typing import Optional, Union

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib

from .schema import RefineConfig


def find_global_config_file() -> Optional[Path]:
    """Find global configuration file in standard locations."""
    # Check standard XDG config directory first
    xdg_config = os.environ.get("XDG_CONFIG_HOME", "~/.config")
    xdg_config = Path(xdg_config).expanduser()
    global_config = xdg_config / "refine" / "refine.toml"
    if global_config.exists():
        return global_config

    # Fallback to ~/.refine.toml
    legacy_config = Path.home() / ".refine.toml"
    if legacy_config.exists():
        return legacy_config

    return None


def find_project_config_file(start_path: Optional[Path] = None) -> Optional[Path]:
    """Find project configuration file by searching up the directory tree."""
    if start_path is None:
        start_path = Path.cwd()
    elif not start_path.is_absolute():
        start_path = Path.cwd() / start_path

    current = start_path if start_path.is_dir() else start_path.parent

    while True:
        config_file = current / "refine.toml"
        if config_file.exists():
            return config_file

        if current.parent == current:
            break
        current = current.parent

    return None


def load_config_from_file(config_path: Path) -> dict:
    """Load configuration from TOML file."""
    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        raise ValueError(f"Failed to load config from {config_path}: {e}")


def load_config(config_path: Optional[Union[str, Path]] = None, scan_path: Optional[Path] = None) -> RefineConfig:
    """Load and merge configuration from multiple sources.

    Priority order (highest to lowest):
    1. Environment variables
    2. Explicit config file path
    3. Project config file (refine.toml in current/project directory)
    4. Global config file (~/.config/refine/refine.toml or ~/.refine.toml)
    5. Default configuration
    """
    # Start with default configuration
    config_dict = {}

    # Load from global config file
    global_config_path = find_global_config_file()
    if global_config_path:
        global_config = load_config_from_file(global_config_path)
        config_dict.update(global_config)

    # Load from project config file
    if config_path is None:
        project_config_path = find_project_config_file(scan_path)
    else:
        project_config_path = None

    # Load from explicit config file
    if config_path is not None:
        config_path = Path(config_path)
        if config_path.exists():
            explicit_config = load_config_from_file(config_path)
            config_dict = _deep_merge(config_dict, explicit_config)
        else:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
    elif project_config_path:
        # Load from auto-discovered project config
        project_config = load_config_from_file(project_config_path)
        config_dict = _deep_merge(config_dict, project_config)

    # Load from environment variables
    env_config = _load_env_config()
    if env_config:
        # Deep merge environment config
        config_dict = _deep_merge(config_dict, env_config)

    # Validate and create configuration object
    try:
        return RefineConfig(**config_dict)
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")


def _load_env_config() -> dict:
    """Load configuration from environment variables."""
    config = {}
    prefix = "REFINE_"

    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue

        # Remove prefix and split by double underscore
        config_key = key[len(prefix):].lower()

        # Handle nested configuration
        if "__" in config_key:
            parts = config_key.split("__")
            _set_nested_value(config, parts, value)
        else:
            # Handle top-level config
            if config_key in ["verbose", "color", "classical_only", "llm_only", "show_fixes", "debug"]:
                config[config_key] = value.lower() in ("true", "1", "yes", "on")
            elif config_key in ["max_file_size", "max_files", "max_tokens", "timeout"]:
                try:
                    config[config_key] = int(value)
                except ValueError:
                    pass  # Skip invalid values
            elif config_key == "temperature":
                try:
                    config[config_key] = float(value)
                except ValueError:
                    pass  # Skip invalid values
            elif config_key in ["include_patterns", "exclude_patterns", "enabled"]:
                # Handle comma-separated lists
                config[config_key] = [item.strip() for item in value.split(",") if item.strip()]
            else:
                config[config_key] = value

    return config


def _set_nested_value(config: dict, keys: list, value: str) -> None:
    """Set a nested value in a dictionary."""
    current = config
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    last_key = keys[-1]

    # Type conversion based on key
    if last_key in ["verbose", "color", "classical_only", "llm_only", "show_fixes", "debug"]:
        current[last_key] = value.lower() in ("true", "1", "yes", "on")
    elif last_key in ["max_file_size", "max_files", "max_tokens", "timeout"]:
        try:
            current[last_key] = int(value)
        except ValueError:
            current[last_key] = value
    elif last_key == "temperature":
        try:
            current[last_key] = float(value)
        except ValueError:
            current[last_key] = value
    elif last_key in ["include_patterns", "exclude_patterns", "enabled"]:
        # Handle comma-separated lists
        current[last_key] = [item.strip() for item in value.split(",") if item.strip()]
    else:
        current[last_key] = value


def _deep_merge(base: dict, update: dict) -> dict:
    """Deep merge two dictionaries.

    Empty strings don't override non-empty values (allows global api_key to persist).
    """
    result = base.copy()

    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        elif value == "" and key in result and result[key]:
            # Don't override non-empty values with empty strings
            pass
        else:
            result[key] = value

    return result


def save_config(config: RefineConfig, path: Path) -> None:
    """Save configuration to a TOML file."""
    try:
        content = config.model_dump_toml()
        path.write_text(content)
    except Exception as e:
        raise ValueError(f"Failed to save config to {path}: {e}")






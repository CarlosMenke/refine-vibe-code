"""LLM client providers for different services."""

from typing import Optional
from ..config.schema import RefineConfig
from .base import ProviderFactory, LLMProvider

# Re-export for backward compatibility
def get_provider(config: Optional[RefineConfig] = None) -> LLMProvider:
    """Get the configured LLM provider (backward compatibility)."""
    return ProviderFactory.get_provider(config)

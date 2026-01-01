"""LLM client providers for different services."""

from abc import ABC, abstractmethod
from typing import Optional
from ..config.schema import RefineConfig


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: RefineConfig):
        self.config = config

    @abstractmethod
    def analyze_code(self, prompt: str) -> str:
        """Analyze code using the LLM provider."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is available and configured."""
        pass


def get_provider(config: Optional[RefineConfig] = None) -> LLMProvider:
    """Get the configured LLM provider."""
    if config is None:
        from ..config.loader import load_config
        config = load_config()

    if config.llm.provider in ["openai", "google"]:
        from .openai import OpenAIProvider
        return OpenAIProvider(config)
    else:
        # Default to OpenAI
        from .openai import OpenAIProvider
        return OpenAIProvider(config)

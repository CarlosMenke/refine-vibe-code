"""Base LLM provider classes and factory for provider detection."""

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


class ProviderFactory:
    """Factory class for creating LLM providers based on configuration."""

    @staticmethod
    def get_provider(config: Optional[RefineConfig] = None) -> LLMProvider:
        """Get the configured LLM provider based on the provider type in config."""
        if config is None:
            from ..config.loader import load_config
            config = load_config()

        provider_name = config.llm.provider.lower()

        if provider_name == "openai":
            from .openai import OpenAIProvider
            return OpenAIProvider(config)
        elif provider_name in ["google", "gemini"]:
            from .google import GoogleProvider
            return GoogleProvider(config)
        elif provider_name in ["claude", "anthropic"]:
            from .claude import ClaudeProvider
            return ClaudeProvider(config)
        else:
            # Default to OpenAI for backward compatibility
            from .openai import OpenAIProvider
            return OpenAIProvider(config)

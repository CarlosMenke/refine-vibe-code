"""Anthropic Claude LLM provider implementation."""

from typing import Optional
from .base import LLMProvider


class ClaudeProvider(LLMProvider):
    """Anthropic Claude API provider for LLM analysis."""

    def __init__(self, config):
        super().__init__(config)
        self._client = None

    def is_available(self) -> bool:
        """Check if Claude provider is available."""
        api_key = self.config.llm.api_key

        # Check if we have a real API key (not just a placeholder)
        if not api_key:
            return False

        # Check for common placeholder patterns
        placeholder_patterns = [
            "sk-ant-your-claude-api-key-here",
            "your-claude-api-key-here",
            "sk-ant-api03-your-key-here",
            "",  # Empty string
        ]

        # Allow real Anthropic API keys (they start with sk-ant-)
        if api_key.startswith("sk-ant-"):
            return True

        return api_key not in placeholder_patterns

    def analyze_code(self, prompt: str) -> str:
        """Analyze code using Anthropic Claude API."""
        if not self.is_available():
            raise ValueError("Claude API key not configured")

        try:
            from anthropic import Anthropic

            # Initialize client if not already done
            if self._client is None:
                api_key = self.config.llm.api_key
                base_url = self.config.llm.base_url

                # Initialize with base_url if provided, otherwise use default
                if base_url:
                    self._client = Anthropic(
                        api_key=api_key,
                        base_url=base_url,
                    )
                else:
                    self._client = Anthropic(api_key=api_key)

            # Convert temperature to match Claude's expected range (0.0 to 1.0)
            # OpenAI uses 0-2, Claude uses 0-1
            temperature = min(self.config.llm.temperature / 2.0, 1.0)

            # Make the API call
            response = self._client.messages.create(
                model=self.config.llm.model,
                max_tokens=self.config.llm.max_tokens,
                temperature=temperature,
                system="You are a code analysis expert. Analyze code for issues, bugs, and improvements. Be precise and focus on actual problems.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                timeout=self.config.llm.timeout,
            )

            return response.content[0].text

        except ImportError:
            raise ValueError("Anthropic package not installed. Install with: pip install anthropic")
        except Exception as e:
            raise ValueError(f"Claude API error: {e}")

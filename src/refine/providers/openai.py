"""OpenAI LLM provider implementation."""

from typing import Optional
from .base import LLMProvider


class OpenAIProvider(LLMProvider):
    """OpenAI API provider for LLM analysis."""

    def __init__(self, config):
        super().__init__(config)
        self._client = None

    def is_available(self) -> bool:
        """Check if OpenAI provider is available."""
        api_key = self.config.llm.api_key

        # Check if we have a real API key (not just a placeholder)
        if not api_key:
            return False

        # Check for common placeholder patterns
        placeholder_patterns = [
            "sk-your-openai-api-key-here",
            "your-openai-api-key-here",
            "",  # Empty string
        ]

        # Allow real OpenAI API keys (they start with sk-)
        if api_key.startswith("sk-"):
            return True

        return api_key not in placeholder_patterns

    def analyze_code(self, prompt: str) -> str:
        """Analyze code using OpenAI API."""
        if not self.is_available():
            raise ValueError("OpenAI API key not configured")

        try:
            from openai import OpenAI

            # Initialize client if not already done
            if self._client is None:
                api_key = self.config.llm.api_key
                base_url = self.config.llm.base_url

                self._client = OpenAI(
                    api_key=api_key,
                    base_url=base_url,
                )

            # Make the API call
            response = self._client.chat.completions.create(
                model=self.config.llm.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a code analysis expert. Analyze code for issues, bugs, and improvements. Be precise and focus on actual problems."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                timeout=self.config.llm.timeout,
            )

            return response.choices[0].message.content

        except ImportError:
            raise ValueError("OpenAI package not installed. Install with: pip install openai")
        except Exception as e:
            raise ValueError(f"OpenAI API error: {e}")


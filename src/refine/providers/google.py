"""Google Gemini LLM provider implementation."""

from typing import Optional
from .base import LLMProvider


class GoogleProvider(LLMProvider):
    """Google Gemini API provider for LLM analysis using OpenAI-compatible interface."""

    def __init__(self, config):
        super().__init__(config)
        self._client = None

    def is_available(self) -> bool:
        """Check if Google provider is available."""
        api_key = self.config.llm.api_key

        # Check if we have a real API key (not just a placeholder)
        if not api_key:
            return False

        # Check for common placeholder patterns
        placeholder_patterns = [
            "your-google-api-key-here",
            "",  # Empty string
        ]

        # Allow real Google API keys (they start with specific patterns)
        if api_key.startswith(("AIza", "ya29.")):
            return True

        return api_key not in placeholder_patterns

    def analyze_code(self, prompt: str) -> str:
        """Analyze code using Google Gemini API."""
        if not self.is_available():
            raise ValueError("Google API key not configured")

        try:
            from openai import OpenAI

            # Initialize client if not already done
            if self._client is None:
                api_key = self.config.llm.api_key
                # Use Google's OpenAI-compatible API endpoint
                base_url = self.config.llm.base_url or "https://generativelanguage.googleapis.com/v1beta/openai/"

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
            raise ValueError(f"Google Gemini API error: {e}")


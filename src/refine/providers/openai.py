"""OpenAI LLM provider implementation."""

import os
from typing import Optional
from ..config.schema import RefineConfig
from . import LLMProvider


class OpenAIProvider(LLMProvider):
    """OpenAI API provider for LLM analysis."""

    def __init__(self, config: RefineConfig):
        super().__init__(config)
        self._client = None

    def is_available(self) -> bool:
        """Check if OpenAI/Google provider is available."""
        if self.config.llm.provider == "google":
            # Prioritize environment variable over config file
            api_key = os.getenv("GOOGLE_API_KEY") or self.config.llm.api_key
        else:
            # Prioritize environment variable over config file
            api_key = os.getenv("OPENAI_API_KEY") or self.config.llm.api_key

        # Check if we have a real API key (not just a placeholder)
        if not api_key:
            return False

        # Check for common placeholder patterns
        placeholder_patterns = [
            "sk-your-openai-api-key-here",
            "your-openai-api-key-here",
            "sk-...",
            "your-google-api-key-here",
            "your-google-api-key-here",  # Updated placeholder
            "AQ.Ab8RN6KJZnkDbofE5cRd-3DZJYcmSleHvg-8N7do1FXdzfQ-8g",  # Old Google key
        ]

        return api_key not in placeholder_patterns and not api_key.startswith("sk-...")

    def analyze_code(self, prompt: str) -> str:
        """Analyze code using OpenAI/Google API."""
        if not self.is_available():
            if self.config.llm.provider == "google":
                raise ValueError("Google API key not configured")
            else:
                raise ValueError("OpenAI API key not configured")

        try:
            from openai import OpenAI

            # Initialize client if not already done
            if self._client is None:
                if self.config.llm.provider == "google":
                    api_key = self.config.llm.api_key or os.getenv("GOOGLE_API_KEY")
                    # Use Google's OpenAI-compatible API endpoint
                    base_url = self.config.llm.base_url or "https://generativelanguage.googleapis.com/v1beta/openai/"
                else:
                    api_key = self.config.llm.api_key or os.getenv("OPENAI_API_KEY")
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

    def _get_api_key_from_env(self) -> Optional[str]:
        """Get API key from environment variables."""
        if self.config.llm.provider == "google":
            return os.getenv("GOOGLE_API_KEY")
        else:
            return os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_APIKEY")






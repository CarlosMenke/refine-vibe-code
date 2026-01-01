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
        """Check if OpenAI provider is available."""
        api_key = self.config.llm.api_key or os.getenv("OPENAI_API_KEY")
        return bool(api_key)

    def analyze_code(self, prompt: str) -> str:
        """Analyze code using OpenAI API."""
        if not self.is_available():
            raise ValueError("OpenAI API key not configured")

        try:
            from openai import OpenAI

            # Initialize client if not already done
            if self._client is None:
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
        return os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_APIKEY")






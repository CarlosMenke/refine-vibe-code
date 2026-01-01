"""Local LLM provider implementation for Ollama/Llama.cpp."""

import os
import json
from typing import Optional
from ..config.schema import RefineConfig
from . import LLMProvider


class LocalProvider(LLMProvider):
    """Local LLM provider for Ollama/Llama.cpp models."""

    def __init__(self, config: RefineConfig):
        super().__init__(config)
        self.base_url = self.config.llm.base_url or "http://localhost:11434"

    def is_available(self) -> bool:
        """Check if local LLM provider is available."""
        try:
            import httpx
            # Try to connect to the local service
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except (ImportError, Exception):
            return False

    def analyze_code(self, prompt: str) -> str:
        """Analyze code using local LLM API."""
        if not self.is_available():
            raise ValueError(f"Local LLM service not available at {self.base_url}")

        try:
            import httpx

            # Prepare the request for Ollama API
            payload = {
                "model": self.config.llm.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.llm.temperature,
                    "num_predict": self.config.llm.max_tokens,
                }
            }

            with httpx.Client(timeout=self.config.llm.timeout) as client:
                response = client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    raise ValueError(f"Local LLM API error: {response.status_code}")

                result = response.json()
                return result.get("response", "")

        except ImportError:
            raise ValueError("httpx package not installed. Install with: pip install httpx")
        except Exception as e:
            raise ValueError(f"Local LLM API error: {e}")

    def list_available_models(self) -> list:
        """List available models from the local service."""
        try:
            import httpx

            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.base_url}/api/tags")
                if response.status_code == 200:
                    data = response.json()
                    return [model["name"] for model in data.get("models", [])]
                return []
        except Exception:
            return []

    def _is_ollama_available(self) -> bool:
        """Check if Ollama service is running."""
        try:
            import httpx
            with httpx.Client(timeout=2.0) as client:
                response = client.get(f"{self.base_url}/api/version")
                return response.status_code == 200
        except Exception:
            return False






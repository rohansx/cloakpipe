"""Base HTTP client for the CloakPipe API."""

from __future__ import annotations

import httpx
from typing import Any


class CloakPipeClient:
    """
    Thin HTTP client for the CloakPipe proxy API.

    Can be used standalone or as the backend for LangChain/LlamaIndex wrappers.

    Args:
        base_url: URL of your CloakPipe proxy (e.g. "http://localhost:3100").
        api_key: Your upstream LLM API key. CloakPipe passes this through.
        token: Optional CloakPipe Cloud JWT token (for cloud features like batch detect).
        timeout: Request timeout in seconds.

    Example::

        client = CloakPipeClient(
            base_url="http://localhost:3100",
            api_key="sk-your-openai-key",
        )
        response = client.chat("Summarize the file for Priya Mehta, PAN BNZPM2501F")
        print(response)  # PII was masked before reaching OpenAI
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3100",
        api_key: str = "",
        token: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.token = token
        self._client = httpx.Client(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.token:
            h["X-CloakPipe-Token"] = self.token
        return h

    def chat(
        self,
        prompt: str,
        model: str = "gpt-4o",
        system: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a single chat prompt through the CloakPipe proxy."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self._client.post(
            f"{self.base_url}/v1/chat/completions",
            headers=self._headers(),
            json={"model": model, "messages": messages, **kwargs},
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def detect(self, text: str) -> list[dict]:
        """Detect PII entities in text (no masking)."""
        response = self._client.post(
            f"{self.base_url}/api/detect",
            headers=self._headers(),
            json={"text": text},
        )
        response.raise_for_status()
        return response.json().get("entities", [])

    def mask(self, text: str, strategy: str = "token") -> dict:
        """Mask PII in text. Returns masked text and entity map."""
        response = self._client.post(
            f"{self.base_url}/api/pseudonymize",
            headers=self._headers(),
            json={"text": text, "strategy": strategy},
        )
        response.raise_for_status()
        return response.json()

    def batch_detect(self, texts: list[str], pseudonymize: bool = False) -> dict:
        """Detect PII across multiple texts in one call (Cloud API)."""
        if not self.token:
            raise ValueError("batch_detect requires a CloakPipe Cloud token")
        response = self._client.post(
            f"{self.base_url}/api/detect/batch",
            headers={**self._headers(), "Authorization": f"Bearer {self.token}"},
            json={"texts": texts, "pseudonymize": pseudonymize},
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> bool:
        """Check if the CloakPipe proxy is running."""
        try:
            r = self._client.get(f"{self.base_url}/api/health")
            return r.status_code == 200
        except Exception:
            return False

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CloakPipeClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

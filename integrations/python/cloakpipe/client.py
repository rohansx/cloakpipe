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
        cloud_api_key: Optional CloakPipe Cloud API key (``cp_xxx``).
            When provided, sent as ``X-CloakPipe-Key`` header.
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
        cloud_api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.token = token
        self.cloud_api_key = cloud_api_key
        self._client = httpx.Client(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.token:
            h["X-CloakPipe-Token"] = self.token
        if self.cloud_api_key:
            h["X-CloakPipe-Key"] = self.cloud_api_key
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

    def _cloud_headers(self) -> dict[str, str]:
        """Headers for cloud API endpoints (JWT auth)."""
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.cloud_api_key:
            headers["X-CloakPipe-Key"] = self.cloud_api_key
        return headers

    def redact_document(
        self, file_path: str, profile: str = "general", mode: str = "redact"
    ) -> dict:
        """Upload a document for PII detection and redaction.

        Args:
            file_path: Path to file (PDF, CSV, TXT, JSON, MD).
            profile: Detection profile (general, fintech, healthcare, legal).
            mode: "redact" or "detect_only".

        Returns:
            Dict with redacted_text, entities, format, pages, rows, byte_size.
        """
        import os

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            files = {"file": (filename, f)}
            data = {"profile": profile, "mode": mode}
            resp = self._client.post(
                f"{self.base_url}/api/v1/documents/redact",
                files=files,
                data=data,
                headers=self._cloud_headers(),
            )
        resp.raise_for_status()
        return resp.json()

    def redact_document_bytes(
        self,
        data: bytes,
        filename: str,
        profile: str = "general",
        mode: str = "redact",
    ) -> dict:
        """Upload raw bytes for PII detection and redaction.

        Args:
            data: File contents as bytes.
            filename: Filename with extension (used for format detection).
            profile: Detection profile.
            mode: "redact" or "detect_only".

        Returns:
            Dict with redacted_text, entities, format, pages, rows, byte_size.
        """
        files = {"file": (filename, data)}
        form_data = {"profile": profile, "mode": mode}
        resp = self._client.post(
            f"{self.base_url}/api/v1/documents/redact",
            files=files,
            data=form_data,
            headers=self._cloud_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def get_guardrails(self) -> list[dict]:
        """Get current guardrail policies."""
        resp = self._client.get(
            f"{self.base_url}/api/guardrails",
            headers=self._cloud_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def set_guardrails(self, tenant_id: str, **kwargs: Any) -> dict:
        """Create or update guardrail policy for a tenant.

        Args:
            tenant_id: Tenant ID to configure.
            **kwargs: enabled, mode, prompt_injection, jailbreak, toxicity,
                      pii_leakage_output, injection_threshold,
                      toxicity_threshold, entropy_threshold.

        Returns:
            Updated policy dict.
        """
        body = {"tenant_id": tenant_id, **kwargs}
        resp = self._client.post(
            f"{self.base_url}/api/guardrails",
            json=body,
            headers=self._cloud_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def get_access_policies(self) -> list[dict]:
        """Get RBAC access policies."""
        resp = self._client.get(
            f"{self.base_url}/api/policies",
            headers=self._cloud_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def create_access_policy(
        self, tenant_id: str, role_name: str, unmask_categories: list[str]
    ) -> dict:
        """Create an RBAC access policy.

        Args:
            tenant_id: Tenant ID.
            role_name: Role name (e.g. "finance", "support", "auditor").
            unmask_categories: List of PII categories this role can see unmasked.

        Returns:
            Created policy dict.
        """
        resp = self._client.post(
            f"{self.base_url}/api/policies",
            json={
                "tenant_id": tenant_id,
                "role_name": role_name,
                "unmask_categories": unmask_categories,
            },
            headers=self._cloud_headers(),
        )
        resp.raise_for_status()
        return resp.json()

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

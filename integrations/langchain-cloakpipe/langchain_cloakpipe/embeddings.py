"""CloakPipe-wrapped OpenAIEmbeddings that routes through the privacy proxy."""

from __future__ import annotations

from langchain_openai import OpenAIEmbeddings


class CloakPipeEmbeddings(OpenAIEmbeddings):
    """Drop-in replacement for OpenAIEmbeddings that routes through CloakPipe.

    Embedding inputs are scanned for PII and masked before reaching the provider.

    Usage::

        from langchain_cloakpipe import CloakPipeEmbeddings

        embeddings = CloakPipeEmbeddings(
            model="text-embedding-3-small",
            openai_api_key="sk-...",
            cloakpipe_url="http://localhost:3100",
        )
        vectors = embeddings.embed_documents(["Patient Rajesh, Aadhaar 2345 6789 0123"])
    """

    cloakpipe_url: str = "http://localhost:3100"
    cloud_api_key: str | None = None

    def __init__(self, **kwargs):
        cloakpipe_url = kwargs.pop("cloakpipe_url", "http://localhost:3100")
        cloud_api_key = kwargs.pop("cloud_api_key", None)
        kwargs.setdefault("openai_api_base", f"{cloakpipe_url}/v1")
        if cloud_api_key:
            headers = kwargs.get("default_headers") or {}
            kwargs["default_headers"] = {**headers, "X-CloakPipe-Key": cloud_api_key}
        super().__init__(**kwargs)
        self.cloakpipe_url = cloakpipe_url
        self.cloud_api_key = cloud_api_key

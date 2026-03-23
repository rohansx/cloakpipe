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

    def __init__(self, **kwargs):
        cloakpipe_url = kwargs.pop("cloakpipe_url", "http://localhost:3100")
        kwargs.setdefault("openai_api_base", f"{cloakpipe_url}/v1")
        super().__init__(**kwargs)
        self.cloakpipe_url = cloakpipe_url

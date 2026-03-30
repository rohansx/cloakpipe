"""CloakPipe-wrapped OpenAI embeddings for LlamaIndex."""

from __future__ import annotations

from llama_index.embeddings.openai import OpenAIEmbedding


class CloakPipeEmbedding(OpenAIEmbedding):
    """Drop-in replacement for LlamaIndex OpenAIEmbedding routed through CloakPipe.

    Usage::

        from llamaindex_cloakpipe import CloakPipeEmbedding

        embed = CloakPipeEmbedding(
            model_name="text-embedding-3-small",
            api_key="sk-...",
            cloakpipe_url="http://localhost:3100",
        )
        vector = embed.get_text_embedding("Patient Rajesh, Aadhaar 2345 6789 0123")
    """

    cloakpipe_url: str = "http://localhost:3100"
    cloud_api_key: str | None = None

    def __init__(
        self,
        cloakpipe_url: str = "http://localhost:3100",
        cloud_api_key: str | None = None,
        **kwargs,
    ):
        kwargs.setdefault("api_base", f"{cloakpipe_url}/v1")
        if cloud_api_key:
            headers = kwargs.get("additional_kwargs", {}).get("headers", {})
            kwargs.setdefault("additional_kwargs", {})
            kwargs["additional_kwargs"]["headers"] = {
                **headers,
                "X-CloakPipe-Key": cloud_api_key,
            }
        super().__init__(**kwargs)
        self.cloakpipe_url = cloakpipe_url
        self.cloud_api_key = cloud_api_key

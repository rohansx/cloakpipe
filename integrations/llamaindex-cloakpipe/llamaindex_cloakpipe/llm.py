"""CloakPipe-wrapped OpenAI LLM for LlamaIndex."""

from __future__ import annotations

from llama_index.llms.openai import OpenAI


class CloakPipeLLM(OpenAI):
    """Drop-in replacement for LlamaIndex OpenAI that routes through CloakPipe.

    Usage::

        from llamaindex_cloakpipe import CloakPipeLLM

        llm = CloakPipeLLM(
            model="gpt-4",
            api_key="sk-...",
            cloakpipe_url="http://localhost:3100",
        )
        response = llm.complete("Summarize case for Rajesh, PAN BNZPM2501F")
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

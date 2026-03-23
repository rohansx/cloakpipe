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

    def __init__(self, cloakpipe_url: str = "http://localhost:3100", **kwargs):
        kwargs.setdefault("api_base", f"{cloakpipe_url}/v1")
        super().__init__(**kwargs)
        self.cloakpipe_url = cloakpipe_url

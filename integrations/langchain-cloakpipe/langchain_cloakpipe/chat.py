"""CloakPipe-wrapped ChatOpenAI that routes all traffic through the privacy proxy."""

from __future__ import annotations

from langchain_openai import ChatOpenAI


class ChatCloakPipe(ChatOpenAI):
    """Drop-in replacement for ChatOpenAI that routes through CloakPipe.

    All prompts are scanned for PII, masked before reaching the LLM,
    and responses are rehydrated automatically.

    Usage::

        from langchain_cloakpipe import ChatCloakPipe

        llm = ChatCloakPipe(
            model="gpt-4",
            openai_api_key="sk-...",
            cloakpipe_url="http://localhost:3100",
        )
        response = llm.invoke("Summarize case for Rajesh Singh, Aadhaar 2345 6789 0123")
    """

    cloakpipe_url: str = "http://localhost:3100"

    def __init__(self, **kwargs):
        cloakpipe_url = kwargs.pop("cloakpipe_url", "http://localhost:3100")
        kwargs.setdefault("openai_api_base", f"{cloakpipe_url}/v1")
        super().__init__(**kwargs)
        self.cloakpipe_url = cloakpipe_url

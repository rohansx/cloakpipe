"""LlamaIndex integration for CloakPipe.

Usage::

    from cloakpipe.llamaindex import CloakPipeLLM

    llm = CloakPipeLLM(
        base_url="http://localhost:3100",
        api_key="sk-your-openai-key",
        model="gpt-4o",
    )

    from llama_index.core import Settings
    Settings.llm = llm  # All LlamaIndex queries now route through CloakPipe
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

_LLAMAINDEX_AVAILABLE = False
try:
    from llama_index.core.llms import (
        LLM,
        ChatMessage,
        ChatResponse,
        CompletionResponse,
        LLMMetadata,
        MessageRole,
    )
    from llama_index.core.llms.callbacks import llm_chat_callback, llm_completion_callback
    _LLAMAINDEX_AVAILABLE = True
except ImportError:
    # Provide stubs so the module can be imported without llama-index installed.
    # The real error is raised when CloakPipeLLM is instantiated.
    class LLM:  # type: ignore[no-redef]
        pass
    def llm_chat_callback():  # type: ignore[misc]
        return lambda f: f
    def llm_completion_callback():  # type: ignore[misc]
        return lambda f: f
    class ChatMessage:  # type: ignore[no-redef]
        def __init__(self, role=None, content=""):
            self.role = role
            self.content = content
    class ChatResponse:  # type: ignore[no-redef]
        def __init__(self, message=None):
            self.message = message
    class CompletionResponse:  # type: ignore[no-redef]
        def __init__(self, text=""):
            self.text = text
    class LLMMetadata:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    class MessageRole:  # type: ignore[no-redef]
        USER = "user"
        ASSISTANT = "assistant"

import httpx


def _to_openai_messages(messages: Sequence[ChatMessage]) -> list[dict]:
    return [
        {"role": msg.role.value if hasattr(msg.role, "value") else str(msg.role),
         "content": msg.content}
        for msg in messages
    ]


class CloakPipeLLM(LLM):
    """
    LlamaIndex-compatible LLM that routes all requests through CloakPipe.

    Requires: pip install 'cloakpipe[llamaindex]'

    Set as your default LLM via `Settings.llm = CloakPipeLLM(...)` to
    automatically mask PII in all RAG queries, index summarization, and
    agent reasoning steps.
    """

    base_url: str = "http://localhost:3100"
    api_key: str = ""
    model: str = "gpt-4o"
    temperature: float = 0.1
    max_tokens: int = 1024

    def __init__(self, **kwargs: Any) -> None:
        if not _LLAMAINDEX_AVAILABLE:
            raise ImportError(
                "llama-index-core is required for CloakPipe LlamaIndex integration.\n"
                "Install with: pip install 'cloakpipe[llamaindex]'"
            )
        super().__init__(**kwargs)

    @property
    def metadata(self) -> LLMMetadata:
        return LLMMetadata(
            model_name=self.model,
            context_window=128000,
            num_output=self.max_tokens,
            is_chat_model=True,
        )

    def _post_chat(self, messages: Sequence[ChatMessage], **kwargs: Any) -> dict:
        with httpx.Client() as client:
            resp = client.post(
                f"{self.base_url.rstrip('/')}/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                json={
                    "model": self.model,
                    "messages": _to_openai_messages(messages),
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    **kwargs,
                },
                timeout=60.0,
            )
            resp.raise_for_status()
        return resp.json()

    @llm_chat_callback()
    def chat(self, messages: Sequence[ChatMessage], **kwargs: Any) -> ChatResponse:
        data = self._post_chat(messages, **kwargs)
        content = data["choices"][0]["message"]["content"]
        return ChatResponse(message=ChatMessage(role=MessageRole.ASSISTANT, content=content))

    @llm_completion_callback()
    def complete(self, prompt: str, **kwargs: Any) -> CompletionResponse:
        messages = [ChatMessage(role=MessageRole.USER, content=prompt)]
        data = self._post_chat(messages, **kwargs)
        content = data["choices"][0]["message"]["content"]
        return CompletionResponse(text=content)

    @llm_chat_callback()
    def stream_chat(self, messages: Sequence[ChatMessage], **kwargs: Any):
        raise NotImplementedError("Use async_stream_chat for streaming")

    @llm_completion_callback()
    def stream_complete(self, prompt: str, **kwargs: Any):
        raise NotImplementedError("Use async_stream_complete for streaming")

    async def achat(self, messages: Sequence[ChatMessage], **kwargs: Any) -> ChatResponse:
        import httpx as _httpx
        async with _httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url.rstrip('/')}/v1/chat/completions",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "messages": _to_openai_messages(messages),
                      "temperature": self.temperature, "max_tokens": self.max_tokens, **kwargs},
                timeout=60.0,
            )
            resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return ChatResponse(message=ChatMessage(role=MessageRole.ASSISTANT, content=content))

    async def acomplete(self, prompt: str, **kwargs: Any) -> CompletionResponse:
        messages = [ChatMessage(role=MessageRole.USER, content=prompt)]
        resp = await self.achat(messages, **kwargs)
        return CompletionResponse(text=resp.message.content)

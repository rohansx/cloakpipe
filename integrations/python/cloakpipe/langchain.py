"""LangChain integration for CloakPipe.

Provides two integration patterns:
1. CloakPipeLLM — a drop-in LangChain BaseChatModel that routes through the proxy.
2. wrap_llm — attach to any existing LangChain LLM.

Usage::

    # Pattern 1: Replace your LLM with CloakPipeLLM
    from cloakpipe.langchain import CloakPipeLLM
    from langchain_core.messages import HumanMessage

    llm = CloakPipeLLM(
        base_url="http://localhost:3100",
        api_key="sk-your-openai-key",
        model="gpt-4o",
    )
    response = llm.invoke([HumanMessage(content="Summarize: Priya Mehta, PAN BNZPM2501F")])
    print(response.content)  # PII was masked before reaching OpenAI

    # Pattern 2: Wrap an existing LLM
    from cloakpipe.langchain import wrap_llm
    from langchain_openai import ChatOpenAI

    safe_llm = wrap_llm(ChatOpenAI(), base_url="http://localhost:3100")
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

try:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.messages import (
        AIMessage,
        BaseMessage,
        HumanMessage,
        SystemMessage,
    )
    from langchain_core.outputs import ChatGeneration, ChatResult
except ImportError as e:
    raise ImportError(
        "langchain-core is required for CloakPipe LangChain integration.\n"
        "Install with: pip install 'cloakpipe[langchain]'"
    ) from e

import httpx
from .client import CloakPipeClient


def _messages_to_openai(messages: Sequence[BaseMessage]) -> list[dict]:
    result = []
    for msg in messages:
        if isinstance(msg, HumanMessage):
            role = "user"
        elif isinstance(msg, AIMessage):
            role = "assistant"
        elif isinstance(msg, SystemMessage):
            role = "system"
        else:
            role = "user"
        result.append({"role": role, "content": msg.content})
    return result


class CloakPipeLLM(BaseChatModel):
    """
    LangChain-compatible chat model that routes all requests through CloakPipe.

    PII in prompts is automatically masked before reaching the upstream LLM,
    and restored in the response. The upstream model never sees real PII.
    """

    base_url: str = "http://localhost:3100"
    api_key: str = ""
    model: str = "gpt-4o"
    temperature: float = 0.7
    max_tokens: Optional[int] = None

    @property
    def _llm_type(self) -> str:
        return "cloakpipe"

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> ChatResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": _messages_to_openai(messages),
            "temperature": self.temperature,
        }
        if self.max_tokens:
            payload["max_tokens"] = self.max_tokens
        if stop:
            payload["stop"] = stop

        with httpx.Client() as client:
            resp = client.post(
                f"{self.base_url.rstrip('/')}/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                json=payload,
                timeout=60.0,
            )
            resp.raise_for_status()

        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"base_url": self.base_url, "model": self.model}


def wrap_llm(llm: Any, base_url: str = "http://localhost:3100") -> CloakPipeLLM:
    """
    Convenience wrapper: extract the api_key and model from an existing LangChain LLM.

    Works with ChatOpenAI, ChatAnthropic, and other OpenAI-compatible models.
    """
    api_key = getattr(llm, "openai_api_key", None) or getattr(llm, "api_key", "")
    model = getattr(llm, "model_name", None) or getattr(llm, "model", "gpt-4o")
    if hasattr(api_key, "get_secret_value"):
        api_key = api_key.get_secret_value()
    return CloakPipeLLM(base_url=base_url, api_key=str(api_key), model=str(model))

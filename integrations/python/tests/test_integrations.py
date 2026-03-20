"""Tests for CloakPipe Python integrations (no live server needed)."""

import pytest
from unittest.mock import MagicMock, patch
import json


def test_client_health_returns_false_when_server_down():
    from cloakpipe.client import CloakPipeClient
    client = CloakPipeClient(base_url="http://localhost:19999")
    assert client.health() is False


def test_client_batch_detect_requires_token():
    from cloakpipe.client import CloakPipeClient
    client = CloakPipeClient(base_url="http://localhost:3100", api_key="test")
    with pytest.raises(ValueError, match="token"):
        client.batch_detect(["test text"])


def test_langchain_llm_type():
    from cloakpipe.langchain import CloakPipeLLM
    llm = CloakPipeLLM(base_url="http://localhost:3100", api_key="test")
    assert llm._llm_type == "cloakpipe"
    assert llm.model == "gpt-4o"


def test_langchain_wrap_llm():
    from cloakpipe.langchain import wrap_llm, CloakPipeLLM

    mock_llm = MagicMock()
    mock_llm.model_name = "gpt-4-turbo"
    mock_llm.openai_api_key = "sk-test"
    # openai_api_key is just a plain string here (not SecretStr)

    wrapped = wrap_llm(mock_llm, base_url="http://localhost:3100")
    assert isinstance(wrapped, CloakPipeLLM)
    assert wrapped.model == "gpt-4-turbo"


def test_llamaindex_llm_metadata():
    from cloakpipe.llamaindex import CloakPipeLLM
    llm = CloakPipeLLM(base_url="http://localhost:3100", api_key="test", model="gpt-4o")
    meta = llm.metadata
    assert meta.model_name == "gpt-4o"
    assert meta.is_chat_model is True

"""Tests for ChatCloakPipe."""

from langchain_cloakpipe import ChatCloakPipe


def test_default_base_url():
    llm = ChatCloakPipe(openai_api_key="test-key")
    assert "localhost:3100" in str(llm.openai_api_base)


def test_custom_cloakpipe_url():
    llm = ChatCloakPipe(
        openai_api_key="test-key",
        cloakpipe_url="http://cloakpipe.internal:9000",
    )
    assert "cloakpipe.internal:9000" in str(llm.openai_api_base)


def test_model_passthrough():
    llm = ChatCloakPipe(openai_api_key="test-key", model="gpt-4o")
    assert llm.model_name == "gpt-4o"

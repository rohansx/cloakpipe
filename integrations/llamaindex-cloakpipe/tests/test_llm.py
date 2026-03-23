"""Tests for CloakPipeLLM."""

from llamaindex_cloakpipe import CloakPipeLLM


def test_default_base_url():
    llm = CloakPipeLLM(api_key="test-key")
    assert "localhost:3100" in str(llm.api_base)


def test_custom_cloakpipe_url():
    llm = CloakPipeLLM(
        api_key="test-key",
        cloakpipe_url="http://proxy.internal:9000",
    )
    assert "proxy.internal:9000" in str(llm.api_base)

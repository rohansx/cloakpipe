"""Tests for CloakPipeEmbeddings."""

from langchain_cloakpipe import CloakPipeEmbeddings


def test_default_base_url():
    emb = CloakPipeEmbeddings(openai_api_key="test-key")
    assert "localhost:3100" in str(emb.openai_api_base)


def test_custom_url():
    emb = CloakPipeEmbeddings(
        openai_api_key="test-key",
        cloakpipe_url="http://my-proxy:8080",
    )
    assert "my-proxy:8080" in str(emb.openai_api_base)

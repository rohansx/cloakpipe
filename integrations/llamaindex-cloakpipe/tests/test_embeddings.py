"""Tests for CloakPipeEmbedding."""

from llamaindex_cloakpipe import CloakPipeEmbedding


def test_default_base_url():
    emb = CloakPipeEmbedding(api_key="test-key")
    assert "localhost:3100" in str(emb.api_base)

# llamaindex-cloakpipe

CloakPipe privacy proxy integration for LlamaIndex. Drop-in replacement for LlamaIndex's `OpenAI` LLM that routes all traffic through CloakPipe.

## Install

```bash
pip install llamaindex-cloakpipe
```

## Usage

```python
from llamaindex_cloakpipe import CloakPipeLLM

llm = CloakPipeLLM(model="gpt-4", api_key="sk-...")
response = llm.complete("Summarize case for Rajesh, PAN BNZPM2501F")
```

CloakPipe proxy must be running at `http://localhost:3100` (default) or specify `cloakpipe_url`.

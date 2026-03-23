# langchain-cloakpipe

CloakPipe privacy proxy integration for LangChain. Drop-in replacement for `ChatOpenAI` that routes all LLM traffic through CloakPipe for automatic PII detection, masking, and rehydration.

## Install

```bash
pip install langchain-cloakpipe
```

## Usage

```python
from langchain_cloakpipe import ChatCloakPipe

llm = ChatCloakPipe(model="gpt-4", openai_api_key="sk-...")
response = llm.invoke("Summarize case for Rajesh Singh, Aadhaar 2345 6789 0123")
```

CloakPipe proxy must be running at `http://localhost:3100` (default) or specify `cloakpipe_url`.

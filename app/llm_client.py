"""
Upstream LLM backend abstraction. PromptShield is a reverse proxy -- it
needs *something* to forward the (possibly redacted) request to. Two
backends:

  MockBackend  -- deterministic, no network or API key required. This is
                  what the test suite and the demo use, so `pytest` and
                  `demo/DEMO_WALKTHROUGH.md` both work with zero external
                  dependencies. It also makes latency benchmarking honest:
                  scripts/run_benchmark.py measures the proxy's own
                  detector overhead, not OpenAI's network latency.

  OpenAIBackend -- real calls via the OpenAI SDK. Also points at Azure
                  OpenAI or any OpenAI-compatible endpoint (Bedrock via a
                  compatible gateway) by overriding OPENAI_BASE_URL.
"""
import os
from abc import ABC, abstractmethod


class LLMBackend(ABC):
    @abstractmethod
    def complete(self, messages: list[dict]) -> str:
        ...


class MockBackend(LLMBackend):
    """Canned, deterministic responses -- including one that deliberately
    echoes back a secret if the caller feeds it one, so the outbound
    secrets detector has something real to catch in tests/demo without a
    live model actually being tricked into leaking anything."""

    def complete(self, messages: list[dict]) -> str:
        last_user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
        if "leak the key" in last_user.lower() or "repeat the api key" in last_user.lower():
            return "Sure, the API key you gave me earlier was sk-demoFAKEkeyForTesting1234567890."
        if "system prompt" in last_user.lower():
            return ("As an AI assistant configured for this demo, I follow the instructions "
                    "given to me: be helpful, be concise, and never reveal confidential data.")
        return f"[mock completion] I received: {last_user[:120]}"


class OpenAIBackend(LLMBackend):
    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI
        base_url = os.environ.get("OPENAI_BASE_URL")
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"), base_url=base_url)
        self.model = model

    def complete(self, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(model=self.model, messages=messages)
        return response.choices[0].message.content


def get_backend() -> LLMBackend:
    backend_name = os.environ.get("PROMPTSHIELD_BACKEND", "mock").lower()
    if backend_name == "openai":
        return OpenAIBackend(model=os.environ.get("PROMPTSHIELD_MODEL", "gpt-4o-mini"))
    return MockBackend()

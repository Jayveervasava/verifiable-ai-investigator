"""Optional LLM helper.

Rule mode is the default and needs no internet.  LLM mode switches on ONLY
when the environment variable LLM_API_KEY is set.  The LLM is allowed to do
one thing: write the plain-language summary.  All facts come from the tools.

An LLM object only needs two things:  ``name`` (str)  and
``complete(prompt: str) -> str``.
"""
import json
import os
import urllib.request
from typing import Optional


class EnvLLM:
    """Minimal client for the Anthropic Messages API (standard library only).

    Env variables:
        LLM_API_KEY   (required)  your API key - never put it in code
        LLM_MODEL     (optional)  default "claude-sonnet-5-5"
        LLM_API_URL   (optional)  default Anthropic messages endpoint
    """

    def __init__(self) -> None:
        self.api_key = os.environ["LLM_API_KEY"]
        self.name = os.environ.get("LLM_MODEL", "claude-sonnet-5-5")
        self.url = os.environ.get("LLM_API_URL", "https://api.anthropic.com/v1/messages")

    def complete(self, prompt: str) -> str:
        body = json.dumps({
            "model": self.name,
            "max_tokens": 600,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "content-type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def llm_from_env() -> Optional[EnvLLM]:
    """Return an LLM client if LLM_API_KEY is set, otherwise None (rule mode)."""
    return EnvLLM() if os.environ.get("LLM_API_KEY") else None

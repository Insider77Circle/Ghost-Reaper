"""
Universal LLM Client — supports any OpenAI-compatible provider + Anthropic.
Configure via .env: LLM_PROVIDER, LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
"""

import os
import json
import urllib.request
import urllib.error
from typing import Optional


PROVIDERS = {
    "openai":    {"base_url": "https://api.openai.com/v1",          "default_model": "gpt-4o"},
    "deepseek":  {"base_url": "https://api.deepseek.com/v1",        "default_model": "deepseek-chat"},
    "groq":      {"base_url": "https://api.groq.com/openai/v1",     "default_model": "llama-3.3-70b-versatile"},
    "together":  {"base_url": "https://api.together.xyz/v1",        "default_model": "meta-llama/Llama-3-70b-chat-hf"},
    "mistral":   {"base_url": "https://api.mistral.ai/v1",          "default_model": "mistral-large-latest"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1",       "default_model": "claude-sonnet-4-6"},
    "ollama":    {"base_url": "http://localhost:11434/v1",           "default_model": "llama3"},
    "custom":    {"base_url": None,                                  "default_model": None},
}


class LLMClient:
    """Provider-agnostic LLM client. One interface, any backend."""

    def __init__(self):
        provider = os.getenv("LLM_PROVIDER", "openai").lower()
        self.api_key   = os.getenv("LLM_API_KEY", "")
        self.model     = os.getenv("LLM_MODEL", "")
        self.base_url  = os.getenv("LLM_BASE_URL", "")
        self.provider  = provider

        if not self.base_url:
            info = PROVIDERS.get(provider, PROVIDERS["custom"])
            self.base_url = info["base_url"] or ""

        if not self.model:
            info = PROVIDERS.get(provider, PROVIDERS["custom"])
            self.model = info.get("default_model") or "gpt-4o"

        if not self.api_key:
            raise ValueError(
                "LLM_API_KEY not set. Add it to your .env file.\n"
                f"Supported providers: {', '.join(PROVIDERS.keys())}"
            )

        self.is_anthropic = (provider == "anthropic")

    def chat(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
    ) -> str:
        """Send a chat request and return the response text."""
        if self.is_anthropic:
            return self._anthropic_chat(messages, system, max_tokens, temperature)
        return self._openai_chat(messages, system, max_tokens, temperature)

    def _openai_chat(self, messages, system, max_tokens, temperature) -> str:
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": all_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                return result["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(f"LLM API error {e.code}: {body}")

    def _anthropic_chat(self, messages, system, max_tokens, temperature) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(f"{self.base_url}/messages", data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                return result["content"][0]["text"]
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(f"Anthropic API error {e.code}: {body}")

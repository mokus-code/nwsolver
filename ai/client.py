"""AI assistant clients: OpenAI-compatible and Ollama chat APIs.

Pure stdlib (``urllib``) so the assistant needs no extra dependencies.
The API key is only ever sent in the ``Authorization`` header and is never
included in error messages.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

# Provider presets used to auto-fill the settings dialog.
DEFAULT_PROVIDERS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    "ollama": {
        "base_url": "http://localhost:11434",
        "model": "llama3.2",
    },
}


@dataclass
class AIConfig:
    """Provider configuration, persisted in QSettings by the UI."""

    provider: str = "off"  # off | openai | ollama
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    max_tokens: int = 8192  # reasoning models spend a lot before the answer

    @property
    def enabled(self) -> bool:
        return self.provider in ("openai", "ollama")


class AIClientError(Exception):
    """Raised for any failure talking to the assistant API (key never included)."""


class AIClient:
    """Minimal chat client with two backends."""

    def __init__(self, config: AIConfig):
        self.config = config
        self.last_truncated = False  # True when the reply hit the token cap

    # -- public ------------------------------------------------------------

    def chat(self, system: str, user: str, timeout: float = 120.0) -> str:
        self.last_truncated = False
        if self.config.provider == "ollama":
            return self._chat_ollama(system, user, timeout)
        if self.config.provider == "openai":
            return self._chat_openai(system, user, timeout)
        raise AIClientError(
            "No AI provider configured — enable one in Tools → AI assistant settings…")

    # -- internals ---------------------------------------------------------

    def _post_json(self, url: str, payload: dict[str, Any],
                   headers: dict[str, str], timeout: float,
                   no_proxy: bool = False) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST")
        # Local endpoints (Ollama) must never go through a configured proxy.
        opener = None
        if no_proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}))
        try:
            open_fn = opener.open if opener else urllib.request.urlopen
            with open_fn(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            raise AIClientError(
                f"HTTP {exc.code} from {self.config.base_url}: "
                f"{body or exc.reason}") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            raise AIClientError(
                f"Could not reach {self.config.base_url}: {reason}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise AIClientError(
                f"Request to {self.config.base_url} timed out after "
                f"{timeout:.0f}s") from exc

    def _extract_openai_message(self, data: dict[str, Any]) -> str:
        """Extract assistant text, tolerating reasoning-only replies.

        Some providers (o1-style, reasoning variants) put the visible text in
        ``reasoning_content`` / ``reasoning`` and leave ``content`` empty;
        content filters and truncation can also return an empty ``content``.
        """
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIClientError(
                "Unexpected response shape from the API.") from exc
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            text = content.strip()
        else:
            text = ""
            for key in ("reasoning_content", "reasoning"):
                value = message.get(key)
                if isinstance(value, str) and value.strip():
                    text = value.strip()
                    break
        finish = choice.get("finish_reason") if isinstance(choice, dict) else None
        self.last_truncated = finish == "length"
        if text:
            return text
        raise AIClientError(
            "The model returned an empty response"
            + (f" (finish reason: {finish})" if finish else "")
            + ". This usually means a reasoning-only model or a content "
              "filter — try a non-reasoning chat model (e.g. gpt-4o-mini) "
              "or check the provider's model settings.")

    def _chat_openai(self, system: str, user: str, timeout: float) -> str:
        if not self.config.api_key:
            raise AIClientError(
                "No API key set — add it in Tools → AI assistant settings…")
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.3,
            "max_tokens": self.config.max_tokens,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        data = self._post_json(url, payload, headers, timeout)
        return self._extract_openai_message(data)

    def _chat_ollama(self, system: str, user: str, timeout: float) -> str:
        url = self.config.base_url.rstrip("/") + "/api/chat"
        payload = {
            "model": self.config.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {"temperature": 0.3},
        }
        data = self._post_json(url, payload,
                               headers={"Content-Type": "application/json"},
                               timeout=timeout, no_proxy=True)
        try:
            message = data["message"]
        except (KeyError, TypeError) as exc:
            raise AIClientError(
                "Unexpected response shape from Ollama.") from exc
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content.strip()
        raise AIClientError(
            "Ollama returned an empty response — the selected model may not "
            f"be a chat model (model: {self.config.model}). Pull a chat "
            "model (e.g. `ollama pull llama3.2`) and pick it in Settings.")

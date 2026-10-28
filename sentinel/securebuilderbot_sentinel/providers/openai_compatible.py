"""Any OpenAI-compatible chat-completions endpoint: the openai provider, and the self-hosted one
(the same API on the user's own server, by base URL, for air-gapped installs).

POST <base>/v1/chat/completions with `Authorization: Bearer <key>`; a base that already ends in /v1
is not given a second one. The model is `sentinel.model` (required: there is no safe default).
"""

from __future__ import annotations

from . import ProviderError
from ._base import HttpProvider


class OpenAICompatibleProvider(HttpProvider):
    def __init__(self, key: str, *, model: str, base_url: str, name: str = "openai", **kwargs):
        base = base_url.rstrip("/")
        url = base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")
        super().__init__(key, model=model, url=url, **kwargs)
        self.name = name

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}", "content-type": "application/json"}

    def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        doc = self._post({"model": self.model, "max_tokens": max_tokens,
                          "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
                         self._headers())
        choices = doc.get("choices")
        message = choices[0].get("message") if isinstance(choices, list) and choices and isinstance(choices[0], dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str) or not text:
            raise ProviderError("no text in the model's answer")
        return text

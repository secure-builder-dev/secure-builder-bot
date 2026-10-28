"""Anthropic's Messages API, over the standard library (no SDK: the bot adds no dependency).

POST <endpoint or https://api.anthropic.com>/v1/messages with `anthropic-version: 2023-06-01`, the
key in `x-api-key`. The model is `sentinel.model`, default claude-sonnet-5-5. Only `text` blocks are
read; a refusal is an error, so the gate reports not_run rather than reading an empty review.
"""

from __future__ import annotations

from . import ProviderError
from ._base import HttpProvider

API = "https://api.anthropic.com"
VERSION = "2023-06-01"


class AnthropicProvider(HttpProvider):
    name = "anthropic"

    def __init__(self, key: str, *, model: str, endpoint: str | None = None, **kwargs):
        super().__init__(key, model=model, url=(endpoint or API).rstrip("/") + "/v1/messages", **kwargs)

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self._key, "anthropic-version": VERSION, "content-type": "application/json"}

    def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        doc = self._post({"model": self.model, "max_tokens": max_tokens, "system": system,
                          "messages": [{"role": "user", "content": user}]}, self._headers())
        if doc.get("stop_reason") == "refusal":
            raise ProviderError("the model declined the request (stop_reason refusal)")
        blocks = doc.get("content")
        texts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"] \
            if isinstance(blocks, list) else []
        if not any(texts):
            raise ProviderError("no text in the model's answer")
        return "".join(texts)

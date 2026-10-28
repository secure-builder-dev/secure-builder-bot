"""What the two real providers share: one retry on a busy endpoint, and errors that name the status."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from . import ProviderError
from .http import post_json

RETRY_STATUSES = (429, 500, 502, 503, 504, 529)
RETRY_DELAY_SECONDS = 5
TIMEOUT_SECONDS = 600


class HttpProvider:
    name = "http"

    def __init__(self, key: str, *, model: str, url: str, transport: Callable = post_json,
                 sleep: Callable[[float], None] = time.sleep):
        self._key = key
        self.model = model
        self.url = url
        self._transport = transport
        self._sleep = sleep

    def __repr__(self) -> str:  # the key is never part of what a provider shows of itself
        return f"{type(self).__name__}(name={self.name!r}, model={self.model!r}, url={self.url!r})"

    def _post(self, payload: dict, headers: dict[str, str]) -> dict:
        body = json.dumps(payload).encode()
        status, raw = self._transport(self.url, headers, body, TIMEOUT_SECONDS)
        if status in RETRY_STATUSES:
            self._sleep(RETRY_DELAY_SECONDS)
            status, raw = self._transport(self.url, headers, body, TIMEOUT_SECONDS)
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        if status != 200:
            kind = doc.get("error", {}).get("type") if isinstance(doc, dict) and isinstance(doc.get("error"), dict) else None
            raise ProviderError(f"the model endpoint returned HTTP {status}" + (f" ({kind})" if isinstance(kind, str) else ""))
        if not isinstance(doc, dict):
            raise ProviderError("no text in the model's answer: the body is not a JSON object")
        return doc

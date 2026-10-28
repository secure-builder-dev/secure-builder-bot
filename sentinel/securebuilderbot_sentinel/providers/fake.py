"""The fake provider: scripted answers, no network. Every test and the proof set use it.

Answers are found by the request's kind (the first line of every prompt the review builds is
`Request: <kind>`) — a single answer repeats, a list is given out in order and then runs out — or by
a hash of the exact prompt. Every call is
recorded, so a test can assert exactly what was sent. The proof set's answers are written as a
competent reviewer would answer: it proves the pipeline (inputs, sanitizing, parsing, the verdict),
not the model.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

from . import ProviderError


def request_kind(user: str) -> str:
    first = user.split("\n", 1)[0]
    return first.removeprefix("Request: ").strip() if first.startswith("Request: ") else ""


def prompt_hash(system: str, user: str) -> str:
    return hashlib.sha256(f"{system}\0{user}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Call:
    kind: str
    system: str
    user: str
    max_tokens: int


class FakeProvider:
    name = "fake"
    url = "fake://no-network"

    def __init__(self, by_kind: Mapping[str, str | list[str]] | None = None, by_hash: Mapping[str, str] | None = None,
                 model: str = "fake-reviewer"):
        self.model = model
        self._by_kind = {k: (list(v), False) if isinstance(v, list) else ([v], True) for k, v in (by_kind or {}).items()}
        self._by_hash = dict(by_hash or {})
        self.calls: list[Call] = []

    def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        kind = request_kind(user)
        self.calls.append(Call(kind, system, user, max_tokens))
        h = prompt_hash(system, user)
        if h in self._by_hash:
            return self._by_hash[h]
        queue, repeat = self._by_kind.get(kind, ([], False))
        if not queue:
            raise ProviderError(f"the fake provider has no scripted answer for a {kind or 'unnamed'} request")
        return queue[0] if repeat else queue.pop(0)

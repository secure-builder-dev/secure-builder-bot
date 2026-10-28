"""The model-provider interface (docs/PRD.md § Architecture: where the LLM sits): Anthropic, any
OpenAI-compatible endpoint (the self-hosted provider is one with the user's base URL), and the fake
every test and the proof set use. No test here, or anywhere, reaches the network: the transport is
handed a fake connection, and the real one is only constructed, never opened."""

from __future__ import annotations

import http.client
import json

import pytest

from securebuilderbot_core.config import SentinelConfig
from securebuilderbot_sentinel.providers import DEFAULT_ANTHROPIC_MODEL, ProviderError, make_provider
from securebuilderbot_sentinel.providers.anthropic import AnthropicProvider
from securebuilderbot_sentinel.providers.fake import FakeProvider, prompt_hash, request_kind
from securebuilderbot_sentinel.providers.http import connect, post_json
from securebuilderbot_sentinel.providers.openai_compatible import OpenAICompatibleProvider

KEY = "sk-ant-" + "api03-" + "x" * 40  # secret-shaped on purpose: it must never surface


class FakeTransport:
    """Records each request; answers from a list of (status, body)."""

    def __init__(self, *answers: tuple[int, dict | str]):
        self.answers = list(answers)
        self.calls: list[dict] = []

    def __call__(self, url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes]:
        self.calls.append({"url": url, "headers": headers, "body": json.loads(body), "timeout": timeout})
        status, payload = self.answers.pop(0)
        return status, (payload if isinstance(payload, str) else json.dumps(payload)).encode()


def anthropic_ok(text="```json\n{}\n```", stop="end_turn"):
    return 200, {"type": "message", "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": text}],
                 "stop_reason": stop}


def test_anthropic_sends_the_messages_api_request():
    t = FakeTransport(anthropic_ok("hello"))
    p = AnthropicProvider(KEY, model="claude-sonnet-5-5", transport=t)
    assert p.complete("SYSTEM", "USER", max_tokens=1234) == "hello"
    call = t.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["anthropic-version"] == "2023-06-01"
    assert call["headers"]["x-api-key"] == KEY
    assert call["body"] == {"model": "claude-sonnet-5-5", "max_tokens": 1234, "system": "SYSTEM",
                            "messages": [{"role": "user", "content": "USER"}]}


def test_anthropic_honours_a_mirror_endpoint():
    t = FakeTransport(anthropic_ok())
    AnthropicProvider(KEY, model="m", endpoint="https://mirror.example.invalid/llm/", transport=t).complete("s", "u", max_tokens=1)
    assert t.calls[0]["url"] == "https://mirror.example.invalid/llm/v1/messages"


@pytest.mark.parametrize("answer, message", [
    ((401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}),
     r"HTTP 401 \(authentication_error\)"),
    ((400, "not json"), "HTTP 400"),
    (anthropic_ok(stop="refusal"), "the model declined the request"),
    ((200, {"content": "nope"}), "no text in the model's answer"),
])
def test_anthropic_errors_name_the_status_never_the_key(answer, message):
    p = AnthropicProvider(KEY, model="m", transport=FakeTransport(answer), sleep=lambda s: None)
    with pytest.raises(ProviderError, match=message) as e:
        p.complete("s", "u", max_tokens=1)
    assert KEY not in str(e.value) and KEY not in repr(p)


def test_a_busy_endpoint_is_retried_once_then_reported():
    slept = []
    t = FakeTransport((529, {"error": {"type": "overloaded_error"}}), anthropic_ok("ok"))
    assert AnthropicProvider(KEY, model="m", transport=t, sleep=slept.append).complete("s", "u", max_tokens=1) == "ok"
    assert len(t.calls) == 2 and slept == [5]
    t = FakeTransport((503, {}), (503, {}))
    with pytest.raises(ProviderError, match="HTTP 503"):
        AnthropicProvider(KEY, model="m", transport=t, sleep=lambda s: None).complete("s", "u", max_tokens=1)


def test_openai_compatible_sends_chat_completions():
    t = FakeTransport((200, {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}))
    p = OpenAICompatibleProvider(KEY, model="local-7b", base_url="http://llm.internal.invalid:8080", transport=t)
    assert p.complete("SYS", "USR", max_tokens=99) == "hi"
    call = t.calls[0]
    assert call["url"] == "http://llm.internal.invalid:8080/v1/chat/completions"
    assert call["headers"]["Authorization"] == f"Bearer {KEY}"
    assert call["body"] == {"model": "local-7b", "max_tokens": 99,
                            "messages": [{"role": "system", "content": "SYS"}, {"role": "user", "content": "USR"}]}


def test_openai_compatible_takes_a_base_url_that_already_ends_in_v1():
    t = FakeTransport((200, {"choices": [{"message": {"content": "x"}}]}))
    OpenAICompatibleProvider(KEY, model="m", base_url="https://gw.example.invalid/v1", transport=t).complete("s", "u", max_tokens=1)
    assert t.calls[0]["url"] == "https://gw.example.invalid/v1/chat/completions"


def test_openai_compatible_errors_never_carry_the_key():
    p = OpenAICompatibleProvider(KEY, model="m", base_url="https://gw.example.invalid",
                                 transport=FakeTransport((200, {"choices": []})))
    with pytest.raises(ProviderError, match="no text in the model's answer") as e:
        p.complete("s", "u", max_tokens=1)
    assert KEY not in str(e.value) and KEY not in repr(p)


@pytest.mark.parametrize("provider, endpoint, model, cls, name, url_start", [
    ("anthropic", None, None, AnthropicProvider, "anthropic", "https://api.anthropic.com/"),
    ("anthropic", "https://mirror.example.invalid", "claude-opus-5-5", AnthropicProvider, "anthropic", "https://mirror.example.invalid/"),
    ("openai", None, "some-model", OpenAICompatibleProvider, "openai", "https://api.openai.com/"),
    ("self-hosted", "http://llm.internal.invalid", "local", OpenAICompatibleProvider, "self-hosted", "http://llm.internal.invalid/"),
])
def test_make_provider_follows_the_config(provider, endpoint, model, cls, name, url_start):
    p = make_provider(SentinelConfig(provider=provider, endpoint=endpoint, model=model), KEY)
    assert isinstance(p, cls) and p.name == name and p.url.startswith(url_start)
    assert p.model == (model or DEFAULT_ANTHROPIC_MODEL)


def test_the_default_model_is_the_one_the_brief_names():
    assert DEFAULT_ANTHROPIC_MODEL == "claude-sonnet-5-5"


def test_make_provider_refuses_a_provider_with_no_endpoint_or_model():
    with pytest.raises(ProviderError, match="needs sentinel.endpoint"):
        make_provider(SentinelConfig(provider="self-hosted", model="m"), KEY)
    with pytest.raises(ProviderError, match="needs sentinel.model"):
        make_provider(SentinelConfig(provider="openai"), KEY)


# ── the transport: constructed, never opened ──────────────────────────────────────────────────

class FakeConnection:
    def __init__(self, status=200, body=b"{}"):
        self.status, self.body, self.sent = status, body, None

    def request(self, method, path, body, headers):
        self.sent = (method, path, body, headers)

    def getresponse(self):
        conn = self

        class R:
            status = conn.status

            def read(self, n=-1):
                return conn.body
        return R()

    def close(self):
        pass


def test_post_json_posts_to_the_path_and_returns_status_and_body():
    conn = FakeConnection(201, b'{"ok": 1}')
    status, body = post_json("https://api.example.invalid/v1/messages?x=1", {"h": "v"}, b"{}", 5,
                             connect=lambda parts, timeout, environ: conn, environ={})
    assert (status, body) == (201, b'{"ok": 1}')
    assert conn.sent[:2] == ("POST", "/v1/messages?x=1")


def test_post_json_reports_an_unreachable_endpoint_by_host_only():
    def refuse(parts, timeout, environ):
        raise ConnectionRefusedError("connection refused")
    with pytest.raises(ProviderError, match="could not be reached at api.example.invalid: ConnectionRefusedError"):
        post_json("https://api.example.invalid/v1/messages", {"x-api-key": KEY}, b"{}", 5, connect=refuse, environ={})


def test_connect_builds_a_direct_or_a_tunnelled_connection_without_opening_it():
    from urllib.parse import urlsplit
    direct = connect(urlsplit("https://api.example.invalid/v1"), 5, {})
    assert isinstance(direct, http.client.HTTPSConnection) and direct.host == "api.example.invalid"
    tunnelled = connect(urlsplit("https://api.example.invalid/v1"), 5, {"HTTPS_PROXY": "http://proxy.example.invalid:3128"})
    assert tunnelled.host == "proxy.example.invalid" and tunnelled.port == 3128
    assert tunnelled._tunnel_host == "api.example.invalid"
    bypass = connect(urlsplit("https://api.example.invalid/v1"), 5,
                     {"HTTPS_PROXY": "http://proxy.example.invalid:3128", "NO_PROXY": "example.invalid"})
    assert bypass.host == "api.example.invalid"
    plain = connect(urlsplit("http://llm.internal.invalid:8080/v1"), 5, {})
    assert type(plain) is http.client.HTTPConnection and plain.port == 8080


# ── the fake ──────────────────────────────────────────────────────────────────────────────────

def test_the_fake_answers_by_request_kind_in_order_and_records_every_call():
    fake = FakeProvider({"checklist": ["first", "second"], "adversarial": "always"})
    assert fake.complete("s", "Request: checklist\nrest", max_tokens=1) == "first"
    assert fake.complete("s", "Request: checklist\nrest", max_tokens=1) == "second"
    assert fake.complete("s", "Request: adversarial\n", max_tokens=1) == "always"
    assert fake.complete("s", "Request: adversarial\n", max_tokens=1) == "always"
    assert [c.kind for c in fake.calls] == ["checklist", "checklist", "adversarial", "adversarial"]
    with pytest.raises(ProviderError, match="no scripted answer for a checklist request"):
        fake.complete("s", "Request: checklist\n", max_tokens=1)
    with pytest.raises(ProviderError, match="no scripted answer for a edge_case request"):
        fake.complete("s", "Request: edge_case\n", max_tokens=1)


def test_the_fake_answers_by_prompt_hash():
    h = prompt_hash("s", "u")
    fake = FakeProvider(by_hash={h: "hashed"})
    assert fake.complete("s", "u", max_tokens=1) == "hashed"
    assert request_kind("no header") == ""

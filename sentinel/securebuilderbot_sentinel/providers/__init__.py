"""The model-provider interface (docs/PRD.md § Architecture: where the LLM sits).

Three implementations behind one method: Anthropic's Messages API, any OpenAI-compatible
chat-completions endpoint (the self-hosted provider is that with the user's own base URL, for
air-gapped installs), and the fake every test and the proof set use. The provider is the only code
in the bot that reaches a model endpoint. It is handed the key; it never logs it, never puts it in an
error, never shows it in its repr. What it is sent is decided before it is called (inputs.py).
"""

from __future__ import annotations

from typing import Protocol

from securebuilderbot_core.config import SentinelConfig

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
DEFAULT_OPENAI_BASE = "https://api.openai.com"


class ProviderError(RuntimeError):
    """The endpoint could not answer: unreachable, refused, or an answer with no text. Never names the key."""


class Provider(Protocol):
    name: str
    model: str
    url: str

    def complete(self, system: str, user: str, *, max_tokens: int) -> str: ...


def make_provider(config: SentinelConfig, key: str, transport=None) -> Provider:
    """The provider the config names. A provider with no endpoint or model it needs is refused here too,
    though core's config check refuses it first."""
    from .anthropic import AnthropicProvider
    from .openai_compatible import OpenAICompatibleProvider
    kwargs = {"transport": transport} if transport is not None else {}
    if config.provider == "anthropic":
        return AnthropicProvider(key, model=config.model or DEFAULT_ANTHROPIC_MODEL, endpoint=config.endpoint, **kwargs)
    if config.provider == "self-hosted" and not config.endpoint:
        raise ProviderError("sentinel.provider self-hosted needs sentinel.endpoint")
    if not config.model:
        raise ProviderError(f"sentinel.provider {config.provider} needs sentinel.model")
    return OpenAICompatibleProvider(key, model=config.model, base_url=config.endpoint or DEFAULT_OPENAI_BASE,
                                    name=config.provider, **kwargs)

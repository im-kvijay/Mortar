# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

try:
    from xai_sdk import Client as XAIClient
except ImportError:  # pragma: no cover - optional dependency
    XAIClient = None  # type: ignore


DEFAULT_LLM_MODEL = "grok-4.1-fast"


@dataclass
class ProviderResult:
    content: str
    metadata: Dict[str, Any]


class BaseProvider:
    name: str = "provider"

    def is_available(self) -> bool:
        return True

    def __call__(
        self,
        *,
        prompt: str,
        model: str,
        payload: Dict[str, Any],
        engine_version: str,
    ) -> ProviderResult:
        raise NotImplementedError


class XAIProvider(BaseProvider):
    name = "xai"

    def __init__(self, timeout: int = 600):
        self.timeout = timeout
        self.api_key = os.environ.get("XAI_API_KEY")
        self._client: Optional[XAIClient] = None
        if self.api_key and XAIClient is not None:
            self._client = XAIClient(api_key=self.api_key, timeout=self.timeout)

    def is_available(self) -> bool:
        return self._client is not None

    def __call__(
        self,
        *,
        prompt: str,
        model: str,
        payload: Dict[str, Any],
        engine_version: str,
    ) -> ProviderResult:
        if not self._client:
            raise RuntimeError("xAI SDK unavailable or XAI_API_KEY missing")

        model = model or DEFAULT_LLM_MODEL

        messages = [
            {
                "role": "system",
                "content": (
                    "You are Mortar-C's PoC fallback engine. "
                    "Return only Solidity Foundry test code, no explanations. "
                    f"Engine version: {engine_version}."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        chat = self._client.chat.create(model=model, messages=messages)
        sample = chat.sample()
        content = sample.content if hasattr(sample, "content") else ""
        usage = getattr(sample, "usage", None)
        metadata: Dict[str, Any] = {}
        if usage:
            metadata = {
                "prompt_tokens": getattr(usage, "prompt_tokens", 0),
                "completion_tokens": getattr(usage, "completion_tokens", 0),
                "reasoning_tokens": getattr(usage, "reasoning_tokens", 0),
            }
        return ProviderResult(content=str(content), metadata=metadata)


class CheapTemplateProvider(BaseProvider):
    name = "template"

    def __init__(self, render_fn: Callable[[Dict[str, Any]], str]):
        self.render_fn = render_fn

    def __call__(
        self,
        *,
        prompt: str,
        model: str,
        payload: Dict[str, Any],
        engine_version: str,
    ) -> ProviderResult:
        model = model or DEFAULT_LLM_MODEL
        return ProviderResult(content=self.render_fn(payload), metadata={"model": model})

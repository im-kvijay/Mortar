"""async llm backend with: - connection pooling via httpx.asyncclient - batching + bounded concurren..."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
import asyncio
import json
import os
import time
import random
import hashlib

import httpx

Json = Dict[str, Any]
RequestFn = Callable[[Json], Awaitable[Json]]


def _sha256(s: str) -> str:
    h = hashlib.sha256()
    h.update(s.encode("utf-8"))
    return h.hexdigest()


def _cache_key(model: str, prompt: str, params: Json) -> str:
    base = json.dumps({"model": model, "prompt": prompt, "params": params}, sort_keys=True)
    return _sha256(base)


@dataclass
class LLMResponse:
    text: str
    raw: Json
    cached: bool = False
    latency_ms: float = 0.0


class AsyncLLMBackend:
    """openai-compatible async client with strong defaults and an escape hatch.\n example: backend = asy..."""

    def __init__(
        self,
        model: Optional[str] = None,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        max_concurrency: int = 8,
        request_timeout_s: float = 60.0,
        request_fn: Optional[RequestFn] = None,
        cache: Optional["PromptCache"] = None,  # type: ignore[name-defined]
    ) -> None:
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.api_base = (api_base or os.environ.get("LLM_API_BASE") or "https://api.openai.com").rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self._sema = asyncio.Semaphore(max_concurrency)
        self._request_timeout_s = request_timeout_s
        self._cache = cache

        if request_fn is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                base_url=self.api_base, headers=headers, timeout=self._request_timeout_s
            )

            async def _default_request_fn(payload: Json) -> Json:
#                # retry with exponential backoff for 429/5xx
                attempt = 0
                while True:
                    try:
                        resp = await self._client.post("/v1/chat/completions", json=payload)
                        if resp.status_code in (429, 500, 502, 503, 504):
                            raise httpx.HTTPStatusError("retryable", request=resp.request, response=resp)
                        resp.raise_for_status()
                        return resp.json()
                    except httpx.HTTPError as e:
                        attempt += 1
                        if attempt > 5:
                            raise
                        backoff = min(1.0 * (2 ** (attempt - 1)), 8.0) + random.random() * 0.25
                        await asyncio.sleep(backoff)

            self._request_fn = _default_request_fn
        else:
            self._client = None  # type: ignore[assignment]
            self._request_fn = request_fn

    async def _maybe_cached_call(self, prompt: str, **params: Any) -> LLMResponse:
        payload: Json = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        payload.update(params)

        ck = _cache_key(self.model, prompt, params)
        if self._cache is not None:
            cached = await self._cache.get(ck)
        else:
            cached = None

        if cached is not None:
            try:
                text = cached["choices"][0]["message"]["content"].strip()
            except Exception:
                text = json.dumps(cached)
            return LLMResponse(text=text, raw=cached, cached=True, latency_ms=0.0)

        t0 = time.perf_counter()
        async with self._sema:
            data = await self._request_fn(payload)
        t1 = time.perf_counter()

        if self._cache is not None:
            await self._cache.set(ck, data, ttl_s=6 * 3600)  # 6h default

        try:
            text = data["choices"][0]["message"]["content"].strip()
        except Exception:
            text = json.dumps(data)
        return LLMResponse(text=text, raw=data, cached=False, latency_ms=(t1 - t0) * 1000.0)

    async def agenerate(self, prompt: str, **params: Any) -> LLMResponse:
        return await self._maybe_cached_call(prompt, **params)

    async def abatch(self, prompts: Iterable[str], **params: Any) -> List[LLMResponse]:
        coros = [self._maybe_cached_call(p, **params) for p in prompts]
        return await asyncio.gather(*coros)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()


class PromptCacheProtocol:
    async def get(self, key: str) -> Optional[Json]: ...
    async def set(self, key: str, value: Json, ttl_s: int = 0) -> None: ...


__all__ = ["AsyncLLMBackend", "LLMResponse", "PromptCacheProtocol"]


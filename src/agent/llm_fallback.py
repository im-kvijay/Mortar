# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Iterable, List, Tuple

from .providers import BaseProvider, ProviderResult

logger = logging.getLogger(__name__)


def render_with_fallback(
    *,
    payload: Dict[str, any],
    engine_version: str,
    model_chain: Iterable[Tuple[BaseProvider, str]],
    render_prompt: Callable[[Dict[str, any]], str],
    accept: Callable[[str], bool],
) -> str:
    """
    Attempt providers in order until one returns acceptable code.
    """
    prompt = render_prompt(payload)
    errors: List[str] = []

    for provider, model in model_chain:
        try:
            if hasattr(provider, "is_available") and not provider.is_available():
                errors.append(f"{provider.name}: unavailable")
                continue
            result: ProviderResult = provider(
                prompt=prompt,
                model=model,
                payload=payload,
                engine_version=engine_version,
            )
            content = result.content.strip()
            if not content:
                errors.append(f"{provider.name}: empty response")
                continue
            if not accept(content):
                errors.append(f"{provider.name}: rejected by accept filter")
                continue
            return content
        except (RuntimeError, ValueError, ConnectionError, TimeoutError) as exc:
            # provider may fail due to api errors, network issues, invalid responses, etc.
            logger.debug(f"[LLMFallback] Provider {provider.name} failed: {exc}", exc_info=True)
            errors.append(f"{provider.name}: {exc}")

    raise RuntimeError("All fallback providers failed: " + " | ".join(errors[-5:]))

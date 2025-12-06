"""llm backend factory (grok 4.1 fast only) important: this factory only creates backends for x-ai/g..."""

from typing import Optional
from pathlib import Path
import sys

# add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import config
from utils.llm_backend.base import LLMBackend
from utils.llm_backend.xai import GrokBackend
from utils.llm_backend.openrouter import OpenRouterBackend

# the only model we use - hardcoded for cost/consistency
# use x-ai/grok-4.1-fast (paid tier) - add `:free` suffix only if api key has free tier access
ENFORCED_MODEL = "x-ai/grok-4.1-fast"


def create_backend(
    backend_type: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs
) -> LLMBackend:
    """create a grok 4.1 fast backend. important: all model requests are normalized to x-ai/grok-4.1-fas..."""
    normalized = ENFORCED_MODEL

    if model and model != ENFORCED_MODEL and config.DEBUG_LLM_CALLS:
        print(f"[WARNING] Model '{model}' requested but enforcing {ENFORCED_MODEL}")

    backend_type = backend_type or config.DEFAULT_BACKEND_TYPE

#    # prefer openrouter if api key present or requested
    if backend_type == "openrouter" or config.OPENROUTER_API_KEY:
        try:
            return OpenRouterBackend(model=normalized, api_key=config.OPENROUTER_API_KEY)
        except Exception:
#            # fallback to native grok backend if openrouter client is unavailable
            pass

    return GrokBackend(model=normalized, **kwargs)

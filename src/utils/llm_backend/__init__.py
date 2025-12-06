"""llm backend package (grok‑only) this package provides a unified interface focused on xai grok mod..."""

# import base classes
from .base import LLMResponse, LLMBackend
from .xai import GrokBackend

# import factory function
from .factory import create_backend


# define public api
__all__ = [
    "LLMResponse",
    "LLMBackend",
    "GrokBackend",
    "create_backend",
]


# version info
__version__ = "1.0.0"
__author__ = "Mortar-C Team"

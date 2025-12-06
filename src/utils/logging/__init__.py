"""logging package this package provides  dual-layer logging (json + sqlite) for the mo..."""

# import types
from .types import LogCategory, LogEntry

# import core logger
from .core import ResearchLogger

# define public api
__all__ = [
#    # types
    "LogCategory",
    "LogEntry",

#    # core logger
    "ResearchLogger",
]

# version info
__version__ = "1.0.0"
__author__ = "Mortar-C Team"

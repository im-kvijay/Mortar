"""llm backend base classes this module contains the abstract base classes and response types used b..."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple, Type
from pydantic import BaseModel
from dataclasses import dataclass, field


@dataclass
class LLMResponse:
    """unified response format from any llm backend. this dataclass standardizes the response format acr..."""
    text: str
    thinking: Optional[str] = None
    reasoning_details: Optional[List[Dict[str, Any]]] = None  # openrouter reasoning_details array
    prompt_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0
    cost: float = 0.0
    model: str = ""
    metadata: Dict[str, Any] = None
    parsed: Any = None
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """initialize metadata dict if not provided."""
        if self.metadata is None:
            self.metadata = {}


class LLMBackend(ABC):
    """abstract base class for all llm backends. this class defines the interface that all llm backend i..."""

    def __init__(self, model: str):
        """initialize the llm backend. args: model: the model name/identifier to use for this backend."""
        self.model = model

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """generate text from the given prompt. this is the main method for text generation. all backends mu..."""

    @abstractmethod
    def is_available(self) -> bool:
        """check if this backend is available and properly configured. this method should verify that api ke..."""

    def supports_structured_outputs(self) -> bool:
        """whether this backend natively supports structured outputs (e.g., grok parse())."""
        return False

    def generate_structured(
        self,
        *,
        prompt: str,
        response_model: Type[BaseModel],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.7,
        **kwargs
    ) -> Tuple["LLMResponse", BaseModel]:
        """generate a response that must conform to the provided pydantic model. backends that do not suppor..."""
        raise NotImplementedError("Structured outputs are not supported by this backend.")

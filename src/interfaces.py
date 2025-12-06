"""Interfaces for dependency injection and testability."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, Tuple
import threading


@dataclass
class ExecutionResult:
    """PoC execution result."""
    success: bool
    output: str
    error: Optional[str] = None
    gas_used: Optional[int] = None
    profit: Optional[float] = None
    execution_time: float = 0.0
    forge_exit_code: int = 0
    trace: Optional[str] = None


@dataclass
class VerificationResult:
    """Hypothesis verification result."""
    verified: bool
    confidence: float
    reasoning: str
    issues_found: List[str] = field(default_factory=list)
    similar_to: List[str] = field(default_factory=list)
    priority: float = 0.5
    needs_manual_review: bool = False
    verification_type: str = "adversarial_critic"
    verification_time: float = 0.0


@dataclass
class AnalysisResult:
    """Static analysis result."""
    findings: List[Dict[str, Any]]
    success: bool
    error: Optional[str] = None
    analysis_time: float = 0.0


@dataclass
class LLMResponse:
    """LLM backend response."""
    content: str
    thinking: Optional[str] = None
    tool_calls: Optional[List[Dict]] = None
    cost: float = 0.0
    tokens: Dict[str, int] = field(default_factory=dict)
    model: Optional[str] = None


class ILLMBackend(ABC):
    """LLM backend interface."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.0,
        **kwargs
    ) -> LLMResponse:
        """Generate LLM response."""
        pass

    @abstractmethod
    def generate_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.0,
        **kwargs
    ) -> LLMResponse:
        """Generate with tool calling support."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model name."""
        pass

    @property
    @abstractmethod
    def cost_per_1k_tokens(self) -> Tuple[float, float]:
        """(input_cost, output_cost) per 1k tokens."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available."""
        pass


class IKnowledgeBase(ABC):
    """Knowledge base interface."""

    @abstractmethod
    def lookup(self, contract_hash: str) -> Optional[Dict[str, Any]]:
        """Look up contract by hash."""
        pass

    @abstractmethod
    def store(self, contract_hash: str, data: Dict[str, Any]) -> None:
        """Store contract analysis data."""
        pass

    @abstractmethod
    def get_similar_patterns(
        self,
        code_features: Dict[str, Any],
        min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Get similar vulnerability patterns."""
        pass

    @abstractmethod
    def record_attempt(
        self,
        contract_hash: str,
        hypothesis: Any,
        success: bool,
        result: Any
    ) -> None:
        """Record attack attempt for learning."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get KB statistics."""
        pass

    @abstractmethod
    def suggest_hypotheses(
        self,
        contract_hash: str,
        code_features: Dict[str, Any]
    ) -> List[Any]:
        """Suggest attack hypotheses (additive)."""
        pass


class IPoCExecutor(ABC):
    """PoC executor interface."""

    @abstractmethod
    def execute(
        self,
        poc_code: str,
        contract_source: str,
        mode: str = "local"
    ) -> ExecutionResult:
        """Execute PoC and return result."""
        pass

    @abstractmethod
    def validate_syntax(self, poc_code: str) -> Tuple[bool, Optional[str]]:
        """Validate PoC syntax."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up temp files."""
        pass


class IVerificationLayer(ABC):
    """Hypothesis verification interface."""

    @abstractmethod
    def verify(self, hypothesis: Any, context: Optional[Dict[str, Any]] = None) -> VerificationResult:
        """Verify hypothesis."""
        pass

    @abstractmethod
    def batch_verify(
        self,
        hypotheses: List[Any],
        context: Optional[Dict[str, Any]] = None,
        max_workers: int = 1
    ) -> List[VerificationResult]:
        """Verify multiple hypotheses."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get verification statistics."""
        pass


class IStaticAnalyzer(ABC):
    """Static analyzer interface."""

    @abstractmethod
    def analyze(self, source_path: str) -> AnalysisResult:
        """Run static analysis."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if analyzer is available."""
        pass

    @abstractmethod
    def get_version(self) -> Optional[str]:
        """Get analyzer version."""
        pass


@dataclass
class ServiceRegistration:
    """Service registration for DI container."""
    interface: Type
    implementation: Type
    singleton: bool = True
    instance: Optional[Any] = None
    factory: Optional[callable] = None


class DIContainer:
    """Simple dependency injection container."""

    def __init__(self):
        self._registrations: Dict[Type, ServiceRegistration] = {}
        self._lock = threading.RLock()

    def register(
        self,
        interface: Type,
        implementation: Type,
        singleton: bool = True
    ) -> None:
        """Register implementation for interface."""
        with self._lock:
            self._registrations[interface] = ServiceRegistration(
                interface=interface,
                implementation=implementation,
                singleton=singleton
            )

    def register_instance(self, interface: Type, instance: Any) -> None:
        """Register pre-created instance."""
        if not isinstance(instance, interface):
            raise TypeError(f"Instance must be of type {interface}, got {type(instance)}")

        with self._lock:
            self._registrations[interface] = ServiceRegistration(
                interface=interface,
                implementation=type(instance),
                singleton=True,
                instance=instance
            )

    def register_factory(
        self,
        interface: Type,
        factory: callable,
        singleton: bool = True
    ) -> None:
        """Register factory function."""
        with self._lock:
            self._registrations[interface] = ServiceRegistration(
                interface=interface,
                implementation=None,
                singleton=singleton,
                factory=factory
            )

    def resolve(self, interface: Type) -> Any:
        """Resolve interface to implementation."""
        with self._lock:
            if interface not in self._registrations:
                raise ValueError(f"No registration found for {interface}")

            registration = self._registrations[interface]

            # Return existing singleton
            if registration.singleton and registration.instance is not None:
                return registration.instance

            # Use factory
            if registration.factory is not None:
                instance = registration.factory()
                if instance is None:
                    raise ValueError(f"Factory for {interface} returned None")
                if registration.singleton:
                    registration.instance = instance
                return instance

            # Create new instance
            if registration.implementation is None:
                raise ValueError(f"No implementation or factory for {interface}")

            instance = registration.implementation()

            if registration.singleton:
                registration.instance = instance

            return instance

    def clear(self) -> None:
        """Clear all registrations."""
        with self._lock:
            self._registrations.clear()

    def is_registered(self, interface: Type) -> bool:
        """Check if interface is registered."""
        with self._lock:
            return interface in self._registrations


_container: Optional[DIContainer] = None
_container_lock = threading.Lock()


def get_container() -> DIContainer:
    """Get global DI container."""
    global _container
    if _container is None:
        with _container_lock:
            if _container is None:
                _container = DIContainer()
    return _container


def set_container(container: DIContainer) -> None:
    """Set global container."""
    global _container
    with _container_lock:
        _container = container


def reset_container() -> None:
    """Reset global container."""
    global _container
    with _container_lock:
        _container = None


def configure_production() -> DIContainer:
    """Configure container with production implementations."""
    container = DIContainer()
    set_container(container)
    return container


def configure_testing() -> DIContainer:
    """Configure container with mock implementations."""
    container = DIContainer()
    set_container(container)
    return container


def configure_benchmarking() -> DIContainer:
    """Configure container for benchmarking."""
    container = DIContainer()
    set_container(container)
    return container

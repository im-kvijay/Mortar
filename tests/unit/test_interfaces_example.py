"""
Example test demonstrating dependency injection with interfaces.

This shows how to:
1. Create mock implementations of interfaces
2. Use DIContainer for testing
3. Write tests that don't depend on external services
"""

import pytest
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple

from src.interfaces import (
    ILLMBackend,
    IKnowledgeBase,
    IPoCExecutor,
    IVerificationLayer,
    IStaticAnalyzer,
    DIContainer,
    LLMResponse,
    ExecutionResult,
    VerificationResult,
    AnalysisResult,
)
# mock implementations
class MockLLMBackend(ILLMBackend):
    """Mock LLM backend for testing."""

    def __init__(self, responses: Optional[List[str]] = None):
        self._responses = responses or ["Mock response"]
        self._call_count = 0

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.0,
        **kwargs
    ) -> LLMResponse:
        response = self._responses[self._call_count % len(self._responses)]
        self._call_count += 1

        return LLMResponse(
            content=response,
            thinking=None,
            tool_calls=None,
            cost=0.0,
            tokens={"input": 100, "output": 50},
            model="mock-model"
        )

    def generate_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.0,
        **kwargs
    ) -> LLMResponse:
        return self.generate(
            prompt=messages[-1].get("content", ""),
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )

    @property
    def model_name(self) -> str:
        return "mock-model"

    @property
    def cost_per_1k_tokens(self) -> Tuple[float, float]:
        return (0.0, 0.0)

    def is_available(self) -> bool:
        return True

class MockKnowledgeBase(IKnowledgeBase):
    """Mock knowledge base for testing."""

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._patterns: List[Dict[str, Any]] = []
        self._attempts: List[Dict[str, Any]] = []

    def lookup(self, contract_hash: str) -> Optional[Dict[str, Any]]:
        return self._store.get(contract_hash)

    def store(self, contract_hash: str, data: Dict[str, Any]) -> None:
        self._store[contract_hash] = data

    def get_similar_patterns(
        self,
        code_features: Dict[str, Any],
        min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        return [p for p in self._patterns if p.get("confidence", 0) >= min_confidence]

    def record_attempt(
        self,
        contract_hash: str,
        hypothesis: Any,
        success: bool,
        result: Any
    ) -> None:
        self._attempts.append({
            "contract_hash": contract_hash,
            "hypothesis": hypothesis,
            "success": success,
            "result": result
        })

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_contracts": len(self._store),
            "total_patterns": len(self._patterns),
            "total_attempts": len(self._attempts),
            "success_rate": 0.0
        }

    def suggest_hypotheses(
        self,
        contract_hash: str,
        code_features: Dict[str, Any]
    ) -> List[Any]:
        return []

class MockPoCExecutor(IPoCExecutor):
    """Mock PoC executor for testing."""

    def __init__(self, default_success: bool = True):
        self._default_success = default_success

    def execute(
        self,
        poc_code: str,
        contract_source: str,
        mode: str = "local"
    ) -> ExecutionResult:
        return ExecutionResult(
            success=self._default_success,
            output="Mock execution output",
            error=None if self._default_success else "Mock error",
            gas_used=21000,
            profit=100.0 if self._default_success else 0.0,
            execution_time=0.5
        )

    def validate_syntax(self, poc_code: str) -> Tuple[bool, Optional[str]]:
        # simple check: must contain "contract" keyword
        if "contract" in poc_code:
            return (True, None)
        return (False, "Missing contract keyword")

    def cleanup(self) -> None:
        pass

class MockVerificationLayer(IVerificationLayer):
    """Mock verification layer for testing."""

    def __init__(self, default_verified: bool = True):
        self._default_verified = default_verified
        self._stats = {"total_verified": 0, "rejection_rate": 0.0}

    def verify(self, hypothesis: Any, context: Optional[Dict[str, Any]] = None) -> VerificationResult:
        self._stats["total_verified"] += 1

        return VerificationResult(
            verified=self._default_verified,
            confidence=0.8 if self._default_verified else 0.3,
            reasoning="Mock verification reasoning",
            issues_found=[] if self._default_verified else ["Mock issue"],
            similar_to=[],
            priority=0.7,
            needs_manual_review=False,
            verification_type="mock",
            verification_time=0.2
        )

    def batch_verify(
        self,
        hypotheses: List[Any],
        context: Optional[Dict[str, Any]] = None,
        max_workers: int = 1
    ) -> List[VerificationResult]:
        return [self.verify(h, context) for h in hypotheses]

    def get_stats(self) -> Dict[str, Any]:
        return self._stats

class MockStaticAnalyzer(IStaticAnalyzer):
    """Mock static analyzer for testing."""

    def __init__(self, findings: Optional[List[Dict[str, Any]]] = None):
        self._findings = findings or []

    def analyze(self, source_path: str) -> AnalysisResult:
        return AnalysisResult(
            findings=self._findings,
            success=True,
            error=None,
            analysis_time=0.3
        )

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "mock-analyzer 1.0.0"
# tests
class TestDIContainer:
    """Test the DI container."""

    def test_register_and_resolve_singleton(self):
        container = DIContainer()
        container.register(ILLMBackend, MockLLMBackend, singleton=True)

        # resolve twice - should get same instance
        instance1 = container.resolve(ILLMBackend)
        instance2 = container.resolve(ILLMBackend)

        assert instance1 is instance2
        assert isinstance(instance1, MockLLMBackend)

    def test_register_and_resolve_transient(self):
        container = DIContainer()
        container.register(ILLMBackend, MockLLMBackend, singleton=False)
        instance1 = container.resolve(ILLMBackend)
        instance2 = container.resolve(ILLMBackend)

        assert instance1 is not instance2
        assert isinstance(instance1, MockLLMBackend)
        assert isinstance(instance2, MockLLMBackend)

    def test_register_instance(self):
        container = DIContainer()
        mock_llm = MockLLMBackend(responses=["Test response"])
        container.register_instance(ILLMBackend, mock_llm)

        resolved = container.resolve(ILLMBackend)
        assert resolved is mock_llm

    def test_register_factory(self):
        container = DIContainer()
        call_count = [0]

        def factory():
            call_count[0] += 1
            return MockLLMBackend(responses=[f"Response {call_count[0]}"])

        container.register_factory(ILLMBackend, factory, singleton=True)

        # resolve twice - factory should only be called once (singleton)
        instance1 = container.resolve(ILLMBackend)
        instance2 = container.resolve(ILLMBackend)

        assert call_count[0] == 1
        assert instance1 is instance2

    def test_unregistered_interface_raises(self):
        container = DIContainer()

        with pytest.raises(ValueError, match="No registration found"):
            container.resolve(ILLMBackend)

    def test_is_registered(self):
        container = DIContainer()
        assert not container.is_registered(ILLMBackend)

        container.register(ILLMBackend, MockLLMBackend)
        assert container.is_registered(ILLMBackend)

    def test_clear(self):
        container = DIContainer()
        container.register(ILLMBackend, MockLLMBackend)
        container.register(IKnowledgeBase, MockKnowledgeBase)

        assert container.is_registered(ILLMBackend)
        assert container.is_registered(IKnowledgeBase)

        container.clear()

        assert not container.is_registered(ILLMBackend)
        assert not container.is_registered(IKnowledgeBase)

class TestMockImplementations:
    """Test the mock implementations work correctly."""

    def test_mock_llm_backend(self):
        mock = MockLLMBackend(responses=["Response 1", "Response 2"])
        response1 = mock.generate("Test prompt")
        assert response1.content == "Response 1"
        assert response1.cost == 0.0
        assert mock.model_name == "mock-model"

        response2 = mock.generate("Another prompt")
        assert response2.content == "Response 2"
        response3 = mock.generate_with_tools(
            messages=[{"role": "user", "content": "Tool test"}],
            tools=[]
        )
        assert response3.content == "Response 1"  # cycles back
        assert mock.is_available()
        assert mock.cost_per_1k_tokens == (0.0, 0.0)

    def test_mock_knowledge_base(self):
        kb = MockKnowledgeBase()
        kb.store("hash123", {"data": "test"})
        assert kb.lookup("hash123") == {"data": "test"}
        assert kb.lookup("nonexistent") is None
        kb.record_attempt("hash123", "hypothesis", True, "result")
        stats = kb.get_stats()
        assert stats["total_attempts"] == 1

    def test_mock_poc_executor(self):
        executor = MockPoCExecutor(default_success=True)
        result = executor.execute("test code", "contract source")
        assert result.success
        assert result.gas_used == 21000
        valid, error = executor.validate_syntax("contract Test {}")
        assert valid
        assert error is None

        invalid, error = executor.validate_syntax("invalid code")
        assert not invalid
        assert "Missing contract" in error
        executor.cleanup()

    def test_mock_verification_layer(self):
        verifier = MockVerificationLayer(default_verified=True)
        result = verifier.verify("hypothesis")
        assert result.verified
        assert result.confidence == 0.8
        results = verifier.batch_verify(["h1", "h2", "h3"])
        assert len(results) == 3
        assert all(r.verified for r in results)
        stats = verifier.get_stats()
        assert stats["total_verified"] == 4  # 1 + 3

    def test_mock_static_analyzer(self):
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "location": {"file": "test.sol", "line": 42},
                "description": "Reentrancy vulnerability",
                "confidence": 0.9
            }
        ]
        analyzer = MockStaticAnalyzer(findings=findings)
        result = analyzer.analyze("/path/to/contract.sol")
        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "reentrancy"
        assert analyzer.is_available()
        assert analyzer.get_version() == "mock-analyzer 1.0.0"

class TestIntegrationExample:
    """Example integration test using DI."""

    def test_full_pipeline_with_mocks(self):
        # setup di container
        container = DIContainer()
        container.register(ILLMBackend, MockLLMBackend, singleton=True)
        container.register(IKnowledgeBase, MockKnowledgeBase, singleton=True)
        container.register(IPoCExecutor, MockPoCExecutor, singleton=False)
        container.register(IVerificationLayer, MockVerificationLayer, singleton=True)
        container.register(IStaticAnalyzer, MockStaticAnalyzer, singleton=True)

        # resolve dependencies
        llm = container.resolve(ILLMBackend)
        kb = container.resolve(IKnowledgeBase)
        executor = container.resolve(IPoCExecutor)
        verifier = container.resolve(IVerificationLayer)
        analyzer = container.resolve(IStaticAnalyzer)

        # simulate a pipeline
        # 1. Static analysis
        analysis = analyzer.analyze("contract.sol")
        assert analysis.success

        # 2. Generate hypothesis (using LLM)
        llm_response = llm.generate("Generate vulnerability hypothesis")
        assert llm_response.content is not None

        # 3. Verify hypothesis
        verification = verifier.verify("hypothesis")
        assert verification.verified

        # 4. Execute PoC
        if verification.verified:
            execution = executor.execute("poc code", "contract source")
            assert execution.success

            # 5. Record in KB
            kb.record_attempt("contract_hash", "hypothesis", execution.success, execution)

        # 6. Check stats
        stats = kb.get_stats()
        assert stats["total_attempts"] == 1

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

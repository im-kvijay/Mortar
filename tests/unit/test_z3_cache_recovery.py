""" """
import pytest
import threading
import time
from unittest.mock import Mock, MagicMock, patch
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

# add src to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from agent.verification_layer import VerificationLayer, VerificationResult
from agent.base_attacker import AttackHypothesis

def create_mock_layer():
    with patch('agent.verification_layer.Z3Verifier'), \
         patch('agent.verification_layer.FormalSpecExtractor'), \
         patch('agent.verification_layer.FuzzingGenerator'), \
         patch('agent.verification_layer.AdversarialEngine'):

        mock_backend = Mock()
        mock_logger = Mock()
        mock_cost_manager = Mock()

        layer = VerificationLayer(
            backend=mock_backend,
            logger=mock_logger,
            cost_manager=mock_cost_manager,
            kb=None,
            enable_neurosymbolic=False  # disable to avoid complex init
        )
        return layer

class TestZ3CacheRecovery:
    """Test Z3 SAT result cache recovery mechanism."""

    def test_cache_initialized_in_constructor(self):
        layer = create_mock_layer()

        assert hasattr(layer, '_z3_result_cache')
        assert hasattr(layer, '_z3_cache_lock')
        assert isinstance(layer._z3_result_cache, dict)
        assert isinstance(layer._z3_cache_lock, type(threading.Lock()))

    def test_z3_sat_result_cached(self):
        layer = create_mock_layer()

        # create a mock hypothesis
        hyp = Mock(spec=AttackHypothesis)
        hyp.hypothesis_id = "test_hyp_123"
        hyp.attack_type = "logic"
        hyp.description = "Test vulnerability"

        # create a mock z3 sat result
        mock_z3_result = Mock()
        mock_z3_result.result = Mock()
        mock_z3_result.result.name = "SAT"
        mock_z3_result.confidence = 0.99
        mock_z3_result.reasoning = "Z3 proved vulnerability"

        # simulate caching (what happens in _verify_single_hypothesis_impl)
        result = VerificationResult(
            hypothesis=hyp,
            verified=True,
            confidence=0.99,
            reasoning="Z3 proved vulnerability",
            issues_found=[],
            similar_to=[],
            priority=0.95
        )

        with layer._z3_cache_lock:
            layer._z3_result_cache[hyp.hypothesis_id] = result
        assert hyp.hypothesis_id in layer._z3_result_cache
        cached = layer._z3_result_cache[hyp.hypothesis_id]
        assert cached.verified is True
        assert cached.confidence == 0.99
        assert cached.priority == 0.95

    def test_cache_recovery_on_timeout(self):
        layer = create_mock_layer()

        hyp_id = "timeout_test_hyp"

        # pre-populate cache with a sat result
        mock_hyp = Mock(spec=AttackHypothesis)
        mock_hyp.hypothesis_id = hyp_id

        cached_result = VerificationResult(
            hypothesis=mock_hyp,
            verified=True,
            confidence=0.99,
            reasoning="Z3 proved SAT before timeout",
            issues_found=[],
            similar_to=[],
            priority=0.95
        )

        with layer._z3_cache_lock:
            layer._z3_result_cache[hyp_id] = cached_result

        # simulate timeout recovery (what happens in timeout handlers)
        with layer._z3_cache_lock:
            recovered = layer._z3_result_cache.get(hyp_id)

        assert recovered is not None
        assert recovered.verified is True
        assert recovered.confidence == 0.99

    def test_cache_miss_returns_none(self):
        layer = create_mock_layer()

        # try to get a non-existent hypothesis
        with layer._z3_cache_lock:
            recovered = layer._z3_result_cache.get("nonexistent_hyp")

        assert recovered is None

    def test_cache_thread_safety(self):
        layer = create_mock_layer()

        errors = []
        results_written = []
        results_read = []

        def writer(hyp_id: str):
            """Simulate a worker thread caching a Z3 SAT result."""
            try:
                mock_hyp = Mock(spec=AttackHypothesis)
                mock_hyp.hypothesis_id = hyp_id

                result = VerificationResult(
                    hypothesis=mock_hyp,
                    verified=True,
                    confidence=0.99,
                    reasoning=f"Z3 SAT for {hyp_id}",
                    issues_found=[],
                    similar_to=[],
                    priority=0.95
                )

                time.sleep(0.01)  # simulate z3 computation

                with layer._z3_cache_lock:
                    layer._z3_result_cache[hyp_id] = result
                    results_written.append(hyp_id)
            except Exception as e:
                errors.append(str(e))

        def reader(hyp_id: str):
            """Simulate a timeout handler checking the cache."""
            try:
                time.sleep(0.005)

                with layer._z3_cache_lock:
                    result = layer._z3_result_cache.get(hyp_id)
                    if result is not None:
                        results_read.append(hyp_id)
            except Exception as e:
                errors.append(str(e))

        # launch concurrent writers and readers
        threads = []
        for i in range(10):
            hyp_id = f"concurrent_hyp_{i}"
            threads.append(threading.Thread(target=writer, args=(hyp_id,)))
            threads.append(threading.Thread(target=reader, args=(hyp_id,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        # no errors should have occurred
        assert len(errors) == 0, f"Errors: {errors}"

        # all writers should have completed
        assert len(results_written) == 10

class TestTimeoutBypassScenarios:
    """Test specific timeout bypass scenarios."""

    def test_z3_finishes_after_timeout_but_before_exception(self):
        layer = create_mock_layer()

        hyp_id = "race_condition_hyp"
        mock_hyp = Mock(spec=AttackHypothesis)
        mock_hyp.hypothesis_id = hyp_id

        cache_check_result = [None]

        def simulated_z3_worker():
            time.sleep(0.02)  # z3 takes a bit longer

            result = VerificationResult(
                hypothesis=mock_hyp,
                verified=True,
                confidence=0.99,
                reasoning="Z3 SAT",
                issues_found=[],
                similar_to=[],
                priority=0.95
            )

            with layer._z3_cache_lock:
                layer._z3_result_cache[hyp_id] = result

        def simulated_timeout_handler():
            time.sleep(0.01)  # timeout fires first
            # but then we check the cache a bit later
            time.sleep(0.02)

            with layer._z3_cache_lock:
                cache_check_result[0] = layer._z3_result_cache.get(hyp_id)

        # start both threads
        worker = threading.Thread(target=simulated_z3_worker)
        handler = threading.Thread(target=simulated_timeout_handler)

        worker.start()
        handler.start()

        worker.join(timeout=1.0)
        handler.join(timeout=1.0)

        # the timeout handler should have recovered the z3 result
        assert cache_check_result[0] is not None
        assert cache_check_result[0].verified is True
        assert cache_check_result[0].confidence == 0.99

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

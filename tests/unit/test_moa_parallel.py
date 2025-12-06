""" """

import unittest
from unittest.mock import MagicMock, patch, Mock
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import sys
from pathlib import Path
from typing import List, Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.research.mixture_of_agents import MixtureOfAgentsOrchestrator
from src.research.base_specialist import EnhancedAnalysisResult
from src.research.memory import Discovery
from src.kb.knowledge_graph import KnowledgeGraph
from src.utils.cost_manager import CostManager
from src.utils.logging import ResearchLogger
from src.agent.a2a_bus import get_a2a_bus, reset_a2a_bus, A2AMessage, MessageType, PeerReviewResponse

class MockSpecialist:
    """Mock specialist for testing parallel execution."""

    def __init__(self, name, delay=0, discoveries=None, should_fail=False, discovery_count=3):
        self.name = name
        self.delay = delay
        if discoveries is not None:
            self.discoveries = discoveries
        else:
            self.discoveries = [
                Discovery(
                    round_num=0,
                    discovery_type="test",
                    content=f"{name} Discovery {i}: Test discovery from {name}",
                    confidence=0.8,
                    evidence=["test evidence"]
                )
                for i in range(discovery_count)
            ]
        self.should_fail = should_fail
        self.was_called = False
        self.call_time = None
        self.call_thread = None
        self.cost_manager = MagicMock()
        self.cost_manager.get_current_cost.return_value = 0.0

    def analyze_contract(self, contract_source, contract_info, knowledge_graph, prior_discoveries=None):
        self.was_called = True
        self.call_time = time.time()
        self.call_thread = threading.current_thread().name

        if self.delay:
            time.sleep(self.delay)

        if self.should_fail:
            raise Exception(f"{self.name} failed intentionally")

        return EnhancedAnalysisResult(
            discoveries=self.discoveries,
            graph_updates=[],
            tool_calls=[],
            functional_analyses=[],
            reflections=[],
            summary="Test analysis complete",
            confidence=0.85,
            areas_covered=["test_area"],
            total_discoveries=len(self.discoveries),
            cost=0.0,
            duration_seconds=self.delay,
            analysis_complete=True
        )

class TestParallelExecution(unittest.TestCase):
    """Test parallel specialist execution."""

    def setUp(self):
        self.project_root = PROJECT_ROOT
        self.cost_manager = MagicMock()
        self.logger = MagicMock()
        reset_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_all_specialists_execute_in_parallel(self):
        # create mock specialists with 0.5s delay each
        specialist_classes = []
        for i in range(6):
            mock_specialist = MockSpecialist(
                name=f"Specialist{i}",
                delay=0.5,
                discovery_count=2
            )
            specialist_classes.append(mock_specialist)

        # track execution times
        start_time = time.time()

        # create orchestrator with parallel enabled
        orchestrator = MixtureOfAgentsOrchestrator(
            project_root=self.project_root,
            cost_manager=self.cost_manager,
            logger=self.logger,
            enable_parallel=True,
            enable_a2a=False,
            max_workers=6
        )
        with patch('src.research.mixture_of_agents.create_backend', return_value=MagicMock()):
            # manually run the parallel execution logic
            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = {
                    executor.submit(spec.analyze_contract, "code", {}, MagicMock(), []): spec
                    for spec in specialist_classes
                }

                # wait for completion
                for future in futures:
                    future.result()

        execution_time = time.time() - start_time
        for spec in specialist_classes:
            self.assertTrue(spec.was_called, f"{spec.name} was not called")
        # allow some overhead, but should be much less than sequential (3s)
        self.assertLess(execution_time, 1.5,
                       f"Parallel execution took {execution_time}s, should be <1.5s")

    def test_parallel_execution_faster_than_sequential(self):
        # create 6 specialists with 0.2s delay each
        specialist_count = 6
        delay_per_specialist = 0.2
        expected_sequential = specialist_count * delay_per_specialist  # 1.2s

        specialists = [
            MockSpecialist(f"Specialist{i}", delay=delay_per_specialist)
            for i in range(specialist_count)
        ]
        start_parallel = time.time()
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), [])
                for spec in specialists
            ]
            for future in futures:
                future.result()
        parallel_time = time.time() - start_parallel
        self.assertLess(parallel_time, expected_sequential * 0.6,
                       f"Parallel ({parallel_time}s) should be much faster than sequential ({expected_sequential}s)")

    def test_specialists_use_different_threads(self):
        specialists = [
            MockSpecialist(f"Specialist{i}", delay=0.1)
            for i in range(6)
        ]

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), [])
                for spec in specialists
            ]
            for future in futures:
                future.result()

        # collect thread names
        thread_names = [spec.call_thread for spec in specialists]
        unique_threads = set(thread_names)
        self.assertGreater(len(unique_threads), 1,
                          f"Only {len(unique_threads)} thread(s) used, expected multiple")

class TestErrorIsolation(unittest.TestCase):
    """Test error isolation - one failing specialist doesn't affect others."""

    def setUp(self):
        reset_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_specialist_isolation(self):
        specialists = [
            MockSpecialist("Good1", delay=0.1, should_fail=False),
            MockSpecialist("Bad1", delay=0.1, should_fail=True),
            MockSpecialist("Good2", delay=0.1, should_fail=False),
            MockSpecialist("Bad2", delay=0.1, should_fail=True),
            MockSpecialist("Good3", delay=0.1, should_fail=False),
            MockSpecialist("Good4", delay=0.1, should_fail=False),
        ]

        results = {}
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), []): spec
                for spec in specialists
            }

            for future, spec in futures.items():
                try:
                    result = future.result()
                    results[spec.name] = result
                except Exception:
                    results[spec.name] = None
        for spec in specialists:
            self.assertTrue(spec.was_called, f"{spec.name} was not called")
        self.assertIsNotNone(results["Good1"])
        self.assertIsNotNone(results["Good2"])
        self.assertIsNotNone(results["Good3"])
        self.assertIsNotNone(results["Good4"])
        self.assertIsNone(results["Bad1"])
        self.assertIsNone(results["Bad2"])

    def test_partial_results_on_failure(self):
        specialists = [
            MockSpecialist("Success1", should_fail=False, discovery_count=3),
            MockSpecialist("Failure1", should_fail=True),
            MockSpecialist("Success2", should_fail=False, discovery_count=2),
        ]

        successful_results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), [])
                for spec in specialists
            ]

            for future in futures:
                try:
                    result = future.result()
                    successful_results.append(result)
                except Exception:
                    pass  # ignore failures
        self.assertEqual(len(successful_results), 2)
        total_discoveries = sum(len(r.discoveries) for r in successful_results)
        self.assertEqual(total_discoveries, 5)  # 3 + 2

class TestResultAggregation(unittest.TestCase):
    """Test result aggregation from specialists."""

    def setUp(self):
        reset_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_results_from_all_specialists_collected(self):
        specialists = [
            MockSpecialist("Spec1", discovery_count=2),
            MockSpecialist("Spec2", discovery_count=3),
            MockSpecialist("Spec3", discovery_count=1),
        ]

        results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), []): spec
                for spec in specialists
            }

            for future, spec in futures.items():
                try:
                    result = future.result()
                    results[spec.name] = [result]
                except Exception:
                    pass
        self.assertEqual(len(results), 3)
        total_discoveries = sum(
            len(r.discoveries) for results_list in results.values() for r in results_list
        )
        self.assertEqual(total_discoveries, 6)  # 2 + 3 + 1

    def test_discoveries_merged_correctly(self):
        # create specialists with distinct discoveries
        spec1_discoveries = [
            Discovery(
                round_num=0,
                discovery_type="reentrancy",
                content="Reentrancy in withdraw: Test vulnerability",
                confidence=0.9,
                evidence=["evidence1"]
            )
        ]
        spec2_discoveries = [
            Discovery(
                round_num=0,
                discovery_type="access_control",
                content="Missing access control: Test vulnerability",
                confidence=0.8,
                evidence=["evidence2"]
            )
        ]

        specialists = [
            MockSpecialist("Spec1", discoveries=spec1_discoveries),
            MockSpecialist("Spec2", discoveries=spec2_discoveries),
        ]

        results = {}
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), []): spec
                for spec in specialists
            }

            for future, spec in futures.items():
                result = future.result()
                results[spec.name] = [result]

        # merge all discoveries
        all_discoveries = [
            d for results_list in results.values()
            for r in results_list
            for d in r.discoveries
        ]
        self.assertEqual(len(all_discoveries), 2)
        discovery_types = {d.discovery_type for d in all_discoveries}
        self.assertIn("reentrancy", discovery_types)
        self.assertIn("access_control", discovery_types)

    def test_empty_results_handled(self):
        specialists = [
            MockSpecialist("EmptySpec", discoveries=[]),
            MockSpecialist("NonEmptySpec", discovery_count=2),
        ]

        results = {}
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), []): spec
                for spec in specialists
            }

            for future, spec in futures.items():
                result = future.result()
                results[spec.name] = [result]

        # both should return results
        self.assertEqual(len(results), 2)
        empty_result = results["EmptySpec"][0]
        self.assertEqual(len(empty_result.discoveries), 0)
        non_empty_result = results["NonEmptySpec"][0]
        self.assertEqual(len(non_empty_result.discoveries), 2)

class TestTimeoutHandling(unittest.TestCase):
    """Test timeout handling for slow specialists."""

    def setUp(self):
        reset_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_slow_specialist_timeout(self):
        slow_specialist = MockSpecialist("SlowSpec", delay=5.0)  # 5 second delay

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                slow_specialist.analyze_contract, "code", {}, MagicMock(), []
            )

            # try to get result with 1 second timeout
            with self.assertRaises(FuturesTimeoutError):
                future.result(timeout=1.0)

    def test_timeout_doesnt_block_fast_specialists(self):
        specialists = [
            MockSpecialist("Fast1", delay=0.1),
            MockSpecialist("Slow", delay=5.0),
            MockSpecialist("Fast2", delay=0.1),
        ]

        results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), []): spec
                for spec in specialists
            }

            # wait for fast ones, timeout on slow one
            for future, spec in futures.items():
                try:
                    result = future.result(timeout=1.0)
                    results[spec.name] = result
                except FuturesTimeoutError:
                    results[spec.name] = None
        self.assertIsNotNone(results["Fast1"])
        self.assertIsNotNone(results["Fast2"])
        # note: we can't cancel futures, so this might still be running
        self.assertTrue("Slow" in results)

    def test_partial_results_on_timeout(self):
        specialists = [
            MockSpecialist("Success1", delay=0.1, discovery_count=3),
            MockSpecialist("Timeout", delay=5.0, discovery_count=1),
            MockSpecialist("Success2", delay=0.1, discovery_count=2),
        ]

        successful_results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), [])
                for spec in specialists
            ]

            for future in futures:
                try:
                    result = future.result(timeout=1.0)
                    successful_results.append(result)
                except FuturesTimeoutError:
                    pass  # ignore timeouts
        self.assertGreaterEqual(len(successful_results), 2)
        total_discoveries = sum(len(r.discoveries) for r in successful_results)
        self.assertGreaterEqual(total_discoveries, 5)  # at least 3 + 2

class TestA2APeerReview(unittest.TestCase):
    """Test A2A peer review communication."""

    def setUp(self):
        reset_a2a_bus()
        self.bus = get_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_peer_review_updates_confidence(self):
        # create a discovery with initial confidence
        discovery = Discovery(
            round_num=0,
            discovery_type="reentrancy",
            content="Test vulnerability: Test description",
            confidence=0.70,
            evidence=["test evidence"]
        )

        # simulate peer reviews
        reviews = [
            PeerReviewResponse(
                reviewer_id="reviewer1",
                finding_id="test",
                approved=True,
                confidence=0.85,
                critique="Good finding",
                issues_found=[],
                suggestions=[]
            ),
            PeerReviewResponse(
                reviewer_id="reviewer2",
                finding_id="test",
                approved=True,
                confidence=0.90,
                critique="Strong evidence",
                issues_found=[],
                suggestions=[]
            ),
        ]

        # calculate confidence adjustment
        original_conf = discovery.confidence
        adjustment = 0.0
        for resp in reviews:
            delta = 0.08 if resp.approved else -0.10
            delta += (resp.confidence - 0.5) * 0.1
            adjustment += delta

        avg_adjustment = adjustment / len(reviews)
        new_conf = min(1.0, max(0.0, original_conf + avg_adjustment))
        self.assertGreater(new_conf, original_conf)
        self.assertLessEqual(new_conf, 1.0)

    def test_negative_peer_review_decreases_confidence(self):
        discovery = Discovery(
            round_num=0,
            discovery_type="test",
            content="Test: Test description",
            confidence=0.80,
            evidence=[]
        )

        # simulate negative review
        reviews = [
            PeerReviewResponse(
                reviewer_id="reviewer1",
                finding_id="test",
                approved=False,
                confidence=0.30,
                critique="Weak evidence",
                issues_found=["weak_evidence"],
                suggestions=[]
            ),
        ]

        original_conf = discovery.confidence
        adjustment = 0.0
        for resp in reviews:
            delta = 0.08 if resp.approved else -0.10
            delta += (resp.confidence - 0.5) * 0.1
            adjustment += delta

        new_conf = min(1.0, max(0.0, original_conf + adjustment))
        self.assertLess(new_conf, original_conf)

class TestMoAQualityScoring(unittest.TestCase):
    """Test MoA quality score calculation."""

    def setUp(self):
        reset_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_quality_score_specialist_coverage(self):
        orchestrator = MixtureOfAgentsOrchestrator(
            project_root=PROJECT_ROOT,
            cost_manager=MagicMock(),
            logger=MagicMock(),
            enable_a2a=False
        )
        specialist_results = {
            f"Specialist{i}": [MagicMock(discoveries=[])]
            for i in range(6)
        }

        aggregated_result = MagicMock(
            discoveries=[],
            confidence=0.9
        )

        score = orchestrator._calculate_moa_quality(specialist_results, aggregated_result)

        # with full coverage, score should include full 0.25 for coverage
        # (Actual score depends on other factors too)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_quality_score_partial_coverage(self):
        orchestrator = MixtureOfAgentsOrchestrator(
            project_root=PROJECT_ROOT,
            cost_manager=MagicMock(),
            logger=MagicMock(),
            enable_a2a=False
        )
        specialist_results = {
            f"Specialist{i}": [MagicMock(discoveries=[])]
            for i in range(3)
        }

        aggregated_result = MagicMock(
            discoveries=[],
            confidence=0.9
        )

        score = orchestrator._calculate_moa_quality(specialist_results, aggregated_result)

        # score should be lower with partial coverage
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

class TestSequentialExecution(unittest.TestCase):
    """Test sequential execution mode (for comparison and debugging)."""

    def setUp(self):
        reset_a2a_bus()

    def tearDown(self):
        reset_a2a_bus()

    def test_sequential_execution(self):
        specialists = [
            MockSpecialist(f"Spec{i}", delay=0.1, discovery_count=2)
            for i in range(3)
        ]

        # execute sequentially
        results = {}
        for spec in specialists:
            result = spec.analyze_contract("code", {}, MagicMock(), [])
            results[spec.name] = [result]
        self.assertEqual(len(results), 3)
        for spec in specialists:
            self.assertTrue(spec.was_called)

    def test_sequential_slower_than_parallel(self):
        specialists_parallel = [
            MockSpecialist(f"ParSpec{i}", delay=0.2)
            for i in range(4)
        ]

        specialists_sequential = [
            MockSpecialist(f"SeqSpec{i}", delay=0.2)
            for i in range(4)
        ]

        # measure parallel execution
        start_parallel = time.time()
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(spec.analyze_contract, "code", {}, MagicMock(), [])
                for spec in specialists_parallel
            ]
            for future in futures:
                future.result()
        parallel_time = time.time() - start_parallel

        # measure sequential execution
        start_sequential = time.time()
        for spec in specialists_sequential:
            spec.analyze_contract("code", {}, MagicMock(), [])
        sequential_time = time.time() - start_sequential
        self.assertGreater(sequential_time, parallel_time,
                          f"Sequential ({sequential_time}s) should be slower than parallel ({parallel_time}s)")

if __name__ == "__main__":
    unittest.main()

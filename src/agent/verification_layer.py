import os
import time
import random
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
import grpc
import json

from config import config
from utils.llm_backend.base import LLMBackend
from utils.logging import ResearchLogger
from kb.knowledge_base import KnowledgeBase
from utils.cost_manager import CostManager
from agent.base_attacker import AttackHypothesis
from kb.knowledge_graph import KnowledgeGraph, NodeType
from verification.fuzzing_gen import FuzzingGenerator
from agent.adversarial_engine import AdversarialEngine
from verification.formal_spec_extractor import FormalSpecExtractor
from verification.z3_verifier import Z3Verifier, VerificationResult as Z3Result, Z3VerificationResult

class TimeoutException(Exception):
    pass

@dataclass
class VerificationResult:
    hypothesis: AttackHypothesis
    verified: bool
    confidence: float
    reasoning: str
    issues_found: List[str]
    similar_to: List[str]
    priority: float
    needs_manual_review: bool = False
    verification_type: str = "adversarial_critic"
    verification_time: float = 0.0


class VerificationLayer:
    """Validates hypotheses before PoC generation using Z3 + adversarial critic"""

    def __init__(self, backend: LLMBackend, logger: ResearchLogger, cost_manager: CostManager,
                 kb: Optional[KnowledgeBase] = None, enable_neurosymbolic: bool = True):
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager
        self.enable_neurosymbolic = enable_neurosymbolic
        self.formal_spec_extractor: Optional[FormalSpecExtractor] = None
        self.z3_verifier: Optional[Z3Verifier] = None
        self.fuzz_generator = FuzzingGenerator(project_root=config.PROJECT_ROOT)
        self.adversarial_engine = AdversarialEngine(project_root=str(config.PROJECT_ROOT))

        env_workers = os.getenv("VERIFICATION_WORKERS", "").strip()
        default_workers = max(1, (os.cpu_count() or 1))
        try:
            parsed_workers = int(env_workers) if env_workers else 0
        except ValueError:
            parsed_workers = 0
        self.max_verification_workers = max(1, parsed_workers) if parsed_workers > 0 else default_workers

        if self.max_verification_workers > 1:
            self.logger.info(f"[VerificationLayer] Parallel verification enabled (workers={self.max_verification_workers})")

        if self.enable_neurosymbolic:
            try:
                self.formal_spec_extractor = FormalSpecExtractor(backend=backend, logger=logger, cost_manager=cost_manager)
                self.z3_verifier = Z3Verifier(logger=logger, timeout_ms=30000)
                self.logger.info("[VerificationLayer] Neurosymbolic verification ENABLED (Z3 + formal specs)")
            except Exception as exc:
                self.enable_neurosymbolic = False
                self.formal_spec_extractor = None
                self.z3_verifier = None
                self.logger.warning(f"[VerificationLayer] Failed to initialize neurosymbolic verification ({exc}); falling back to adversarial critic only.")
        else:
            self.logger.info("[VerificationLayer] Neurosymbolic verification DISABLED")

        self.learning_mgr = None
        if kb:
            from kb.learning_manager import KBLearningManager
            self.learning_mgr = KBLearningManager(kb, logger)
            self.logger.info("[VerificationLayer] Automatic KB learning enabled")

        import threading
        self._z3_result_cache: Dict[str, VerificationResult] = {}
        self._z3_cache_lock = threading.Lock()

    def verify_hypotheses(self, hypotheses: List[AttackHypothesis], contract_source: str,
                          contract_info: Dict[str, Any], knowledge_graph: KnowledgeGraph,
                          max_hypotheses: int = 20) -> List[VerificationResult]:
        """Verify hypotheses with timeout management"""
        start_time = time.time()
        contract_timeout = config.VERIFICATION_CONTRACT_TIMEOUT
        min_time_remaining = config.VERIFICATION_MIN_TIME_REMAINING

        if max_hypotheses and len(hypotheses) > max_hypotheses:
            self.logger.info(f"[VerificationLayer] Truncating hypotheses {len(hypotheses)} → {max_hypotheses}")
            hypotheses = hypotheses[:max_hypotheses]

        self.logger.info(f"[VerificationLayer] Verifying {len(hypotheses)} hypotheses (timeout: {contract_timeout}s)")

        deduped_groups = self._deduplicate_hypotheses(hypotheses)
        self.logger.info(f"[VerificationLayer] Deduplication: {len(hypotheses)} → {len(deduped_groups)} unique attacks")

        dedup_items = list(deduped_groups.items())
        ordered_results = self._run_verification(
            dedup_items=dedup_items, contract_source=contract_source, contract_info=contract_info,
            knowledge_graph=knowledge_graph, start_time=start_time,
            contract_timeout=contract_timeout, min_time_remaining=min_time_remaining
        )

        results: List[VerificationResult] = []
        total_groups = len(ordered_results)

        for idx, (representative, result) in enumerate(ordered_results, start=1):
            if result is None:
                continue
            status = "APPROVED" if result.verified else "REJECTED"
            self.logger.info(f"[VerificationLayer] [{idx}/{total_groups}] {status} {representative.hypothesis_id} (confidence={result.confidence:.2f})")
            self.logger.log_verification_decision(
                hypothesis_id=representative.hypothesis_id, attacker=representative.attack_type,
                verified=result.verified, confidence=result.confidence,
                reasoning=result.reasoning, issues=result.issues_found
            )
            results.append(result)

        verified = [r for r in results if r.verified]
        rejected = [r for r in results if not r.verified]
        timeout_count = sum(1 for r in results if r.verification_type in ["timeout", "timeout_skipped"])
        timeout_exceeded = sum(1 for r in results if r.verification_type == "timeout")
        total_verification_time = time.time() - start_time
        avg_time = sum(r.verification_time for r in results) / len(results) if results else 0

        self.logger.info(f"[VerificationLayer] Results: {len(verified)} verified, {len(rejected)} rejected (total: {total_verification_time:.1f}s, avg: {avg_time:.1f}s)")
        if timeout_count > 0:
            self.logger.warning(f"[VerificationLayer] Timeouts: {timeout_count} total ({timeout_exceeded} exceeded)")

        if self.learning_mgr and rejected:
            contract_name = contract_info.get("name", "Unknown")
            for result in rejected:
                try:
                    self.learning_mgr.learn_from_rejection(
                        hypothesis=result.hypothesis, rejection_reason=result.reasoning,
                        rejection_stage="verification", contract_name=contract_name
                    )
                except Exception as exc:
                    self.logger.warning(f"[VerificationLayer] KB learning failed for {result.hypothesis.hypothesis_id}: {exc}")
            self.logger.info(f"[VerificationLayer] Logged {len(rejected)} rejections to KB")

        verified_sorted = sorted(verified, key=lambda r: r.priority, reverse=True)

        explicit_invariants = contract_info.get("invariants", [])
        invariants = explicit_invariants or [n.name for n in knowledge_graph.get_nodes_by_type(NodeType.INVARIANT)]
        if invariants:
            try:
                source_import = contract_info.get("source_import")
                if not source_import:
                    self.logger.warning("[VerificationLayer] Skipping invariant fuzzing (missing source_import)")
                else:
                    generated = self.fuzz_generator.generate_handler(
                        contract_name=contract_info.get("name", "Contract"),
                        invariants=invariants[:5], source_import=source_import
                    )
                    self.logger.info(f"[VerificationLayer] Generated invariant fuzz handler at {generated}")
                    contract_info["invariant_fuzz_handler"] = str(generated)
                    if os.getenv("ENABLE_INVARIANT_FUZZ_RUN", "0") == "1":
                        ok = self.fuzz_generator.run_fuzz(generated)
                        status = "pass" if ok else "fail"
                        contract_info["invariant_fuzz_status"] = status
                        self.logger.info(f"[VerificationLayer] Invariant fuzz: {'PASS' if ok else 'FAIL'}")
                        run_profile = contract_info.get("run_profile")
                        if run_profile and hasattr(run_profile, "notes"):
                            run_profile.notes.append(f"fuzz:{status}:{generated}")
                        if os.getenv("ENABLE_ADVERSARIAL_ENGINE", "0") == "1":
                            try:
                                rel = generated.relative_to(config.PROJECT_ROOT)
                                harnesses = [{"name": "invariant_fuzz", "path": str(config.PROJECT_ROOT), "match": str(rel)}]
                                ae_res = self.adversarial_engine.run_harnesses(harnesses)
                                contract_info["adversarial_harness"] = [r.__dict__ for r in ae_res]
                                for r in ae_res:
                                    self.logger.info(f"[AdversarialEngine] {r.name}: {r.status} code={r.returncode}")
                            except Exception as exc:
                                self.logger.warning(f"[VerificationLayer] AdversarialEngine run failed: {exc}")
            except Exception as exc:
                self.logger.warning(f"[VerificationLayer] Fuzz handler generation failed: {exc}")

        return verified_sorted

    def _deduplicate_hypotheses(self, hypotheses: List[AttackHypothesis]) -> Dict[str, List[AttackHypothesis]]:
        """Group similar hypotheses by attack type + target"""
        groups = defaultdict(list)
        for hyp in hypotheses:
            groups[f"{hyp.attack_type}_{hyp.target_function}"].append(hyp)
        return dict(groups)

    def _create_timeout_result(self, hypothesis: AttackHypothesis, similar_hypotheses: List[AttackHypothesis],
                               elapsed: float, reason: str, verification_type: str = "timeout") -> VerificationResult:
        """Create timeout/error result"""
        return VerificationResult(
            hypothesis=hypothesis, verified=False, confidence=0.0, reasoning=reason,
            issues_found=[reason], similar_to=[h.hypothesis_id for h in similar_hypotheses],
            priority=0.0, verification_type=verification_type, verification_time=elapsed
        )

    def _create_signal_error_fallback_result(self, hypothesis: AttackHypothesis,
                                             similar_hypotheses: List[AttackHypothesis], elapsed: float) -> VerificationResult:
        """Fallback for signal handler errors in worker threads"""
        return VerificationResult(
            hypothesis=hypothesis, verified=True, confidence=0.5,
            reasoning="Z3 verification skipped due to thread limitations; passed to adversarial critic",
            issues_found=["Z3/neurosymbolic verification unavailable in worker thread"],
            similar_to=[h.hypothesis_id for h in similar_hypotheses],
            priority=0.5, verification_type="critic_only_fallback", verification_time=elapsed
        )

    def _is_signal_handler_error(self, exc: Exception) -> bool:
        """Check if exception is signal handler error"""
        error_msg = str(exc).lower()
        return "signal" in error_msg and "main thread" in error_msg

    def _run_verification(self, dedup_items: List[Tuple[str, List[AttackHypothesis]]], contract_source: str,
                          contract_info: Dict[str, Any], knowledge_graph: KnowledgeGraph,
                          start_time: float, contract_timeout: int, min_time_remaining: int
                         ) -> List[Tuple[AttackHypothesis, Optional[VerificationResult]]]:
        """Dispatch sequential or parallel verification"""
        if not dedup_items:
            return []
        if self.max_verification_workers > 1 and len(dedup_items) > 1:
            return self._verify_parallel(dedup_items, contract_source, contract_info, knowledge_graph,
                                        start_time, contract_timeout, min_time_remaining)
        return self._verify_sequential(dedup_items, contract_source, contract_info, knowledge_graph,
                                       start_time, contract_timeout, min_time_remaining)

    def _verify_sequential(self, dedup_items: List[Tuple[str, List[AttackHypothesis]]], contract_source: str,
                          contract_info: Dict[str, Any], knowledge_graph: KnowledgeGraph,
                          start_time: float, contract_timeout: int, min_time_remaining: int
                         ) -> List[Tuple[AttackHypothesis, Optional[VerificationResult]]]:
        ordered: List[Tuple[AttackHypothesis, Optional[VerificationResult]]] = []
        total_groups = len(dedup_items)
        max_per_hypothesis = config.VERIFICATION_HYPOTHESIS_TIMEOUT_MAX

        for idx, (group_id, group_hypotheses) in enumerate(dedup_items, start=1):
            elapsed = time.time() - start_time
            remaining = contract_timeout - elapsed
            remaining_hypotheses = total_groups - idx + 1

            if remaining < min_time_remaining:
                self.logger.warning(f"[VerificationLayer] Timeout budget exhausted: {remaining:.1f}s < {min_time_remaining}s. Skipping {remaining_hypotheses} hypotheses")
                for _, rem_group in dedup_items[idx-1:]:
                    rem_representative = max(rem_group, key=lambda h: h.confidence)
                    similar = [h for h in rem_group if h != rem_representative]
                    timeout_result = self._create_timeout_result(
                        rem_representative, similar, 0.0,
                        f"Skipped (remaining: {remaining:.1f}s < {min_time_remaining}s)", "timeout_skipped"
                    )
                    ordered.append((rem_representative, timeout_result))
                break

            per_hypothesis_timeout = min(remaining / remaining_hypotheses, max_per_hypothesis)
            representative = max(group_hypotheses, key=lambda h: h.confidence)
            self.logger.info(f"[VerificationLayer] [{idx}/{total_groups}] Evaluating {representative.hypothesis_id} (timeout: {per_hypothesis_timeout:.1f}s)")

            hyp_start = time.time()
            try:
                result = self._verify_single_hypothesis(
                    representative, contract_source, contract_info, knowledge_graph,
                    [h for h in group_hypotheses if h != representative], per_hypothesis_timeout
                )
            except TimeoutException:
                hyp_elapsed = time.time() - hyp_start
                self.logger.warning(f"[VerificationLayer] {representative.hypothesis_id} TIMED OUT after {hyp_elapsed:.1f}s")
                with self._z3_cache_lock:
                    cached = self._z3_result_cache.get(representative.hypothesis_id)
                    if cached is not None:
                        self.logger.info(f"[VerificationLayer] Recovered Z3 SAT for {representative.hypothesis_id} from cache")
                        result = cached
                        result.verification_time = hyp_elapsed
                        ordered.append((representative, result))
                        continue
                similar = [h for h in group_hypotheses if h != representative]
                result = self._create_timeout_result(representative, similar, hyp_elapsed, f"Verification timed out after {hyp_elapsed:.1f}s", "timeout")

            hyp_elapsed = time.time() - hyp_start
            if result:
                result.verification_time = hyp_elapsed
            ordered.append((representative, result))

        return ordered

    def _verify_parallel(self, dedup_items: List[Tuple[str, List[AttackHypothesis]]], contract_source: str,
                        contract_info: Dict[str, Any], knowledge_graph: KnowledgeGraph,
                        start_time: float, contract_timeout: int, min_time_remaining: int
                       ) -> List[Tuple[AttackHypothesis, Optional[VerificationResult]]]:
        from queue import Queue
        total_groups = len(dedup_items)
        results_queue: Queue = Queue()
        max_per_hypothesis = config.VERIFICATION_HYPOTHESIS_TIMEOUT_MAX

        def _spawn_neurosymbolic_helpers():
            if not (self.enable_neurosymbolic and self.formal_spec_extractor and self.z3_verifier):
                return None, None
            return (FormalSpecExtractor(self.backend, self.logger, self.cost_manager),
                   Z3Verifier(self.logger, self.z3_verifier.timeout_ms, self.z3_verifier.enable_mcts_fallback))

        def worker(idx: int, group_hypotheses: List[AttackHypothesis], timeout: float):
            representative = max(group_hypotheses, key=lambda h: h.confidence)
            similar = [h for h in group_hypotheses if h != representative]
            self.logger.info(f"[VerificationLayer] [{idx+1}/{total_groups}] Queueing {representative.hypothesis_id} (timeout: {timeout:.1f}s)")

            local_extractor, local_z3 = _spawn_neurosymbolic_helpers()
            hyp_start = time.time()
            result = None

            try:
                result = self._verify_single_hypothesis(representative, contract_source, contract_info,
                                                        knowledge_graph, similar, local_extractor, local_z3, timeout)
            except TimeoutException:
                hyp_elapsed = time.time() - hyp_start
                self.logger.warning(f"[VerificationLayer] Worker {idx+1}: {representative.hypothesis_id} TIMED OUT after {hyp_elapsed:.1f}s")
                with self._z3_cache_lock:
                    cached = self._z3_result_cache.get(representative.hypothesis_id)
                    if cached is not None:
                        self.logger.info(f"[VerificationLayer] Worker {idx+1}: Recovered Z3 SAT for {representative.hypothesis_id}")
                        result = cached
                        result.verification_time = hyp_elapsed
                        return (representative, result, similar, idx)
                result = self._create_timeout_result(representative, similar, hyp_elapsed, f"Verification timed out after {hyp_elapsed:.1f}s", "timeout")
            except (ValueError, Exception) as exc:
                hyp_elapsed = time.time() - hyp_start
                if self._is_signal_handler_error(exc):
                    self.logger.warning(f"[VerificationLayer] Worker {idx+1}: Signal handler error for {representative.hypothesis_id}")
                    result = self._create_signal_error_fallback_result(representative, similar, hyp_elapsed)
                else:
                    self.logger.warning(f"[VerificationLayer] Worker {idx+1} failed for {representative.hypothesis_id}: {exc}")
                    result = None

            hyp_elapsed = time.time() - hyp_start
            if result:
                result.verification_time = hyp_elapsed
            results_queue.put((idx, representative, result))
            return idx, representative, result

        elapsed = time.time() - start_time
        remaining = contract_timeout - elapsed
        per_hypothesis_timeout = min(remaining / total_groups, max_per_hypothesis)
        self.logger.info(f"[VerificationLayer] Parallel verification: {total_groups} hypotheses, {self.max_verification_workers} workers, {per_hypothesis_timeout:.1f}s timeout")

        with ThreadPoolExecutor(max_workers=self.max_verification_workers) as executor:
            futures = {}
            completed_count = 0

            for idx, (_, group_hypotheses) in enumerate(dedup_items):
                future = executor.submit(worker, idx, group_hypotheses, per_hypothesis_timeout)
                futures[future] = idx

            for future in as_completed(futures, timeout=None):
                try:
                    idx, representative, result = future.result()
                    completed_count += 1

                    elapsed = time.time() - start_time
                    remaining = contract_timeout - elapsed
                    remaining_hypotheses = total_groups - completed_count

                    if remaining < min_time_remaining and remaining_hypotheses > 0:
                        self.logger.warning(f"[VerificationLayer] Timeout budget exhausted: {remaining:.1f}s < {min_time_remaining}s. Marking {remaining_hypotheses} hypotheses as skipped")
                        for pending_future in futures:
                            if not pending_future.done():
                                pending_future.cancel()
                        for idx, (_, group_hypotheses) in enumerate(dedup_items):
                            representative = max(group_hypotheses, key=lambda h: h.confidence)
                            similar = [h for h in group_hypotheses if h != representative]
                            timeout_result = self._create_timeout_result(representative, similar, 0.0,
                                                                         f"Skipped (remaining: {remaining:.1f}s < {min_time_remaining}s)", "timeout_skipped")
                            results_queue.put((idx, representative, timeout_result))
                        break
                except FuturesTimeoutError:
                    self.logger.error("[VerificationLayer] Unexpected timeout in as_completed")
                    break
                except Exception as exc:
                    self.logger.error(f"[VerificationLayer] Error processing future result: {exc}")
                    continue

        ordered: List[Optional[Tuple[AttackHypothesis, Optional[VerificationResult]]]] = [None] * total_groups
        while not results_queue.empty():
            idx, representative, result = results_queue.get()
            ordered[idx] = (representative, result)
        return [entry for entry in ordered if entry is not None]

    def _verify_single_hypothesis(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any],
                                  knowledge_graph: KnowledgeGraph, similar_hypotheses: List[AttackHypothesis],
                                  formal_spec_extractor: Optional[FormalSpecExtractor] = None,
                                  z3_verifier: Optional[Z3Verifier] = None, timeout: Optional[float] = None) -> VerificationResult:
        """Verify hypothesis using neurosymbolic + extended thinking"""
        if timeout is not None:
            with ThreadPoolExecutor(max_workers=1) as timeout_executor:
                future = timeout_executor.submit(self._verify_single_hypothesis_impl, hypothesis, contract_source,
                                                contract_info, knowledge_graph, similar_hypotheses,
                                                formal_spec_extractor, z3_verifier)
                try:
                    return future.result(timeout=timeout)
                except FuturesTimeoutError:
                    future.cancel()
                    with self._z3_cache_lock:
                        cached = self._z3_result_cache.get(hypothesis.hypothesis_id)
                        if cached is not None:
                            self.logger.info(f"[VerificationLayer] Recovered Z3 SAT for {hypothesis.hypothesis_id} from cache")
                            return cached
                    raise TimeoutException(f"Verification exceeded {timeout}s timeout")
        else:
            return self._verify_single_hypothesis_impl(hypothesis, contract_source, contract_info, knowledge_graph,
                                                       similar_hypotheses, formal_spec_extractor, z3_verifier)

    def _verify_single_hypothesis_impl(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any],
                                       knowledge_graph: KnowledgeGraph, similar_hypotheses: List[AttackHypothesis],
                                       formal_spec_extractor: Optional[FormalSpecExtractor] = None,
                                       z3_verifier: Optional[Z3Verifier] = None) -> VerificationResult:
        """Internal implementation of single hypothesis verification"""
        import re
        desc_lower = hypothesis.description.lower()
        negative_patterns = [
            (r"lacks?\s+any\s+oracle", "No oracle"), (r"no\s+oracle", "No oracle"),
            (r"does\s+not\s+have.*oracle", "No oracle"), (r"follows?\s+.*CEI\s+pattern\s+correctly", "Correct CEI"),
            (r"correctly\s+implements", "Correct impl"), (r"properly\s+implements", "Proper impl"),
            (r"no\s+reentrancy", "No reentrancy"), (r"does\s+not\s+have.*reentrancy", "No reentrancy"),
            (r"lacks?\s+.*vulnerability", "No vuln"), (r"not\s+vulnerable\s+to", "Not vulnerable"),
            (r"immune\s+to", "Immune"), (r"safeguarded\s+against", "Safeguarded"),
            (r"no\s+(?:flash\s+loan|reentrancy|oracle)\s+(?:risk|vulnerability|issue)", "No risk"),
            (r"does\s+not\s+(?:have|contain|exhibit)", "Absence"), (r"(?:cannot|can't|couldn't)\s+be\s+(?:exploited|attacked)", "Cannot exploit"),
            (r"properly\s+(?:protected|secured|guarded)", "Protected"), (r"(?:safe|secure)\s+(?:from|against)", "Safe"),
            (r"no\s+(?:evidence|indication)\s+of", "No evidence"), (r"resistant\s+to", "Resistant"), (r"mitigated\s+by", "Mitigated"),
        ]

        for pattern, reason in negative_patterns:
            if re.search(pattern, desc_lower):
                self.logger.info(f"[VerificationLayer] [FILTER] Rejecting negative finding {hypothesis.hypothesis_id}: {reason}")
                self._log_rejection_for_learning(hypothesis, f"Negative finding: {reason}", "negative_pattern_filter")
                return VerificationResult(hypothesis, False, 0.05, f"Negative finding: {reason}",
                                         [f"Hypothesis describes absence of vulnerability: {reason}"],
                                         [h.hypothesis_id for h in similar_hypotheses], 0.0, verification_type="negative_pattern_filter")

        if self.enable_neurosymbolic:
            neurosymbolic_result = self._neurosymbolic_verify(hypothesis, contract_source, contract_info,
                                                              formal_spec_extractor, z3_verifier)
            if neurosymbolic_result and neurosymbolic_result.result == Z3Result.SAT:
                self.logger.info(f"[VerificationLayer] Z3 PROVED {hypothesis.hypothesis_id} is SAT (confidence: {neurosymbolic_result.confidence:.2f})")
                result = VerificationResult(hypothesis, True, neurosymbolic_result.confidence, neurosymbolic_result.reasoning,
                                           [], [h.hypothesis_id for h in similar_hypotheses], 0.95)
                with self._z3_cache_lock:
                    self._z3_result_cache[hypothesis.hypothesis_id] = result
                    self.logger.info(f"[VerificationLayer] Cached Z3 SAT result for {hypothesis.hypothesis_id}")
                return result
            elif neurosymbolic_result and neurosymbolic_result.result == Z3Result.UNSAT:
                self.logger.info(f"[VerificationLayer] Z3 PROVED {hypothesis.hypothesis_id} is UNSAT (impossible)")
                return VerificationResult(hypothesis, False, neurosymbolic_result.confidence, neurosymbolic_result.reasoning,
                                         ["Z3 proved attack is logically impossible"], [h.hypothesis_id for h in similar_hypotheses], 0.0)
            elif neurosymbolic_result and neurosymbolic_result.result == Z3Result.UNKNOWN:
                self.logger.info(f"[VerificationLayer] Z3 returned UNKNOWN for {hypothesis.hypothesis_id} (passing to critic)")
            else:
                if neurosymbolic_result:
                    self.logger.warning(f"[VerificationLayer] Unhandled Z3Result: {neurosymbolic_result.result} for {hypothesis.hypothesis_id}")

        graph_context = self._extract_graph_context(knowledge_graph, hypothesis)
        prompt = self._build_verification_prompt(hypothesis, contract_source, contract_info, graph_context, similar_hypotheses)

        response = None
        for attempt in range(3):
            try:
                response = self.backend.generate(prompt, config.MAX_OUTPUT_TOKENS,
                                                config.EXTENDED_THINKING_TEMPERATURE, config.EXTENDED_THINKING_BUDGET)
                break
            except grpc.RpcError as exc:
                if exc.code() == grpc.StatusCode.PERMISSION_DENIED:
                    message = (getattr(exc, "details", lambda: str(exc))())
                    self.logger.warning(f"[VerificationLayer] Safety filter rejected: {hypothesis.description[:100]}")
                    self._log_rejection_for_learning(hypothesis, f"Safety filter: {message}", "safety_filter_rejection")
                    return VerificationResult(hypothesis, False, 0.0, f"Safety filter - requires manual review: {message}",
                                             ["Safety filter rejection"], [h.hypothesis_id for h in similar_hypotheses], 0.0,
                                             needs_manual_review=True, verification_type="safety_filter_rejection")
                if exc.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and attempt < 2:
                    backoff = 10 * (attempt + 1) + random.uniform(0, 5)
                    self.logger.warning(f"[VerificationLayer] Rate limited; sleeping {backoff:.1f}s")
                    time.sleep(backoff)
                    continue
                raise
            except (RuntimeError, ValueError, ConnectionError, TimeoutError) as exc:
                self.logger.warning(f"[VerificationLayer] Backend failed: {exc}", exc_info=True)
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                return VerificationResult(hypothesis, False, 0.0, f"Backend failure: {exc}",
                                         [f"Backend failure: {exc}"], [h.hypothesis_id for h in similar_hypotheses], 0.0)

        if response is None:
            return VerificationResult(hypothesis, False, 0.0, "No backend response after retries",
                                     ["Backend unavailable"], [h.hypothesis_id for h in similar_hypotheses], 0.0)

        if hasattr(response, "cost"):
            self.cost_manager.log_cost("VerificationLayer", contract_info.get("name", "Unknown"), 0, "verification_llm_call",
                                      response.cost, {"input_tokens": response.prompt_tokens, "output_tokens": response.output_tokens})

        return self._parse_verification_response(response.text, hypothesis, similar_hypotheses)

    def _neurosymbolic_verify(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any],
                              formal_spec_extractor: Optional[FormalSpecExtractor] = None,
                              z3_verifier: Optional[Z3Verifier] = None):
        """Neurosymbolic verification using formal spec + Z3"""
        extractor = formal_spec_extractor or self.formal_spec_extractor
        verifier = z3_verifier or self.z3_verifier
        if extractor is None or verifier is None:
            return None

        try:
            self.logger.info(f"[NeurosymbolicVerification] Extracting formal spec for {hypothesis.hypothesis_id}")
            formal_spec = extractor.extract(hypothesis, contract_source, contract_info)

            if not formal_spec:
                self.logger.warning("[NeurosymbolicVerification] No formal spec; skipping Z3")
                return Z3VerificationResult(Z3Result.UNKNOWN, 0.0, None, {}, "Spec extraction failed", 0.0, 0)

            extraction_conf = max(0.0, min(1.0, getattr(formal_spec, "extraction_confidence", 0.0)))
            if extraction_conf < 0.3:
                self.logger.warning(f"[NeurosymbolicVerification] Low confidence ({extraction_conf:.2f}), skipping Z3")
                return Z3VerificationResult(Z3Result.UNKNOWN, extraction_conf, None, {}, "Spec confidence too low", 0.0, 0)

            self.logger.info(f"[NeurosymbolicVerification] Running Z3 on {hypothesis.hypothesis_id}")
            try:
                z3_result = verifier.verify(formal_spec)
            except Exception as z3_exc:
                self.logger.warning(f"[NeurosymbolicVerification] Z3 failed: {z3_exc}")
                return Z3VerificationResult(Z3Result.UNKNOWN, 0.0, None, {}, f"Z3 failed: {z3_exc}", 0.0, 0)

            threshold = getattr(config, "Z3_UNSAT_CONFIDENCE_FLOOR", 0.98)
            if z3_result and z3_result.result == Z3Result.UNSAT and formal_spec.extraction_confidence < threshold:
                self.logger.warning(f"[NeurosymbolicVerification] UNSAT for {hypothesis.hypothesis_id} but confidence {formal_spec.extraction_confidence:.2f} < {threshold}; treating as UNKNOWN")
                return Z3VerificationResult(Z3Result.UNKNOWN, 0.5, None, {}, "Spec confidence too low for UNSAT",
                                           z3_result.solver_time, z3_result.constraints_added)
            return z3_result
        except Exception as e:
            self.logger.error(f"[NeurosymbolicVerification] Failed: {e}")
            return None

    def _extract_graph_context(self, knowledge_graph: KnowledgeGraph, hypothesis: AttackHypothesis) -> str:
        """Extract relevant knowledge graph context"""
        relevant_nodes = []
        if hypothesis.target_function:
            for node_id, node_data in knowledge_graph.graph.nodes(data=True):
                if hypothesis.target_function.lower() in str(node_data).lower():
                    relevant_nodes.append(f"- {node_id}: {node_data.get('label', '')}")

        vuln_nodes = []
        for node_id, node_data in knowledge_graph.graph.nodes(data=True):
            if node_data.get('type', '') in ['invariant', 'assumption', 'vulnerability']:
                vuln_nodes.append(f"- {node_id}: {node_data.get('label', '')}")

        context = "Relevant Knowledge Graph Context:\n"
        if relevant_nodes:
            context += "\nTarget Function Context:\n" + "\n".join(relevant_nodes[:5])
        if vuln_nodes:
            context += "\n\nInvariants & Assumptions:\n" + "\n".join(vuln_nodes[:5])
        return context

    def _budget_context_sections(self, sections: List[str]) -> str:
        """Budget context within section and total limits"""
        if not sections:
            return ""
        max_section = getattr(config, "CONTEXT_SECTION_BUDGET", 2000)
        max_total = getattr(config, "CONTEXT_CHAR_BUDGET", 6000)
        combined, total_len = [], 0
        for block in sections:
            if not block:
                continue
            trimmed = block.strip()
            if len(trimmed) > max_section:
                trimmed = trimmed[:max_section] + "\n...[truncated]"
            if total_len + len(trimmed) > max_total:
                remaining = max_total - total_len
                if remaining <= 0:
                    break
                trimmed = trimmed[:remaining] + "\n...[truncated]"
            combined.append(trimmed)
            total_len += len(trimmed)
        return "\n".join(combined)

    def _build_verification_prompt(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any],
                                   graph_context: str, similar_hypotheses: List[AttackHypothesis]) -> str:
        """Build extended thinking verification prompt"""
        context_sections = []

        if sc := contract_info.get("system_context"):
            context_sections.append(f"SYSTEM CONTEXT:\n{sc}")

        if sm := contract_info.get("system_metrics"):
            parts = []
            if cycles := sm.get("cycles"):
                parts.append(f"Cycles: {len(cycles)}")
            if central := sm.get("centrality"):
                parts.append("Central: " + ", ".join(f"{n}({s:.2f})" for n, s in central[:3]))
            if parts:
                context_sections.append("\nSYSTEM METRICS:\n" + "\n".join(parts))

        if semantic := contract_info.get("semantic_snippets"):
            highlights = [f"- {(s.get('metadata', {}) if isinstance(s, dict) else {}).get('signature') or (s.get('metadata', {}) if isinstance(s, dict) else {}).get('name') or 'snippet'}: {(s.get('content', '') if isinstance(s, dict) else str(s)).replace(chr(10), ' ')[:140]}" for s in semantic[:3]]
            if highlights:
                context_sections.append("\nSEMANTIC:\n" + "\n".join(highlights))

        if slices := contract_info.get("code_slices"):
            context_sections.append("\nCODE SLICES:\n" + "\n".join(f"- {s.get('center')}: {len(s.get('nodes', []))} nodes" for s in slices[:3]))

        if invs := contract_info.get("invariants"):
            inv_lines = [inv if isinstance(inv, str) else (inv.get("invariant") or inv.get("description") or str(inv)) for inv in invs[:5]]
            context_sections.append("\nINVARIANTS:\n" + "\n".join(f"- {l}" for l in inv_lines))

        if econ := contract_info.get("economic_findings"):
            context_sections.append("\nECONOMIC:\n" + "\n".join(f"- {f.get('actor', 'econ')}: {f.get('scenario', '')} ({f.get('margin', '?'):.2f if isinstance(f.get('margin'), (int, float)) else '?'})" for f in econ[:2]))

        if logic := contract_info.get("logic_scan_findings"):
            context_sections.append("\nLOGIC:\n" + "\n".join(f"- {(e.get('target_function') if isinstance(e, dict) else '') or 'logic'}: {e.get('description') if isinstance(e, dict) else str(e)}" for e in logic[:3]))

        if struct := contract_info.get("structural_findings"):
            context_sections.append("\nSTRUCTURAL:\n" + "\n".join(f"- {e.get('description') if isinstance(e, dict) else str(e)}" for e in struct[:3]))

        if cov := contract_info.get("structural_coverage"):
            context_sections.append(f"\nCOVERAGE: {cov.get('coverage_score', 0):.2f} (fns {cov.get('functions_covered', 0)}/{cov.get('functions_total', 0)}, taints {cov.get('taint_count', 0)})")

        if hits := contract_info.get("community_hits"):
            context_sections.append("\nGRAPH HITS:\n" + "\n".join(f"- comm {h.get('metadata', {}).get('community','?')}: {h.get('hits')} hits" for h in hits[:3]))

        if ranked := contract_info.get("community_ranked"):
            context_sections.append("\nGRAPH RANKED:\n" + "\n".join(f"- comm {r.get('metadata',{}).get('community','?')}: {r.get('score')} ({r.get('summary','')})" for r in ranked[:3]))

        if taints := contract_info.get("taint_traces"):
            context_sections.append("\nTAINT PATHS:\n" + "\n".join(taints[:5]))

        similar_desc = "\n\nSimilar hypotheses:\n" + "\n".join(f"- {h.attack_type}: {h.description} ({h.confidence:.2f})" for h in similar_hypotheses[:3]) if similar_hypotheses else ""

        context_block = self._budget_context_sections(context_sections)

        prompt = f"""You are a smart contract security verification expert. Your job is to verify whether an attack hypothesis is LOGICALLY SOUND before we generate an expensive PoC.

CONTRACT INFORMATION:
Name: {contract_info.get('name', 'Unknown')}
Key Functions: {', '.join(contract_info.get('external_functions', [])[:10])}
Flash Loan Capable: {contract_info.get('flash_loan_capable', False)}
Has Oracle: {contract_info.get('has_oracle', False)}
CONTEXT:\n{context_block}

{graph_context}

ATTACK HYPOTHESIS TO VERIFY:
Attack Type: {hypothesis.attack_type}
Target Function: {hypothesis.target_function}
Description: {hypothesis.description}
Attack Sequence:
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(hypothesis.steps))}
Original Confidence: {hypothesis.confidence:.2f}
{similar_desc}

YOUR ROLE: ADVERSARIAL EXPLOIT CRITIC (EXTREMELY SKEPTICAL)

Your job is to KILL fake exploits before they embarrass us.

You are NOT a helpful assistant. You are a HOSTILE CRITIC whose entire purpose
is to find flaws and prove this hypothesis is WRONG.

**MINDSET: Assume the AI is hallucinating unless proven otherwise.**

AI language models are EXCELLENT at generating confident-sounding exploits that
don't actually work. Your job is to catch these BEFORE we waste time on PoCs
or worse, submit fake vulnerabilities to bug bounty programs (instant ban).

═══════════════════════════════════════════════════════════════════

ADVERSARIAL INTERROGATION PROTOCOL:

1. MENTAL SIMULATION (STEP-BY-STEP EXECUTION)

   **Trace through EVERY SINGLE STEP** of this attack:
   - Start from initial state
   - What is the EXACT state after step 1?
   - What is the EXACT state after step 2?
   - Continue for ALL steps

   **AT WHICH EXACT STEP DOES IT BREAK?**
   - Does a require() statement revert?
   - Does a modifier block execution?
   - Is there insufficient balance/allowance?
   - Does a guard prevent reentrancy?
   - Is atomicity assumption violated?

   **RED FLAGS:**
   - Vague steps like "manipulate state" without specifics
   - Ignoring obvious guards/checks visible in code
   - Assuming preconditions without verifying them
   - Magic state transitions that aren't possible

   **ADDITIONAL SKEPTICISM REQUIREMENTS:**
   - Is this vulnerability actually exploitable in practice, or only theoretical?
   - What specific transaction sequence proves exploitability?
   - Are there any implicit assumptions being made about contract state?
   - Does the attack require unrealistic capital or timing?
   - Would MEV bots or other actors prevent this attack?

   If you cannot definitively answer ALL of these questions favorably, reject the hypothesis.

2. CODE VERIFICATION (LINE-BY-LINE CHECK)

   **For each claimed precondition, CHECK THE ACTUAL CODE:**
   - Does function X actually exist? (Search the source)
   - Is access control missing? (Check modifiers, require statements)
   - Can state be manipulated? (Trace the actual state variables)
   - Are there hidden protections? (Check inheritance, libraries)

   **VERIFY EVERY CLAIM:**
   - "Function has no access control" → Find the function, read modifiers
   - "Balance can be manipulated" → Trace all balance modifications
   - "Reentrancy is possible" → Check for guards, state updates

   If you can't find the claimed vulnerability in the actual code, REJECT.

3. HALLUCINATION PATTERNS (COMMON AI MISTAKES)

   **AI hallucinates these frequently:**
   - Reentrancy without checking for guards (most contracts have guards)
   - Flash loan attacks without checking loan requirements
   - Oracle manipulation without checking actual oracle implementation
   - Access control bugs when modifiers clearly exist
   - Integer overflow in Solidity 0.8+ (built-in protection)

   **Does this hypothesis match a hallucination pattern?**
   If yes, double-check with EXTREME skepticism.

4. ECONOMIC SANITY CHECK

   **Would a rational attacker actually do this?**
   - Profit calculation: Is it positive after gas/capital costs?
   - Capital requirements: Does attacker have the funds?
   - Risk assessment: What if a step fails mid-attack?
   - Opportunity cost: Are there easier targets?

   **RED FLAGS:**
   - Attack costs more than profit
   - Requires unrealistic capital (billions)
   - Success depends on lucky timing
   - Relies on other users' actions

5. STATE CONSISTENCY CHECK

   **After the attack, does state make sense?**
   - Are balances consistent? (No creation/destruction of value)
   - Are invariants maintained? (Or explicitly broken as the vuln)
   - Can the attacker actually withdraw/realize profit?
   - Does contract become permanently broken?

   If state ends up impossible/inconsistent, the attack is fake.

6. PAST REJECTIONS (LEARN FROM HISTORY)

   **Have similar hypotheses been rejected before?**
   Check knowledge graph for rejection patterns.
   If this matches a known false positive pattern, be EXTRA skeptical.

═══════════════════════════════════════════════════════════════════

**DECISION CRITERIA:**

REJECT if ANY of these apply:
- [FAIL] Cannot mentally simulate without hitting a blocker
- [FAIL] Claimed code feature doesn't exist in actual source
- [FAIL] Matches known AI hallucination pattern
- [FAIL] Economics don't make sense (cost > profit)
- [FAIL] State transitions are logically impossible
- [FAIL] Requires unrealistic preconditions
- [FAIL] Vague attack steps without specific details
- [FAIL] Ignores obvious guards/protections in code

APPROVE ONLY if ALL of these are true:
- [PASS] Can mentally simulate entire attack successfully
- [PASS] Every claim verified in actual code
- [PASS] Economics make sense (profit > cost)
- [PASS] State transitions are possible
- [PASS] Preconditions are realistic
- [PASS] Attack steps are specific and concrete
- [PASS] No obvious guards being ignored

**USE YOUR FULL EXTENDED THINKING BUDGET (8K TOKENS):**
Think deeply. Simulate carefully. Check thoroughly. Be ruthless.

Your reputation (and ours) depends on catching fake exploits.
When in doubt, REJECT. Better safe than embarrassed.

Respond in this exact JSON format:
{{
    "verified": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation of your verification decision",
    "issues_found": ["issue 1", "issue 2", ...],
    "priority": 0.0-1.0,
    "recommendations": "what should be done next"
}}

CONTRACT SOURCE (for reference):
```solidity
{contract_source[:3000]}
```

VERIFICATION DECISION:"""

        return prompt

    def _parse_verification_response(
        self,
        response: str,
        hypothesis: AttackHypothesis,
        similar_hypotheses: List[AttackHypothesis]
    ) -> VerificationResult:
        """parse verification response into structured result"""
        try:
            # extract json from response
            start = response.find('{')
            end = response.rfind('}') + 1
            json_str = response[start:end]
            data = json.loads(json_str)

            return VerificationResult(
                hypothesis=hypothesis,
                verified=data.get('verified', False),
                confidence=float(data.get('confidence', 0.0)),
                reasoning=data.get('reasoning', ''),
                issues_found=data.get('issues_found', []),
                similar_to=[h.hypothesis_id for h in similar_hypotheses],
                priority=float(data.get('priority', 0.5))
            )
        except (json.JSONDecodeError, ValueError) as e:
            # parsing failed - default to unverified
            self.logger.warning(f"[VerificationLayer] Failed to parse response: {e}")
            return VerificationResult(
                hypothesis=hypothesis,
                verified=False,
                confidence=0.0,
                reasoning="Failed to parse verification response",
                issues_found=["Parse error"],
                similar_to=[h.hypothesis_id for h in similar_hypotheses],
                priority=0.0
            )

    def _log_rejection_for_learning(self, hypothesis: AttackHypothesis, rejection_reason: str, verification_type: str):
        """Log rejection for KB anti-pattern learning"""
        self.logger.info(f"[Verification] Rejection: {hypothesis.attack_type} ({verification_type}): {rejection_reason}")
        if self.learning_mgr:
            try:
                self.learning_mgr.learn_from_rejection(hypothesis, rejection_reason, "verification",
                                                       getattr(hypothesis, 'contract_name', 'Unknown'))
            except Exception as e:
                self.logger.warning(f"[VerificationLayer] Failed to record rejection in KB: {e}")

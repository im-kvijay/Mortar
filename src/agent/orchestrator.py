"""multi-agent attack orchestrator"""

import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass

from config import config
from utils.llm_backend import LLMBackend
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from kb.knowledge_graph import KnowledgeGraph
from agent.base_attacker import BaseAttacker, AttackHypothesis
from agent.economic_simulator import EconomicSimulator
from agent.a2a_bus import A2ABus
from agent.a2a_integration import A2AAttackAgent
from agent.logic_attacker import LogicAttacker
from kb.hypothesis_ranker import select_hypotheses


class CircuitBreakerError(Exception):
    """circuit breaker tripped"""
    pass


@dataclass
class AttackSession:
    """attack session results"""
    contract_name: str
    attackers: List[str]
    rounds: int
    all_hypotheses: List[AttackHypothesis]
    high_confidence_attacks: List[AttackHypothesis]
    pocs_generated: int
    pocs_validated: int
    total_cost: float
    quality_score: float


class AttackOrchestrator:
    """multi-agent attack orchestrator"""

    def __init__(
        self,
        backend: LLMBackend,
        logger: ResearchLogger,
        cost_manager: CostManager,
        knowledge_graph: KnowledgeGraph = None,
        knowledge_base=None,
        research_gateway=None,
        min_confidence: float = config.MIN_POC_CONFIDENCE,
        enable_arena_learning: bool = False,
        evolution_frequency: int = 5,
        enable_a2a: bool = False,
        enable_econ_sim: bool = config.ENABLE_ECON_SIM,
        audit_id: Optional[str] = None,
    ):
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager
        self.knowledge_graph = knowledge_graph
        self.knowledge_base = knowledge_base
        self.research_gateway = research_gateway
        self.min_confidence = min_confidence
        self.enable_econ_sim = enable_econ_sim
        self.economic_simulator: Optional[EconomicSimulator] = None
        self.audit_id = audit_id

        self.enable_a2a = enable_a2a
        self.a2a_bus = A2ABus() if enable_a2a else None
        self.a2a_wrapped_attackers: List[A2AAttackAgent] = []

        self.enable_arena_learning = enable_arena_learning
        self.evolution_frequency = evolution_frequency
        self.contracts_analyzed = 0

        self._kb_lock = threading.RLock()
        self._consecutive_api_failures = 0
        self._max_consecutive_failures = int(os.getenv("MAX_CONSECUTIVE_API_FAILURES", "5"))
        self._circuit_breaker_open = False

        attack_workers_env = os.getenv("ATTACK_WORKERS", "").strip()
        try:
            parsed_workers = int(attack_workers_env) if attack_workers_env else 0
        except ValueError:
            parsed_workers = 0

        default_attack_workers = max(1, (os.cpu_count() or 1))

        if parsed_workers > 0:
            if parsed_workers > 16:
                self.logger.warning(f"[Orchestrator] ATTACK_WORKERS={parsed_workers} exceeds maximum 16, using 16")
                self.max_attack_workers = 16
            else:
                self.max_attack_workers = parsed_workers
        else:
            self.max_attack_workers = default_attack_workers

        if self.enable_arena_learning:
            try:
                from src.evolution.fitness_evaluator import FitnessEvaluator
                from src.evolution.genetic_engine import GeneticEngine
                from src.evolution.agent_registry import AgentRegistry

                self.fitness_evaluator = FitnessEvaluator()
                self.genetic_engine = GeneticEngine(
                    population_size=4,
                    elite_fraction=0.25,
                    selection_fraction=0.5,
                    mutation_rate=0.15,
                    initial_strategy="mixed"
                )
                self.agent_registry = AgentRegistry()
                self.logger.info("[Orchestrator] Arena Learning ENABLED")
            except ImportError as e:
                self.logger.warning(f"[Orchestrator] Arena Learning unavailable: {e}")
                self.enable_arena_learning = False
                self.fitness_evaluator = None
                self.genetic_engine = None
                self.agent_registry = None
        else:
            self.fitness_evaluator = None
            self.genetic_engine = None
            self.agent_registry = None

    def set_knowledge_graph(self, knowledge_graph: KnowledgeGraph):
        """set or update knowledge graph"""
        self.knowledge_graph = knowledge_graph
        self.logger.info("[Orchestrator] Knowledge graph updated")

        self.attackers = []
        if self.enable_econ_sim:
            self.economic_simulator = EconomicSimulator(
                knowledge_graph=self.knowledge_graph,
                knowledge_base=self.knowledge_base,
                logger=self.logger,
                max_steps=config.ECON_SIM_MAX_STEPS,
                min_margin=config.ECON_SIM_MIN_MARGIN,
            )

    def _check_circuit_breaker(self):
        """check circuit breaker state"""
        if self._circuit_breaker_open:
            raise CircuitBreakerError(
                f"Circuit breaker open after {self._consecutive_api_failures} consecutive API failures. "
                f"LLM quota likely exhausted. Aborting to prevent further waste."
            )

    def _record_api_success(self):
        """record api success"""
        if self._consecutive_api_failures > 0:
            self.logger.info(f"[CircuitBreaker] API call succeeded - resetting failure counter (was {self._consecutive_api_failures})")
        self._consecutive_api_failures = 0

    def _record_api_failure(self, error: Exception):
        """record api failure"""
        error_str = str(error).lower()
        is_quota_error = any(keyword in error_str for keyword in [
            "resource_exhausted", "quota", "rate limit", "monthly spending limit", "insufficient_quota", "429"
        ])

        if is_quota_error:
            self._consecutive_api_failures += 1
            self.logger.warning(f"[CircuitBreaker] API quota/rate limit error detected ({self._consecutive_api_failures}/{self._max_consecutive_failures}): {error}")

            if self._consecutive_api_failures >= self._max_consecutive_failures:
                self._circuit_breaker_open = True
                self.logger.error(f"[CircuitBreaker] TRIPPED: {self._consecutive_api_failures} consecutive quota failures.")
        else:
            self.logger.debug(f"[CircuitBreaker] Non-quota error ignored: {error}")

    def spawn_attackers(self) -> List[BaseAttacker]:
        """spawn attack agents"""
        if self.enable_arena_learning:
            return self._spawn_attackers_with_genomes()

        attackers = []
        attacker_configs = [
            ("flash_loan_attacker", "FlashLoanAttacker"),
            ("oracle_attacker", "OracleAttacker"),
            ("reentrancy_attacker", "ReentrancyAttacker"),
            ("logic_attacker", "LogicAttacker")
        ]

        for module_name, class_name in attacker_configs:
            try:
                module = __import__(f"agent.{module_name}", fromlist=[class_name])
                AttackerClass = getattr(module, class_name)

                attacker = AttackerClass(
                    backend=self.backend,
                    logger=self.logger,
                    cost_manager=self.cost_manager,
                    knowledge_graph=self.knowledge_graph,
                    research_gateway=self.research_gateway
                )
                attackers.append(attacker)
                self.logger.info(f"[Orchestrator] Loaded {class_name}")

            except ImportError as e:
                self.logger.warning(f"[Orchestrator] Could not load {class_name}: {e}")
            except Exception as e:
                self.logger.error(f"[Orchestrator] Error instantiating {class_name}: {e}")

        if not attackers:
            self.logger.error("[Orchestrator] CRITICAL: No attackers could be loaded!")
            raise RuntimeError("Failed to load any attack agents")

        self.logger.info(f"[Orchestrator] Spawned {len(attackers)} attack agents")

        if self.enable_a2a:
            for attacker in attackers:
                attack_type = attacker.__class__.__name__.replace("Attacker", "")
                wrapped = A2AAttackAgent(
                    attacker=attacker,
                    attack_type=attack_type,
                    bus=self.a2a_bus,
                    auto_register=True
                )
                self.a2a_wrapped_attackers.append(wrapped)

            self.logger.info(f"[Orchestrator] Enabled A2A protocol for {len(self.a2a_wrapped_attackers)} agents")

        return attackers

    def cleanup_a2a_agents(self):
        """cleanup a2a agents"""
        if not self.enable_a2a or not self.a2a_wrapped_attackers:
            return

        self.logger.info(f"[Orchestrator] Cleaning up {len(self.a2a_wrapped_attackers)} A2A agents")

        for wrapped_agent in self.a2a_wrapped_attackers:
            try:
                if hasattr(wrapped_agent, 'unregister') and callable(wrapped_agent.unregister):
                    wrapped_agent.unregister()
                if hasattr(wrapped_agent, 'cleanup') and callable(wrapped_agent.cleanup):
                    wrapped_agent.cleanup()
            except Exception as e:
                self.logger.warning(f"[Orchestrator] Error cleaning up A2A agent: {e}")

        self.a2a_wrapped_attackers.clear()

        if self.a2a_bus and hasattr(self.a2a_bus, 'clear_history'):
            try:
                self.a2a_bus.clear_history()
            except Exception as e:
                self.logger.warning(f"[Orchestrator] Error clearing A2A bus history: {e}")

    def _run_economic_simulator(self, contract_info: Dict[str, Any], contract_source: str) -> Tuple[List[AttackHypothesis], List[Dict[str, Any]]]:
        """run economic simulator"""
        econ_hypotheses: List[AttackHypothesis] = []
        econ_summaries: List[Dict[str, Any]] = []

        if self.enable_econ_sim and self.economic_simulator:
            try:
                sim_result = self.economic_simulator.simulate(contract_info, contract_source)
                econ_hypotheses = sim_result.get("hypotheses", [])
                econ_summaries = sim_result.get("summaries", [])
                if econ_summaries:
                    contract_info["economic_findings"] = econ_summaries
                    self.logger.info(f"[Orchestrator] Economic simulator produced {len(econ_summaries)} finding(s)")
            except (RuntimeError, ValueError, KeyError) as exc:
                self.logger.warning(f"[Orchestrator] Economic simulator failed: {exc}", exc_info=True)

        return econ_hypotheses, econ_summaries

    def _integrate_attacker_results(self, attacker_obj: BaseAttacker, attacker_results: List[Any], all_round_results: Dict[str, List[Any]], round_hypotheses: List[AttackHypothesis], hypotheses_lock: threading.Lock) -> None:
        """integrate attacker results into round results"""
        all_round_results[attacker_obj.name].extend(attacker_results)
        with hypotheses_lock:
            for result in attacker_results:
                round_hypotheses.extend(result.hypotheses)

    def _execute_parallel_attackers(self, attackers: List[BaseAttacker], contract_source: str, contract_info: Dict[str, Any], all_round_results: Dict[str, List[Any]], round_hypotheses: List[AttackHypothesis], hypotheses_lock: threading.Lock) -> None:
        """execute attackers in parallel"""
        target_workers = self.max_attack_workers or len(attackers)
        self.logger.info(f"[Orchestrator] Parallel attacker execution enabled (workers={target_workers})")

        with ThreadPoolExecutor(max_workers=min(target_workers, len(attackers))) as executor:
            future_to_attacker = {}
            for attacker in attackers:
                self.logger.info(f"[Orchestrator] {attacker.name} analyzing (parallel)...")
                future = executor.submit(self._execute_attacker_round, attacker, contract_source, contract_info)
                future_to_attacker[future] = attacker

            parallel_timeout = int(os.getenv("ATTACK_PARALLEL_TIMEOUT", "3600"))
            per_future_timeout = int(os.getenv("ATTACK_PER_FUTURE_TIMEOUT", "1800"))

            self.logger.info(f"[Orchestrator] Timeouts configured: overall={parallel_timeout}s, per-future={per_future_timeout}s")

            try:
                for future in as_completed(future_to_attacker.keys(), timeout=parallel_timeout):
                    attacker = future_to_attacker.get(future)
                    attacker_name = attacker.name if attacker else "unknown"

                    try:
                        attacker_obj, results, skip_reason = future.result(timeout=per_future_timeout)
                        if skip_reason == "quota":
                            self.logger.warning(f"[Orchestrator] {attacker_obj.name} skipped due to LLM quota exhaustion.")
                            self._record_api_failure(Exception("RESOURCE_EXHAUSTED: quota"))
                            continue
                        self._record_api_success()
                        self._integrate_attacker_results(attacker_obj, results, all_round_results, round_hypotheses, hypotheses_lock)
                    except TimeoutError:
                        self.logger.error(f"[Orchestrator] {attacker_name} exceeded per-future timeout ({per_future_timeout}s)")
                        future.cancel()
                    except Exception as exc:
                        self.logger.error(f"[Orchestrator] {attacker_name} failed with error: {exc}")
                        self._record_api_failure(exc)
            except TimeoutError:
                self.logger.error(f"[Orchestrator] Overall timeout ({parallel_timeout}s) reached for parallel execution")
                incomplete_count = sum(1 for future in future_to_attacker.keys() if not future.done())
                for future in future_to_attacker.keys():
                    if not future.done():
                        future.cancel()
                self.logger.info(f"[Orchestrator] Preserved results from {len(attackers) - incomplete_count}/{len(attackers)} attackers")

    def _execute_sequential_attackers(self, attackers: List[BaseAttacker], contract_source: str, contract_info: Dict[str, Any], all_round_results: Dict[str, List[Any]], round_hypotheses: List[AttackHypothesis], hypotheses_lock: threading.Lock) -> None:
        """execute attackers sequentially"""
        for attacker in attackers:
            self.logger.info(f"[Orchestrator] {attacker.name} analyzing...")
            try:
                attacker_obj, results, skip_reason = self._execute_attacker_round(attacker, contract_source, contract_info)
                if skip_reason == "quota":
                    self.logger.warning(f"[Orchestrator] {attacker_obj.name} skipped due to LLM quota exhaustion.")
                    self._record_api_failure(Exception("RESOURCE_EXHAUSTED: quota"))
                    continue
                self._record_api_success()
                self._integrate_attacker_results(attacker_obj, results, all_round_results, round_hypotheses, hypotheses_lock)
            except Exception as exc:
                self.logger.error(f"[Orchestrator] {attacker.name} failed with error: {exc}")
                self._record_api_failure(exc)

    def _prune_hypotheses(self, all_hypotheses: List[AttackHypothesis]) -> List[AttackHypothesis]:
        """prune hypotheses"""
        if len(all_hypotheses) > config.MAX_HYPOTHESES:
            self.logger.warning(f"[Orchestrator] Hypothesis list exceeds {config.MAX_HYPOTHESES} entries ({len(all_hypotheses)} total). Pruning lowest confidence hypotheses.")
            all_hypotheses.sort(key=lambda h: h.confidence, reverse=True)
            pruned_count = len(all_hypotheses) - config.MAX_HYPOTHESES
            all_hypotheses = all_hypotheses[:config.MAX_HYPOTHESES]
            self.logger.info(f"[Orchestrator] Pruned {pruned_count} low-confidence hypotheses. Retained {len(all_hypotheses)} hypotheses (min confidence: {all_hypotheses[-1].confidence:.2f})")
        return all_hypotheses

    def _filter_high_confidence_attacks(self, all_hypotheses: List[AttackHypothesis]) -> List[AttackHypothesis]:
        """filter high confidence attacks"""
        high_confidence_attacks: List[AttackHypothesis] = []
        for hyp in all_hypotheses:
            if hyp.confidence < self.min_confidence:
                continue
            if self._is_non_actionable(hyp):
                self.logger.info(f"[Orchestrator] Pruning non-actionable hypothesis {hyp.hypothesis_id}: {hyp.description[:80]}")
                continue
            high_confidence_attacks.append(hyp)
        return high_confidence_attacks

    def _select_final_hypotheses(self, high_confidence_attacks: List[AttackHypothesis], contract_info: Dict[str, Any], kb_mode: Optional[str], kb_suggestions: Optional[List[AttackHypothesis]], forced_hypotheses: Optional[List[AttackHypothesis]], hypothesis_budget: Optional[int], exploration_fraction: Optional[float], allow_kb_enrich: bool) -> List[AttackHypothesis]:
        """select final hypotheses"""
        candidates = self._dedup_hypotheses(high_confidence_attacks)
        forced = forced_hypotheses or []
        if forced:
            candidates = self._dedup_hypotheses(candidates + forced)
        allow_enrich = allow_kb_enrich or (kb_mode in ("enrich",))

        if kb_suggestions:
            self.logger.debug(f"[Orchestrator] Merging {len(kb_suggestions)} KB suggestions into candidate pool")
            candidates = self._dedup_hypotheses(candidates + kb_suggestions)

        budget = hypothesis_budget or config.HYPOTHESIS_BUDGET
        explore = exploration_fraction if exploration_fraction is not None else config.KB_EXPLORATION_FRACTION
        kb_mode = kb_mode or config.KB_MODE
        selected_attacks = select_hypotheses(candidates, contract_info, kb_mode, max(1, budget), explore)

        if allow_enrich and not selected_attacks and config.KB_SECOND_PASS_ON_EMPTY:
            enriched_candidates = self._dedup_hypotheses(candidates + (kb_suggestions or []))
            if enriched_candidates:
                self.logger.info("[Orchestrator] Stage-B enrichment: reranking with KB suggestions")
                selected_attacks = select_hypotheses(enriched_candidates, contract_info, "enrich", max(1, budget), explore)

        return selected_attacks

    def _create_attack_session(self, contract_name: str, attackers: List[BaseAttacker], round_num: int, all_hypotheses: List[AttackHypothesis], selected_attacks: List[AttackHypothesis], all_round_results: Dict[str, List[Any]], econ_hypotheses: List[AttackHypothesis]) -> AttackSession:
        """create final attack session result"""
        pocs_generated = len(selected_attacks)
        pocs_validated = 0

        for attack in selected_attacks:
            self.logger.info(f"[Orchestrator] High-confidence attack: {attack.description[:100]}...")

        total_cost = sum(sum(r.cost for r in results) for results in all_round_results.values())

        quality_score = self._calculate_quality_score(
            all_hypotheses=all_hypotheses,
            high_confidence_attacks=selected_attacks,
            pocs_validated=pocs_validated
        )

        attacker_names = [a.name for a in attackers]
        if econ_hypotheses:
            attacker_names.append("EconomicSimulator")

        session = AttackSession(
            contract_name=contract_name,
            attackers=attacker_names,
            rounds=round_num,
            all_hypotheses=all_hypotheses,
            high_confidence_attacks=selected_attacks,
            pocs_generated=pocs_generated,
            pocs_validated=pocs_validated,
            total_cost=total_cost,
            quality_score=quality_score
        )

        self.logger.info(f"[Orchestrator] Quality score: {quality_score:.2f}")
        self.logger.info(f"[Orchestrator] Total cost: ${total_cost:.4f}")

        return session

    def analyze_contract(self, contract_source: str, contract_info: Dict[str, Any], kb_mode: Optional[str] = None, kb_suggestions: Optional[List[AttackHypothesis]] = None, forced_hypotheses: Optional[List[AttackHypothesis]] = None, hypothesis_budget: Optional[int] = None, exploration_fraction: Optional[float] = None, allow_kb_enrich: bool = False) -> AttackSession:
        """coordinate multi-agent attack analysis"""
        contract_name = contract_info.get("name", "Unknown")
        self.logger.info(f"[Orchestrator] Starting attack analysis on {contract_name}")

        try:
            return self._analyze_contract_impl(
                contract_name=contract_name,
                contract_source=contract_source,
                contract_info=contract_info,
                kb_mode=kb_mode,
                kb_suggestions=kb_suggestions,
                forced_hypotheses=forced_hypotheses,
                hypothesis_budget=hypothesis_budget,
                exploration_fraction=exploration_fraction,
                allow_kb_enrich=allow_kb_enrich,
            )
        except Exception as exc:
            message = str(exc)
            if "RESOURCE_EXHAUSTED" in message or "spending limit" in message or "credits" in message:
                self.logger.error("[Orchestrator] LLM quota hit during attack analysis; returning empty session")
                return AttackSession(
                    contract_name=contract_name,
                    attackers=[],
                    rounds=0,
                    all_hypotheses=[],
                    high_confidence_attacks=[],
                    pocs_generated=0,
                    pocs_validated=0,
                    total_cost=0.0,
                    quality_score=0.0,
                )
            raise

    def _analyze_contract_impl(self, contract_name: str, contract_source: str, contract_info: Dict[str, Any], kb_mode: Optional[str] = None, kb_suggestions: Optional[List[AttackHypothesis]] = None, forced_hypotheses: Optional[List[AttackHypothesis]] = None, hypothesis_budget: Optional[int] = None, exploration_fraction: Optional[float] = None, allow_kb_enrich: bool = False) -> AttackSession:
        """internal implementation separated to allow quota fallback"""
        econ_hypotheses, econ_summaries = self._run_economic_simulator(contract_info, contract_source)

        attackers = self.spawn_attackers()
        self.attackers = attackers

        all_round_results = {attacker.name: [] for attacker in attackers}
        all_hypotheses: List[AttackHypothesis] = list(econ_hypotheses)

        round_num = self._execute_attack_rounds(attackers, contract_source, contract_info, all_round_results, all_hypotheses)

        if forced_hypotheses:
            all_hypotheses.extend(forced_hypotheses)
        if kb_suggestions:
            self.logger.info(f"[Orchestrator] Adding {len(kb_suggestions)} KB suggestions to hypothesis pool (additive)")
            all_hypotheses.extend(kb_suggestions)

        high_confidence_attacks = self._filter_high_confidence_attacks(all_hypotheses)
        selected_attacks = self._select_final_hypotheses(
            high_confidence_attacks,
            contract_info,
            kb_mode,
            kb_suggestions,
            forced_hypotheses,
            hypothesis_budget,
            exploration_fraction,
            allow_kb_enrich
        )

        self.logger.info("[Orchestrator] Attack analysis complete")
        self.logger.info(f"  Total hypotheses: {len(all_hypotheses)}")
        self.logger.info(f"  High confidence (>={self.min_confidence}): {len(selected_attacks)} (candidates={len(high_confidence_attacks)})")
        self.logger.info(f"Hypothesis funnel: {len(all_hypotheses)} generated → {len(high_confidence_attacks)} verified → {len(selected_attacks)} validated")

        session = self._create_attack_session(contract_name, attackers, round_num, all_hypotheses, selected_attacks, all_round_results, econ_hypotheses)

        self.cleanup_a2a_agents()

        return session

    def _execute_attack_rounds(self, attackers: List[BaseAttacker], contract_source: str, contract_info: Dict[str, Any], all_round_results: Dict[str, List[Any]], all_hypotheses: List[AttackHypothesis]) -> int:
        """execute collaborative attack rounds"""
        round_num = 1
        orchestrator_start_time = time.time()
        max_rounds = config.MAX_ORCHESTRATOR_ROUNDS
        orchestrator_timeout = config.ORCHESTRATOR_TIMEOUT_SECONDS

        self.logger.info(f"[Orchestrator] Starting attack orchestration (max rounds: {max_rounds}, timeout: {orchestrator_timeout}s)")

        while True:
            elapsed_time = time.time() - orchestrator_start_time
            remaining_time = orchestrator_timeout - elapsed_time

            try:
                self._check_circuit_breaker()
            except CircuitBreakerError as e:
                self.logger.error(f"[Orchestrator] {e}")
                raise

            if elapsed_time >= orchestrator_timeout:
                self.logger.warning(f"[Orchestrator] HARD TIMEOUT reached ({orchestrator_timeout}s) after {round_num-1} rounds.")
                break

            if round_num > max_rounds:
                self.logger.warning(f"[Orchestrator] MAX ROUNDS limit reached ({max_rounds}).")
                break

            self.logger.info(f"[Orchestrator] ===== ROUND {round_num}/{max_rounds} (elapsed: {elapsed_time:.1f}s, remaining: {remaining_time:.1f}s) =====")

            round_hypotheses = []
            hypotheses_lock = threading.Lock()

            target_workers = self.max_attack_workers or len(attackers)
            if target_workers > 1 and len(attackers) > 1:
                self._execute_parallel_attackers(attackers, contract_source, contract_info, all_round_results, round_hypotheses, hypotheses_lock)
            else:
                self._execute_sequential_attackers(attackers, contract_source, contract_info, all_round_results, round_hypotheses, hypotheses_lock)

            all_hypotheses.extend(round_hypotheses)
            all_hypotheses = self._prune_hypotheses(all_hypotheses)

            synthesis = self._synthesize_findings(round_hypotheses, round_num)
            self._update_kb_with_synthesis(synthesis, contract_info)

            continue_attack, reasoning = self._should_continue(
                round_num=round_num,
                all_hypotheses=all_hypotheses,
                round_hypotheses=round_hypotheses
            )

            self.logger.info(f"[Orchestrator] Round {round_num} decision: {'CONTINUE' if continue_attack else 'STOP'}")
            self.logger.info(f"[Orchestrator] Reasoning: {reasoning}")

            if not continue_attack:
                break

            round_num += 1

        return round_num

    def _execute_attacker_round(self, attacker: BaseAttacker, contract_source: str, contract_info: Dict[str, Any]) -> Tuple[BaseAttacker, List[Any], Optional[str]]:
        """execute attacker.analyze_contract() with quota handling"""
        try:
            results = attacker.analyze_contract(contract_source=contract_source, contract_info=contract_info)
            return attacker, results, None
        except BaseException as exc:
            message = str(exc)
            if "RESOURCE_EXHAUSTED" in message or "spending limit" in message or "credits" in message:
                return attacker, [], "quota"
            raise

    def _synthesize_findings(self, hypotheses: List[AttackHypothesis], round_num: int) -> Dict[str, Any]:
        """synthesize findings from all attackers"""
        synthesis = {
            "round": round_num,
            "total_hypotheses": len(hypotheses),
            "unique_targets": set(),
            "common_targets": [],
            "compositional_attacks": [],
            "contradictions": []
        }

        by_target = {}
        for hyp in hypotheses:
            target = hyp.target_function
            if target not in by_target:
                by_target[target] = []
            by_target[target].append(hyp)

        synthesis["unique_targets"] = set(by_target.keys())

        for target, hyps in by_target.items():
            if len(hyps) >= 2:
                synthesis["common_targets"].append({
                    "target": target,
                    "attackers": [h.attack_type for h in hyps],
                    "confidence": max(h.confidence for h in hyps)
                })

        attack_types = set(h.attack_type for h in hypotheses)
        if len(attack_types) >= 2:
            synthesis["compositional_attacks"].append({
                "types": list(attack_types),
                "potential": "Multiple attack vectors can be combined"
            })

        self.logger.info(f"[Orchestrator] Synthesis: {len(synthesis['unique_targets'])} targets, {len(synthesis['common_targets'])} common")

        return synthesis

    @staticmethod
    def _dedup_hypotheses(hypotheses: List[AttackHypothesis]) -> List[AttackHypothesis]:
        import hashlib
        seen = set()
        deduped: List[AttackHypothesis] = []
        for hyp in hypotheses:
            if hasattr(hyp, "hypothesis_id") and hyp.hypothesis_id:
                key = hyp.hypothesis_id
            else:
                hash_input = f"{hyp.description}|{getattr(hyp, 'attack_type', '')}"
                key = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

            if key in seen:
                continue
            seen.add(key)
            deduped.append(hyp)
        return deduped

    def _update_kb_with_synthesis(self, synthesis: Dict[str, Any], contract_info: Dict[str, Any]):
        """update knowledge graph with synthesized findings"""
        if not self.knowledge_graph:
            self.logger.debug("[Orchestrator] Knowledge graph not available, skipping synthesis update")
            return

        with self._kb_lock:
            for common in synthesis.get("common_targets", []):
                self.knowledge_graph.add_node(
                    node_id=f"vuln_{common['target']}",
                    node_type="vulnerability",
                    name=common["target"],
                    data={
                        "attackers": common["attackers"],
                        "confidence": common["confidence"],
                        "synthesis_round": synthesis["round"]
                    },
                    confidence=common["confidence"]
                )

            for comp in synthesis.get("compositional_attacks", []):
                self.knowledge_graph.add_node(
                    node_id=f"comp_attack_{synthesis['round']}",
                    node_type="compositional_attack",
                    name=f"Compositional: {', '.join(comp['types'])}",
                    data={
                        "attack_types": comp["types"],
                        "potential": comp["potential"]
                    },
                    confidence=config.COMPOSITIONAL_ATTACK_CONFIDENCE
                )

    def _should_continue(self, round_num: int, all_hypotheses: List[AttackHypothesis], round_hypotheses: List[AttackHypothesis]) -> Tuple[bool, str]:
        """decide if should continue attack rounds"""
        if not round_hypotheses:
            return False, "No new hypotheses generated"

        try:
            self.cost_manager.check_budget()
        except Exception as e:
            return False, f"Budget exceeded: {e}"

        high_conf = [h for h in all_hypotheses if h.confidence >= config.ATTACK_HIGH_CONFIDENCE_THRESHOLD]
        if len(high_conf) >= config.ATTACK_STOP_COUNT:
            return False, f"Found {len(high_conf)} high-confidence attacks"

        return True, f"Continue exploring ({len(round_hypotheses)} new hypotheses this round)"

    def incorporate_verification_feedback(self, verification_results: List, contract_name: str) -> None:
        """incorporate verification layer feedback into attack strategy"""
        self.logger.info(f"[Orchestrator] Incorporating verification feedback for {contract_name}")

        rejections_by_attacker = {}
        rejection_patterns = []

        for result in verification_results:
            if not result.verified:
                attacker_type = result.hypothesis.attack_type
                if attacker_type not in rejections_by_attacker:
                    rejections_by_attacker[attacker_type] = []

                rejections_by_attacker[attacker_type].append({
                    'hypothesis': result.hypothesis,
                    'reason': result.rejection_reason,
                    'issues': result.issues_found
                })

                rejection_patterns.append({
                    'attacker': attacker_type,
                    'reason': result.rejection_reason,
                    'hypothesis_desc': result.hypothesis.description[:100]
                })

        for attacker in self.attackers:
            if attacker.name in rejections_by_attacker:
                rejections = rejections_by_attacker[attacker.name]
                self.logger.info(f"[Orchestrator] {attacker.name} had {len(rejections)} rejections")
                reasons = [r['reason'] for r in rejections]
                self.logger.info(f"[Orchestrator]   Common issues: {set(reasons)}")

        if self.knowledge_graph:
            with self._kb_lock:
                for pattern in rejection_patterns:
                    self.knowledge_graph.add_node(
                        node_id=f"rejection_{hash(pattern['hypothesis_desc']) % 10000}",
                        node_type="rejection_pattern",
                        name=f"Rejected: {pattern['attacker']}",
                        data={
                            'attacker': pattern['attacker'],
                            'reason': pattern['reason'],
                            'hypothesis': pattern['hypothesis_desc']
                        },
                        confidence=0.9
                    )

        total_rejections = len(rejection_patterns)
        total_verified = len([r for r in verification_results if r.verified])
        rejection_rate = total_rejections / len(verification_results) if verification_results else 0

        self.logger.info(f"[Orchestrator] Verification feedback summary:")
        self.logger.info(f"  Total hypotheses: {len(verification_results)}")
        self.logger.info(f"  Verified: {total_verified}")
        self.logger.info(f"  Rejected: {total_rejections}")
        self.logger.info(f"  Rejection rate: {rejection_rate:.1%}")

        if rejection_rate > 0.50:
            self.logger.warning(f"[Orchestrator] High rejection rate ({rejection_rate:.1%}) - attackers may need recalibration")

    def _calculate_quality_score(self, all_hypotheses: List[AttackHypothesis], high_confidence_attacks: List[AttackHypothesis], pocs_validated: int) -> float:
        """calculate attack quality score (0.0-1.0)"""
        score = 0.0

        if all_hypotheses:
            breadth = min(len(all_hypotheses) / config.ATTACK_QUALITY_BREADTH_CAP, 1.0)
            score += breadth * config.ATTACK_QUALITY_BREADTH_WEIGHT

        if all_hypotheses:
            quality = len(high_confidence_attacks) / len(all_hypotheses)
            score += quality * config.ATTACK_QUALITY_QUALITY_WEIGHT

        if high_confidence_attacks:
            evidence = pocs_validated / len(high_confidence_attacks)
            score += evidence * config.ATTACK_QUALITY_EVIDENCE_WEIGHT

        return score

    @staticmethod
    def _is_non_actionable(hypothesis: AttackHypothesis) -> bool:
        """detect hypotheses that merely state the absence of an exploit surface"""
        blobs = [
            (hypothesis.description or ""),
            (hypothesis.expected_impact or ""),
            " ".join(hypothesis.steps or []),
        ]
        content = " ".join(blobs).strip().lower()
        if not content:
            return True

        negative_patterns = (
            r"\bno\s+(oracle|dependency|dependencies|reentrancy|flash loan|risk|issue|bug)\b",
            r"\bno\s+vulnerability\b",
            r"\bnot\s+vulnerable\b",
            r"\bsafe\s+from\b",
            r"\bcannot\s+be\s+exploited\b",
            r"\bno\s+security\s+impact\b",
            r"\bwithout\s+any\s+oracle\b",
        )
        if any(re.search(pattern, content) for pattern in negative_patterns):
            has_steps = any(step.strip() for step in hypothesis.steps or [])
            if not has_steps:
                return True
        return False

    def evaluate_fitness_and_maybe_evolve(self, session: AttackSession, verification_results: List[Any]):
        """evaluate agent fitness and trigger evolution if needed"""
        if not self.enable_arena_learning:
            return

        from src.evolution.fitness_evaluator import AttackResults

        self.logger.info("[Orchestrator] ARENA LEARNING: Evaluating fitness...")

        self.contracts_analyzed += 1

        fitness_scores = {}

        for attacker in self.attackers:
            attack_results = AttackResults.from_attack_session(
                agent_id=getattr(attacker, 'genome_id', 'baseline'),
                agent_name=attacker.name,
                session=session,
                verifications=verification_results
            )

            fitness_score = self.fitness_evaluator.evaluate(
                agent_id=attack_results.agent_id,
                results=attack_results
            )

            fitness_scores[attack_results.agent_id] = fitness_score.fitness

            if hasattr(attacker, 'genome'):
                self.agent_registry.register_agent(attacker.genome, fitness_score)

            self.logger.info(f"[Orchestrator]   {attacker.name}: fitness={fitness_score.fitness:.3f}")
            self.logger.info(f"[Orchestrator]     - Quality: {fitness_score.quality_score:.3f}")
            self.logger.info(f"[Orchestrator]     - Precision: {fitness_score.precision_score:.3f}")
            self.logger.info(f"[Orchestrator]     - Efficiency: {fitness_score.efficiency_score:.3f}")
            self.logger.info(f"[Orchestrator]     - Novelty: {fitness_score.novelty_score:.3f}")

        if self.contracts_analyzed % self.evolution_frequency == 0:
            self.logger.info(f"\n[Orchestrator] ARENA LEARNING: Triggering evolution (contract #{self.contracts_analyzed})")
            self.genetic_engine.evolve_generation(fitness_scores)

            stats = self.genetic_engine.get_generation_stats()
            self.logger.info(f"[Orchestrator] Evolution complete:")
            self.logger.info(f"  - Generation: {stats['current_generation']}")
            self.logger.info(f"  - Avg fitness: {stats['latest_avg_fitness']:.3f}")
            self.logger.info(f"  - Max fitness: {stats['latest_max_fitness']:.3f}")
            self.logger.info(f"  - Improvement: {stats['fitness_improvement_pct']:.1f}%\n")

    def _spawn_attackers_with_genomes(self) -> List[BaseAttacker]:
        """spawn attackers using evolved genomes from genetic engine"""
        population = self.genetic_engine.get_population()

        attacker_configs = [
            ("flash_loan_attacker", "FlashLoanAttacker", "flash_loan"),
            ("oracle_attacker", "OracleAttacker", "oracle"),
            ("reentrancy_attacker", "ReentrancyAttacker", "reentrancy"),
            ("logic_attacker", "LogicAttacker", "logic")
        ]

        attackers = []

        for i, (module_name, class_name, attacker_type) in enumerate(attacker_configs):
            try:
                module = __import__(f"agent.{module_name}", fromlist=[class_name])
                AttackerClass = getattr(module, class_name)
            except ImportError as e:
                self.logger.warning(f"[Orchestrator] Arena Learning: Could not load {class_name}: {e}")
                continue
            except Exception as e:
                self.logger.error(f"[Orchestrator] Arena Learning: Error loading {class_name}: {e}")
                continue

            genome = population[i % len(population)]

            try:
                config_dict = genome.to_agent_config(attacker_type)

                attacker = AttackerClass(
                    backend=self.backend,
                    logger=self.logger,
                    cost_manager=self.cost_manager,
                    knowledge_graph=self.knowledge_graph,
                    research_gateway=self.research_gateway,
                    thinking_budget=config_dict['thinking_budget']
                )

                attacker.genome = genome
                attacker.genome_id = genome.get_id()
                attacker.evolution_config = config_dict

                attackers.append(attacker)

                self.logger.info(f"[Orchestrator] Spawned {attacker.name} with genome {genome.get_id()}")
                self.logger.info(f"[Orchestrator]   - Thinking budget: {config_dict['thinking_budget']}")
                self.logger.info(f"[Orchestrator]   - Prompt variant: {config_dict['system_prompt_variant']['name']}")
                self.logger.info(f"[Orchestrator]   - Generation: {genome.generation}")

            except Exception as e:
                self.logger.error(f"[Orchestrator] Arena Learning: Error instantiating {class_name} with genome: {e}")
                continue

        if not attackers:
            self.logger.error("[Orchestrator] Arena Learning: CRITICAL: No attackers could be spawned with genomes!")
            raise RuntimeError("Failed to spawn any attack agents with genomes")

        return attackers

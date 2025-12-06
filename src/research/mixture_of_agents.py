"""
mixture of agents orchestrator: parallel proposers + meta-aggregator synthesis
phase 1: 6 specialists run in parallel
phase 2: meta-aggregator synthesizes findings into unified report
"""

import time
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple, Optional, Callable
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import config

from research.base_specialist import EnhancedAgenticSpecialist, EnhancedAnalysisResult
from research.memory import Discovery
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from utils.llm_backend import create_backend
from agent.a2a_bus import (
    get_a2a_bus,
    A2ABus,
    A2AMessage,
    MessageType,
    PeerReviewResponse,
    AgentStatus
)
from agent.agent_card import create_research_specialist_card

logger = logging.getLogger(__name__)


class MixtureOfAgentsOrchestrator:
    """orchestrates mixture of agents analysis with parallel proposers + meta-aggregator synthesis"""

    def __init__(
        self,
        project_root: Path,
        cost_manager: CostManager,
        logger: ResearchLogger,
        backend_type: str = None,
        model: str = None,
        api_key: str = None,
        cost_limit: float = None,
        max_workers: int = 6,
        enable_parallel: bool = True,
        enable_a2a: bool = True,
        enable_incremental_sharing: bool = False
    ):
        self.project_root = project_root
        self.cost_manager = cost_manager
        self.logger = logger
        self.backend_type = backend_type or config.DEFAULT_BACKEND_TYPE
        self.model = model or config.DEFAULT_MODEL
        self.api_key = api_key
        self.cost_limit = cost_limit
        self.max_workers = max_workers
        self.enable_parallel = enable_parallel
        self.enable_a2a = enable_a2a
        self.enable_incremental_sharing = enable_incremental_sharing

        self.a2a_bus = get_a2a_bus() if enable_a2a else None
        self._a2a_registered_agents: Dict[str, Callable] = {}
        self._specialist_agent_ids: Dict[str, str] = {}

        # model assignments for specialists
        self.model_assignments = {
            "EnhancedBusinessLogicAnalyst": self.model,
            "EnhancedStateFlowAnalyst": self.model,
            "EnhancedInvariantAnalyst": self.model,
            "EnhancedEconomicAnalyst": self.model,
            "EnhancedDependencyAnalyst": self.model,
            "EnhancedAccessControlAnalyst": self.model,
        }

        logger.info("="*70)
        logger.info("[MoA] mixture of agents orchestrator")
        logger.info(f"   parallel proposers: {max_workers}")
        logger.info("   meta-aggregation: enabled")
        logger.info(f"   a2a peer review: {'enabled' if enable_a2a else 'disabled'}")
        logger.info("="*70)

    def run_moa_analysis(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph
    ) -> Tuple[KnowledgeGraph, Dict[str, List[EnhancedAnalysisResult]], float]:
        """run complete moa analysis: phase 1 proposers + phase 2 meta-aggregator"""
        contract_name = contract_info.get("name", "Unknown")

        logger.info("="*70)
        logger.info(f"moa: starting analysis of {contract_name}", extra={"contract": contract_name, "phase": "moa_start"})
        logger.info("="*70)

        start_time = time.time()
        # graphrag-lite routing context: attach top-ranked communities/summaries for specialists
        retrieval_summaries = contract_info.get("community_ranked") or contract_info.get("graph_summaries") or []
        if retrieval_summaries:
            contract_info["retrieval_summaries"] = retrieval_summaries[:5]

        # phase 1: parallel proposers
        logger.info("phase 1: parallel proposers", extra={"phase": "moa_proposers"})
        if self.enable_incremental_sharing:
            logger.info("   incremental sharing: enabled (specialists build on previous findings)")
        else:
            logger.info("   incremental sharing: disabled (specialists run independently)")
        logger.info("   spawning v3 specialists...")

        specialist_results = self._run_proposers(
            contract_source=contract_source,
            contract_info=contract_info,
            knowledge_graph=knowledge_graph
        )

        # phase 2: meta-aggregator (synthesis)
        logger.info("phase 2: meta-aggregator synthesis", extra={"phase": "moa_aggregation"})
        logger.info("   analyzing findings from all specialists...")

        aggregated_result, quality_score = self._run_meta_aggregator(
            specialist_results=specialist_results,
            contract_source=contract_source,
            contract_info=contract_info,
            knowledge_graph=knowledge_graph
        )

        # knowledge graph already updated by specialists via update_knowledge_graph tool
        specialist_results["meta_aggregator"] = [aggregated_result]

        duration = time.time() - start_time

        logger.info("="*70)
        logger.info("[ok] moa analysis complete", extra={
            "contract": contract_name,
            "phase": "moa_complete",
            "duration": duration,
            "quality_score": quality_score
        })
        logger.info(f"   duration: {duration:.1f}s")
        logger.info(f"   quality score: {quality_score:.3f}")
        logger.info(f"   total discoveries: {sum(len(r.discoveries) for results in specialist_results.values() for r in results)}")
        logger.info(f"   aggregated findings: {len(aggregated_result.discoveries)}")

        # a2a: log bus statistics if enabled
        if self.enable_a2a and self.a2a_bus:
            stats = self.a2a_bus.get_stats()
            logger.info(f"   a2a bus: {stats['total_agents']} agents registered, {stats['total_messages']} messages exchanged",
                       extra={"a2a_agents": stats['total_agents'], "a2a_messages": stats['total_messages']})

        logger.info("="*70)

        return knowledge_graph, specialist_results, quality_score

    def _register_specialist_with_a2a(
        self,
        specialist,
        specialization: str
    ) -> Optional[str]:
        """register specialist with a2a bus and attach message handler for peer-review"""
        if not (self.enable_a2a and self.a2a_bus):
            return None

        agent_card = create_research_specialist_card(
            specialization=specialization,
            agent_id=f"{specialization}Specialist_v3"
        )
        agent_id = agent_card.agent_id

        self.a2a_bus.unregister_agent(agent_id)

        def message_handler(message):
            self.a2a_bus.update_agent_status(agent_id, AgentStatus.BUSY)
            try:
                if message.message_type == MessageType.PEER_REVIEW:
                    review_request = message.payload.get('review_request', {})
                    finding = review_request.get('finding', {}) or {}
                    # content-aware critique (offline-safe)
                    title = (finding.get('title') or finding.get('summary') or finding.get('description') or "").lower()
                    dtype = (finding.get('discovery_type') or finding.get('type') or "unknown").lower()
                    evidence = finding.get('evidence', [])
                    if isinstance(evidence, list):
                        ev_text = " ".join(str(e) for e in evidence)
                    else:
                        ev_text = str(evidence or "")
                    blob = f"{title} {dtype} {ev_text}".lower()

                    red_flags = any(k in blob for k in [
                        "hypothetical", "assume", "unclear", "unknown", "maybe", "potential", "cannot reproduce"
                    ])
                    strong_ev = any(k in blob for k in [
                        "poc", "assert", "revert", "event", "balance", "foundry"
                    ])
                    category_notes = []
                    if "reentr" in blob:
                        category_notes.append("check cei ordering and reentrancyguard usage")
                    if "flash" in blob:
                        category_notes.append("verify pre/post balance invariants around flash loan")
                    if "oracle" in blob or "price" in blob:
                        category_notes.append("compare twap vs spot; enforce stale-block reads")
                    if any(k in blob for k in ["approve", "arbitrary call", "delegatecall"]):
                        category_notes.append("constrain targets/selectors; enforce role checks")

                    approved = not red_flags
                    base_conf = 0.65 + (0.10 if strong_ev else 0.0) - (0.07 if red_flags else 0.0)
                    confidence = max(0.55, min(0.85, base_conf))
                    critique_parts = []
                    if red_flags:
                        critique_parts.append("evidence weak/ambiguous; needs concrete reproduction")
                    if not strong_ev:
                        critique_parts.append("no concrete poc artifacts; add foundry test or trace")
                    critique_parts.extend(category_notes or ["list concrete pre/post-conditions"])

                    response = PeerReviewResponse(
                        reviewer_id=agent_id,
                        finding_id=finding.get('id', 'unknown'),
                        approved=approved,
                        confidence=confidence,
                        critique=" ".join(critique_parts),
                        issues_found=(['weak_evidence'] if red_flags else []),
                        suggestions=category_notes[:2]
                    )
                    return A2AMessage(
                        message_id=str(uuid.uuid4()),
                        from_agent=agent_id,
                        to_agent=message.from_agent,
                        message_type=MessageType.REVIEW_RESPONSE,
                        payload={'review': response.__dict__},
                        in_reply_to=message.message_id
                    )

                return self.a2a_bus.create_response(
                    from_agent=agent_id,
                    to_agent=message.from_agent,
                    payload={'error': f'message type {message.message_type.value} not yet supported'},
                    in_reply_to=message.message_id
                )
            finally:
                self.a2a_bus.update_agent_status(agent_id, AgentStatus.AVAILABLE)

        registered = self.a2a_bus.register_agent(agent_card, message_handler=message_handler)
        if registered:
            logger.debug(f"[{specialist.name}] [a2a] registered with peer review support",
                        extra={"specialist": specialist.name, "agent_id": agent_id})
        else:
            self.a2a_bus.update_agent_status(agent_id, AgentStatus.AVAILABLE)

        self._a2a_registered_agents[agent_id] = message_handler
        self._specialist_agent_ids[specialist.name] = agent_id
        return agent_id

    def _process_peer_reviews(
        self,
        agent_id: str,
        specialist_name: str,
        discoveries: List[Discovery],
        contract_info: Dict[str, Any]
    ) -> None:
        if not (self.enable_a2a and self.a2a_bus):
            return

        high_conf = [d for d in discoveries if (d.confidence if hasattr(d, 'confidence') else d.get('confidence', 0)) >= 0.80]
        if not high_conf:
            return

        contract_name = contract_info.get("name", "Unknown")

        for discovery in high_conf:
            # Handle both Discovery objects and dicts (base_specialist converts to dicts)
            finding_dict = discovery.to_dict() if hasattr(discovery, 'to_dict') else discovery
            discovery_type = discovery.discovery_type if hasattr(discovery, 'discovery_type') else discovery.get('discovery_type', 'unknown')

            responses = self.a2a_bus.request_peer_review(
                from_agent=agent_id,
                finding=finding_dict,
                context={
                    "contract": contract_name,
                    "specialist": specialist_name,
                    "discovery_type": discovery_type
                },
                review_criteria=["validate", "confidence"]
            )

            if not responses:
                continue

            review_data = []
            adjustment = 0.0
            for resp in responses:
                review_data.append({
                    "reviewer_id": resp.reviewer_id,
                    "approved": resp.approved,
                    "confidence": resp.confidence,
                    "critique": resp.critique,
                    "issues_found": resp.issues_found,
                    "suggestions": resp.suggestions
                })
                delta = 0.0
                delta += 0.08 if resp.approved else -0.10
                delta += (resp.confidence - 0.5) * 0.1
                adjustment += delta

            avg_adjustment = adjustment / len(responses)
            original_conf = discovery.confidence
            new_conf = min(1.0, max(0.0, original_conf + avg_adjustment))
            discovery.confidence = new_conf
            setattr(discovery, "peer_reviews", review_data)

            logger.info(
                f"   [{specialist_name}] [a2a] peer review: {len(responses)} responses, confidence {original_conf:.2f} → {new_conf:.2f}",
                extra={
                    "specialist": specialist_name,
                    "reviews_count": len(responses),
                    "original_confidence": original_conf,
                    "new_confidence": new_conf
                }
            )

    def _run_proposers(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph
    ) -> Dict[str, List[EnhancedAnalysisResult]]:
        """run all 6 v3 specialists as parallel proposers"""
        from src.research.business_logic import EnhancedBusinessLogicAnalyst
        from src.research.state_flow import EnhancedStateFlowAnalyst
        from src.research.invariant import EnhancedInvariantAnalyst
        from src.research.economic import EnhancedEconomicAnalyst
        from src.research.dependency import EnhancedDependencyAnalyst
        from src.research.access_control import EnhancedAccessControlAnalyst

        specialist_classes = [
            EnhancedBusinessLogicAnalyst,
            EnhancedStateFlowAnalyst,
            EnhancedInvariantAnalyst,
            EnhancedEconomicAnalyst,
            EnhancedDependencyAnalyst,
            EnhancedAccessControlAnalyst
        ]

        cost_limit_per_specialist = None
        if self.cost_limit:
            cost_limit_per_specialist = self.cost_limit / (len(specialist_classes) + 1)

        specialist_results = {}

        if self.enable_incremental_sharing:
            if self.enable_parallel:
                logger.info("incremental sharing requires sequential execution. running specialists sequentially.")
            return self._run_specialists_sequential(
                specialist_classes=specialist_classes,
                contract_source=contract_source,
                contract_info=contract_info,
                knowledge_graph=knowledge_graph,
                cost_limit_per_specialist=cost_limit_per_specialist
            )

        if self.enable_parallel:
            logger.info(f"running {len(specialist_classes)} specialists in parallel (max_workers={self.max_workers})")
            specialist_results = self._run_specialists_parallel(
                specialist_classes=specialist_classes,
                contract_source=contract_source,
                contract_info=contract_info,
                knowledge_graph=knowledge_graph,
                cost_limit_per_specialist=cost_limit_per_specialist
            )
        else:
            logger.info(f"running {len(specialist_classes)} specialists sequentially (parallel disabled)")
            specialist_results = self._run_specialists_sequential(
                specialist_classes=specialist_classes,
                contract_source=contract_source,
                contract_info=contract_info,
                knowledge_graph=knowledge_graph,
                cost_limit_per_specialist=cost_limit_per_specialist
            )

        return specialist_results

    def _get_model_for_specialist(self, specialist_class: type) -> str:
        """resolve preferred model for specialist with fallback"""
        return self.model_assignments.get(
            specialist_class.__name__,
            config.DEFAULT_MODEL
        )

    def _run_specialists_parallel(
        self,
        specialist_classes: List[type],
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph,
        cost_limit_per_specialist: float = None
    ) -> Dict[str, List[EnhancedAnalysisResult]]:
        """run specialists in parallel using threadpoolexecutor"""

        def run_specialist(specialist_class):
            """helper function to run single specialist"""
            model = self._get_model_for_specialist(specialist_class)

            specialist = specialist_class(
                backend=create_backend(backend_type=self.backend_type, model=model, api_key=self.api_key),
                project_root=self.project_root,
                cost_limit=cost_limit_per_specialist,
                thinking_budget=config.EXTENDED_THINKING_BUDGET,
                enable_interleaved_thinking=config.ENABLE_INTERLEAVED_THINKING,
                a2a_bus=self.a2a_bus if self.enable_a2a else None,
                a2a_agent_id=None,
                a2a_check_interval=3
            )

            agent_id = None
            if self.enable_a2a and self.a2a_bus:
                specialization = specialist_class.__name__.replace("Enhanced", "").replace("Analyst", "")
                agent_id = self._register_specialist_with_a2a(specialist, specialization)
                specialist.a2a_agent_id = agent_id

            logger.debug(f"[{specialist.name}] using {model.split('-')[-1][:6]}... model",
                        extra={"specialist": specialist.name, "model": model})

            logger.info(f"   [{specialist.name}] starting analysis...", extra={"specialist": specialist.name})

            try:
                if cost_limit_per_specialist:
                    current_cost = specialist.cost_manager.get_current_cost() if hasattr(specialist, 'cost_manager') else 0.0
                    if current_cost >= cost_limit_per_specialist:
                        logger.warning(f"[{specialist.name}] cost limit ${cost_limit_per_specialist:.4f} exceeded before execution",
                                      extra={"specialist": specialist.name, "cost_limit": cost_limit_per_specialist})
                        return (specialist.name, None)

                result = specialist.analyze_contract(
                    contract_source=contract_source,
                    contract_info=contract_info,
                    knowledge_graph=knowledge_graph,
                    prior_discoveries=[]
                )

                if cost_limit_per_specialist and hasattr(specialist, 'cost_manager'):
                    current_cost = specialist.cost_manager.get_current_cost()
                    if current_cost > cost_limit_per_specialist:
                        logger.warning(f"[{specialist.name}] cost limit ${cost_limit_per_specialist:.4f} exceeded: ${current_cost:.4f}",
                                      extra={"specialist": specialist.name, "cost_limit": cost_limit_per_specialist, "current_cost": current_cost})

                if isinstance(result, list):
                    if len(result) > 0:
                        result = result[0]
                    else:
                        logger.error(f"[{specialist.name}] empty result list", extra={"specialist": specialist.name})
                        return (specialist.name, None)

                logger.info(f"   [{specialist.name}] [pass] complete - {len(result.discoveries)} discoveries",
                           extra={"specialist": specialist.name, "discoveries": len(result.discoveries)})

                if agent_id and self.enable_a2a and self.a2a_bus:
                    self._process_peer_reviews(
                        agent_id=agent_id,
                        specialist_name=specialist.name,
                        discoveries=result.discoveries,
                        contract_info=contract_info
                    )

                return (specialist.name, result)

            except Exception as e:
                logger.error(f"[{specialist.name}] Failed: {str(e)}", exc_info=True,
                           extra={"specialist": specialist.name})
                return (specialist.name, None)

        specialist_results = {}

        # Execute specialists in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all specialists
            futures = {
                executor.submit(run_specialist, cls): cls
                for cls in specialist_classes
            }

            # Collect results as they complete
            for future in as_completed(futures):
                specialist_name, result = future.result()
                if result:
                    specialist_results[specialist_name] = [result]

        return specialist_results

    def _run_specialists_sequential(
        self,
        specialist_classes: List[type],
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph,
        cost_limit_per_specialist: float = None
    ) -> Dict[str, List[EnhancedAnalysisResult]]:
        """run specialists sequentially (for debugging)"""

        specialist_results = {}
        cumulative_discoveries: List[Discovery] = []

        for specialist_class in specialist_classes:
            logger.debug(f"Processing specialist class: {specialist_class.__name__}",
                        extra={"specialist_class": specialist_class.__name__})
            model = self._get_model_for_specialist(specialist_class)
            logger.debug(f"Using model: {model}", extra={"model": model})

            agent_id = None
            specialization = specialist_class.__name__.replace("Enhanced", "").replace("Analyst", "")
            logger.debug(f"Creating specialist with backend_type={self.backend_type}, model={model}",
                        extra={"backend_type": self.backend_type, "model": model})

            # Create backend SEPARATELY for debugging
            backend = create_backend(backend_type=self.backend_type, model=model, api_key=self.api_key)
            logger.debug(f"Backend created: {backend}", extra={"backend": str(backend)})

            specialist = specialist_class(
                backend=backend,
                project_root=self.project_root,
                cost_limit=cost_limit_per_specialist,
                thinking_budget=config.EXTENDED_THINKING_BUDGET,
                enable_interleaved_thinking=config.ENABLE_INTERLEAVED_THINKING,
                a2a_bus=self.a2a_bus if self.enable_a2a else None,
                a2a_agent_id=agent_id,
                a2a_check_interval=3
            )
            if hasattr(specialist, "retrieval_summaries"):
                specialist.retrieval_summaries = contract_info.get("retrieval_summaries", [])
            logger.debug(f"Specialist created: {specialist.name}", extra={"specialist": specialist.name})

            if self.enable_a2a and self.a2a_bus:
                logger.debug("registering with a2a...")
                agent_id = self._register_specialist_with_a2a(specialist, specialization)
                specialist.a2a_agent_id = agent_id
                logger.debug(f"a2a registration complete: agent_id={agent_id}", extra={"agent_id": agent_id})

            logger.info(f"   [{specialist.name}] starting analysis...", extra={"specialist": specialist.name})
            logger.debug("about to call analyze_contract...")

            try:
                result = specialist.analyze_contract(
                    contract_source=contract_source,
                    contract_info=contract_info,
                    knowledge_graph=knowledge_graph,
                    prior_discoveries=list(cumulative_discoveries)
                )

                if isinstance(result, list):
                    if result:
                        result = result[0]
                    else:
                        logger.error(f"[{specialist.name}] empty result list", extra={"specialist": specialist.name})
                        continue

                specialist_results[specialist.name] = [result]
                logger.info(f"   [{specialist.name}] [pass] complete - {len(result.discoveries)} discoveries",
                           extra={"specialist": specialist.name, "discoveries": len(result.discoveries)})

                if agent_id and self.enable_a2a and self.a2a_bus:
                    self._process_peer_reviews(
                        agent_id=agent_id,
                        specialist_name=specialist.name,
                        discoveries=result.discoveries,
                        contract_info=contract_info
                    )

                cumulative_discoveries.extend(result.discoveries)

            except Exception as e:
                logger.error(f"[{specialist.name}] failed: {str(e)}", exc_info=True,
                           extra={"specialist": specialist.name})
                if hasattr(self.logger, "log_error"):
                    self.logger.log_error(
                        agent_name=specialist.name,
                        contract_name=contract_info.get("name", "Unknown"),
                        error_type=type(e).__name__,
                        error_message=str(e),
                        context={"phase": "moa_proposers"}
                    )
                else:
                    self.logger.error(
                        f"moa specialist {specialist.name} failed during sequential run: {e}"
                    )

        return specialist_results

    def _run_meta_aggregator(
        self,
        specialist_results: Dict[str, List[EnhancedAnalysisResult]],
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph
    ) -> Tuple[EnhancedAnalysisResult, float]:
        """meta-aggregator synthesizes all specialist findings"""
        from research.meta_aggregator import MetaAggregator

        meta_aggregator = MetaAggregator(
            backend=create_backend(backend_type=self.backend_type, model=self.model, api_key=self.api_key),
            project_root=self.project_root,
            thinking_budget=12000,
            enable_interleaved_thinking=True
        )

        aggregated_result = meta_aggregator.synthesize_findings(
            specialist_results=specialist_results,
            contract_source=contract_source,
            contract_info=contract_info,
            knowledge_graph=knowledge_graph
        )

        quality_score = self._calculate_moa_quality(
            specialist_results=specialist_results,
            aggregated_result=aggregated_result
        )

        return aggregated_result, quality_score

    def _calculate_moa_quality(
        self,
        specialist_results: Dict[str, List[EnhancedAnalysisResult]],
        aggregated_result: EnhancedAnalysisResult
    ) -> float:
        """calculate quality score based on coverage, consensus, aggregation, and richness"""
        score = 0.0

        # specialist coverage (25%)
        expected_specialists = 6
        actual_specialists = len([r for r in specialist_results.values() if r and r[0]])
        coverage = actual_specialists / expected_specialists
        score += coverage * 0.25

        # consensus findings (30%)
        consensus_count = sum(
            1 for discovery in aggregated_result.discoveries
            if (discovery.confidence if hasattr(discovery, 'confidence')
                else discovery.get('confidence', 0)) >= 0.8
        )
        consensus_score = min(consensus_count / 15, 1.0)
        score += consensus_score * 0.30

        # aggregation quality (25%)
        aggregation_quality = aggregated_result.confidence
        score += aggregation_quality * 0.25

        # discovery richness (20%)
        total_discoveries = sum(
            len(r.discoveries) for results in specialist_results.values()
            for r in results if r
        )
        richness = min(total_discoveries / 50, 1.0)
        score += richness * 0.20

        return min(score, 1.0)

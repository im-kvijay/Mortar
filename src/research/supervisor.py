"""supervisor agent - orchestrates specialist agents for contract analysis"""
import logging
import time
import sys
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import config
from kb.knowledge_base import KnowledgeBase
from agent.logic_scanner import LogicVulnScanner
from verification.iris_lite import IrisLite
from research.dependency_refiner import DependencyRefiner

from research.base_specialist import BaseSpecialist, AnalysisResult
from research.state_flow import StateFlowAnalyst
from research.invariant import InvariantAnalyst
from research.business_logic import BusinessLogicAnalyst
from research.economic import EconomicAnalyst
from research.dependency import DependencyAnalyst
from research.access_control import AccessControlAnalyst
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from utils.llm_backend import create_backend  # For ACE integration
from research.state_modeler import StateModeler
from research.taint_tracer import trace_taint_paths
from cal.code_graph import CodeGraph
from cal.slither_runner import run_slither, find_slither
from research.metadata_injector import MetadataInjector


class Supervisor:
    """Orchestrates multiple specialists for contract analysis"""

    def __init__(
        self,
        project_root: Optional[str] = None,
        cost_limit: Optional[float] = None,
        max_team_rounds: Optional[int] = None,
        backend_type: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        enable_v3: bool = False,
        enable_moa: bool = False,
        enable_ace: bool = False,
        enable_a2a: bool = False,
        knowledge_base: Optional[KnowledgeBase] = None,
        disable_kb_bootstrap: bool = False,
    ):
        """Initialize supervisor with config defaults"""
        self.project_root = Path(project_root or str(config.PROJECT_ROOT))
        self.cost_limit = cost_limit or config.DEFAULT_COST_LIMIT_PER_CONTRACT
        self.max_team_rounds = max_team_rounds or config.MAX_TEAM_ROUNDS
        self.backend_type = backend_type or config.DEFAULT_BACKEND_TYPE
        self.model = model or config.DEFAULT_MODEL
        self.api_key = api_key
        self.enable_v3 = enable_v3
        self.enable_moa = enable_moa
        self.enable_ace = enable_ace
        self.enable_a2a = enable_a2a
        self.knowledge_base = knowledge_base
        self.disable_kb_bootstrap = disable_kb_bootstrap

        if self.enable_moa and not self.enable_v3:
            logger.info("MoA requires V3 specialists. Enabling V3 automatically.", extra={"mode": "moa", "auto_enable": "v3"})
            self.enable_v3 = True
        if self.enable_moa and not self.enable_a2a:
            logger.info("MoA uses parallel execution. Enabling A2A for real-time collaboration.", extra={"mode": "moa", "auto_enable": "a2a"})
            self.enable_a2a = True
        if self.enable_ace and not self.enable_v3:
            logger.info("ACE requires V3 specialists. Enabling V3 automatically.", extra={"mode": "ace", "auto_enable": "v3"})
            self.enable_v3 = True
        if self.enable_a2a and not self.enable_v3:
            logger.info("A2A protocol works best with V3 specialists. Enabling V3 automatically.", extra={"mode": "a2a", "auto_enable": "v3"})
            self.enable_v3 = True
        self.logger = ResearchLogger(project_root=str(self.project_root))
        self.cost_manager = CostManager(max_cost_per_contract=self.cost_limit)
        self.state_modeler = StateModeler()
        from research.invariant_expander import InvariantExpander
        self.invariant_expander = InvariantExpander()
        self.logic_scanner = LogicVulnScanner()
        self.iris_lite = IrisLite()
        self.dependency_refiner = DependencyRefiner()
        self.specialists: List[BaseSpecialist] = []
        self.moa_orchestrator = None

        if self.enable_moa:
            from src.research.mixture_of_agents import MixtureOfAgentsOrchestrator
            self.moa_orchestrator = MixtureOfAgentsOrchestrator(
                project_root=self.project_root,
                cost_manager=self.cost_manager,
                logger=self.logger,
                backend_type=self.backend_type,
                model=self.model,
                api_key=self.api_key,
                cost_limit=self.cost_limit,
                max_workers=6,
                enable_parallel=True
            )

        self.a2a_bus = None
        if self.enable_a2a:
            from src.agent.a2a_v3_protocol import A2ABusV3
            self.a2a_bus = A2ABusV3(
                use_grpc=False,
                enable_signatures=False,
                logger=ResearchLogger()
            )

    def _find_target_project_root(self, contract_path: Path) -> Path:
        """Find Foundry project root by walking up looking for foundry.toml"""
        current = contract_path.parent if contract_path.is_file() else contract_path
        for _ in range(10):
            if (current / "foundry.toml").exists() and ((current / "src").exists() or (current / "contracts").exists()):
                return current
            parent = current.parent
            if parent == current:
                break
            current = parent
        return self.project_root

    def spawn_specialists(self) -> List[BaseSpecialist]:
        """Spawn specialist agents based on V3/ACE configuration"""
        logger.info("Spawning specialist agents", extra={"mode": "V3 Enhanced" if self.enable_v3 else "Standard", "v3_enabled": self.enable_v3})

        if self.enable_v3:
            from research.business_logic import EnhancedBusinessLogicAnalyst
            from research.state_flow import EnhancedStateFlowAnalyst
            from research.invariant import EnhancedInvariantAnalyst
            from research.economic import EnhancedEconomicAnalyst
            from research.dependency import EnhancedDependencyAnalyst
            from research.access_control import EnhancedAccessControlAnalyst

            specialist_classes = [
                EnhancedBusinessLogicAnalyst,
                EnhancedStateFlowAnalyst,
                EnhancedInvariantAnalyst,
                EnhancedEconomicAnalyst,
                EnhancedDependencyAnalyst,
                EnhancedAccessControlAnalyst,
            ]
        else:
            specialist_classes = [
                BusinessLogicAnalyst,
                StateFlowAnalyst,
                InvariantAnalyst,
                EconomicAnalyst,
                DependencyAnalyst,
                AccessControlAnalyst,
            ]

        cost_limit_per_specialist = self.cost_limit / len(specialist_classes) if self.cost_limit else None
        specialists: List[BaseSpecialist] = []

        if self.enable_ace and self.enable_v3:
            from research.ace_integration import create_ace_specialist
            for SpecialistClass in specialist_classes:
                specialist = create_ace_specialist(
                    specialist_class=SpecialistClass,
                    backend=create_backend(model=self.model),
                    logger=ResearchLogger(),
                    project_root=self.project_root,
                    enable_ace=True
                )
                if self.knowledge_base:
                    specialist.knowledge_base = self.knowledge_base
                specialists.append(specialist)
                logger.info("Specialist created", extra={"name": specialist.name, "type": "V3+ACE", "description": getattr(specialist, "description", "Self-improving specialist")})
        else:
            for SpecialistClass in specialist_classes:
                is_v3 = "Enhanced" in SpecialistClass.__name__
                specialist = SpecialistClass(
                    project_root=str(self.project_root),
                    backend_type=self.backend_type,
                    model=self.model,
                    cost_limit=cost_limit_per_specialist,
                    thinking_budget=None if not is_v3 else None,
                    enable_interleaved_thinking=True if is_v3 else False,
                ) if is_v3 else SpecialistClass(
                    project_root=str(self.project_root),
                    backend_type=self.backend_type,
                    model=self.model,
                    cost_limit=cost_limit_per_specialist,
                )
                if self.knowledge_base:
                    specialist.knowledge_base = self.knowledge_base
                specialists.append(specialist)
                logger.info("Specialist created", extra={"name": specialist.name, "version": "V3 Enhanced" if is_v3 else "V1", "description": specialist.description})

        if self.enable_a2a and self.a2a_bus:
            from agent.a2a_v3_protocol import AgentCardV3
            for specialist in specialists:
                self.a2a_bus.register(AgentCardV3(
                    agent_id=f"specialist_{specialist.name.lower().replace(' ', '_')}",
                    name=specialist.name,
                    capabilities=[specialist.name.lower()],
                    supported_contract_types=["DeFi", "NFT", "DAO", "Token"],
                    status="available",
                    quality_score=0.0,
                    cost_per_request=0.0,
                    protocol_version="0.3",
                    streaming_supported=False,
                    max_concurrent_tasks=1,
                ))
                logger.debug("A2A specialist registered", extra={"specialist": specialist.name})
            stats = self.a2a_bus.get_stats()
            logger.info("A2A bus initialized", extra={"total_agents": stats['total_agents'], "available": stats['agents_by_status'].get('available', 0)})

        self.specialists = specialists
        return specialists

    def calculate_research_quality(self, knowledge_graph: KnowledgeGraph, specialist_results: Dict[str, List[Any]], contract_info: Dict[str, Any]) -> float:
        """Calculate quality score (0.0-1.0) based on domain coverage, graph completeness, consensus, depth, cross-validation"""
        score = 0.0
        def avg_conf(discoveries):
            return sum(getattr(d, 'confidence', 0.5) for d in discoveries) / len(discoveries) if discoveries else 0.5

        required_domains = ["business_logic", "state_transitions", "invariant"]
        domain_confidence_scores = {}
        domains_found = set()

        bl_nodes = knowledge_graph.get_nodes_by_type(NodeType.BUSINESS_LOGIC)
        if bl_nodes:
            domains_found.add("business_logic")
            bl_discoveries = [d for results in specialist_results.values() for result in results for d in result.discoveries if hasattr(d, 'discovery_type') and 'business' in str(d.discovery_type).lower()]
            domain_confidence_scores["business_logic"] = avg_conf(bl_discoveries)

        state_nodes = knowledge_graph.get_nodes_by_type(NodeType.STATE_VAR)
        if state_nodes:
            domains_found.add("state_transitions")
            state_discoveries = [d for results in specialist_results.values() for result in results for d in result.discoveries if hasattr(d, 'discovery_type') and 'state' in str(d.discovery_type).lower()]
            domain_confidence_scores["state_transitions"] = avg_conf(state_discoveries)

        inv_nodes = knowledge_graph.get_nodes_by_type(NodeType.INVARIANT)
        if inv_nodes:
            domains_found.add("invariant")
            inv_discoveries = [d for results in specialist_results.values() for result in results for d in result.discoveries if hasattr(d, 'discovery_type') and 'invariant' in str(d.discovery_type).lower()]
            domain_confidence_scores["invariant"] = avg_conf(inv_discoveries)

        weighted_coverage = sum(domain_confidence_scores.get(d, 0.5) for d in domains_found) / len(required_domains) if domains_found else 0.0
        score += weighted_coverage * 0.30
        total_functions = max(1, int(contract_info.get("total_functions") or 0), int(knowledge_graph.metadata.get("total_functions", 0) or 0))
        total_state_vars = max(1, int(contract_info.get("total_state_vars") or 0), int(knowledge_graph.metadata.get("total_state_vars", 0) or 0))
        analyzed_funcs = len(knowledge_graph.metadata.get("analyzed_functions", set()))
        traced_vars = len(knowledge_graph.metadata.get("traced_state_vars", set()))
        score += min(analyzed_funcs / total_functions, 1.0) * 0.15
        score += min(traced_vars / total_state_vars, 1.0) * 0.10
        all_discoveries = [d for results in specialist_results.values() for result in results for d in result.discoveries]
        num_specialists = len(specialist_results)

        if num_specialists > 0 and all_discoveries:
            weighted_discovery_count = sum(getattr(d, 'confidence', 0.5) for d in all_discoveries)
            consensus = min((weighted_discovery_count / num_specialists) / 10, 1.0)
            score += consensus * 0.20
        elif num_specialists > 0:
            consensus = min((len(all_discoveries) / num_specialists) / 10, 1.0)
            score += consensus * 0.20

        total_rounds = sum(len(results) for results in specialist_results.values())
        score += min((total_rounds / max(len(specialist_results), 1)) / 5, 1.0) * 0.15

        all_disc_content = [d.content for results in specialist_results.values() for result in results for d in result.discoveries]
        cross_validated = 0
        seen = set()
        for disc in all_disc_content:
            disc_key = disc[:50].lower()
            if disc_key in seen:
                cross_validated += 1
            seen.add(disc_key)
        score += min(cross_validated / 5, 1.0) * 0.10

        return min(score, 1.0)

    @staticmethod
    def _is_quota_error(exc: Exception) -> bool:
        """Detect LLM quota exhaustion from exception message"""
        message = str(exc)
        return bool(message) and any(k in message for k in ("RESOURCE_EXHAUSTED", "spending limit", "credits", "rate limit", "quota"))

    def analyze_contract(self, contract_source: str, contract_info: Dict[str, Any], project_context: Optional[Any] = None) -> Tuple[KnowledgeGraph, Dict[str, List[AnalysisResult]], float]:
        """Analyze contract using specialists (standard or MoA modes), returns (knowledge_graph, specialist_results, quality_score)"""
        contract_name = contract_info.get("name", "Unknown")

        if project_context:
            if hasattr(project_context, 'get_system_view'):
                logger.debug("Using ProjectContext", extra={"contract": contract_name})
                contract_info["system_context"] = project_context.get_system_view()
                contract_info["project_context"] = project_context
                logger.debug("Injected ProjectContext system view", extra={"contract": contract_name})
            elif isinstance(project_context, dict):
                my_summary = project_context.get(contract_name)
                relevant_names = set()
                if my_summary:
                    relevant_names.update(my_summary.dependencies)
                for name, summary in project_context.items():
                    if contract_name in summary.dependencies:
                        relevant_names.add(name)
                system_context_str = "SYSTEM CONTEXT (Related Contracts):\n"
                found_deps = False
                for name, summary in project_context.items():
                    if name != contract_name and (len(project_context) < 10 or name in relevant_names):
                        system_context_str += summary.to_context_string() + "\n\n"
                        found_deps = True
                if found_deps:
                    contract_info["system_context"] = system_context_str
                    logger.debug("Injected system context", extra={"contract": contract_name, "deps_found": True})
        contract_address = contract_info.get("address")
        if contract_address and contract_address.startswith("0x"):
            try:
                injector = MetadataInjector()
                metadata = injector.fetch_metadata(contract_address, contract_info.get("chain", "mainnet"), contract_info.get("fork_block"))
                contract_info["onchain_context"] = injector.format_for_prompt(metadata)
                logger.info("Injected on-chain metadata", extra={"contract": contract_name, "address": contract_address, "eth_balance": metadata.eth_balance, "token_count": len(metadata.token_balances), "is_proxy": metadata.is_proxy})
            except Exception as exc:
                logger.warning("On-chain metadata injection failed", extra={"error": str(exc)})

        logger.info("Starting contract analysis", extra={"contract": contract_name, "moa_mode": self.enable_moa, "v3_specialists": self.enable_v3, "ace_playbooks": self.enable_ace, "a2a_protocol": self.enable_a2a})
        start_time = time.time()
        self.cost_manager.start_contract(contract_name)

        knowledge_graph = KnowledgeGraph(contract_name=contract_name, project_root=str(self.project_root))
        knowledge_graph.metadata["total_functions"] = contract_info.get("total_functions", 0)
        knowledge_graph.metadata["total_state_vars"] = contract_info.get("total_state_vars", 0)

        try:
            state_results = self.state_modeler.analyze(contract_name, contract_source, knowledge_graph)
            contract_info.setdefault("state_vars", state_results.get("state_vars", []))
            knowledge_graph.metadata["total_state_vars"] = len(state_results.get("state_vars", []))
        except Exception as exc:
            logger.warning("State modeler skipped", extra={"error": str(exc)})
        mcg: Optional[CodeGraph] = None
        try:
            mcg = CodeGraph(contract_name)
            slither_json = None
            source_path = contract_info.get("path")
            if source_path and find_slither():
                try:
                    slither_json = run_slither(Path(source_path), self._find_target_project_root(Path(source_path)))
                except Exception as exc:
                    self.logger.warning(f"[Supervisor] Slither parse failed: {exc}")
            mcg.build(contract_source, slither=slither_json)
            slices = []
            for fn in contract_info.get("external_functions", [])[:10]:
                center = f"fn::{fn.split('(')[0]}"
                slice_obj = mcg.slice(center=center, hops=2, max_nodes=60)
                if slice_obj.nodes:
                    slices.append({"center": center, "nodes": slice_obj.nodes, "edges": slice_obj.edges, "metadata": slice_obj.metadata, "invariants": slice_obj.invariants or []})
            contract_info["code_slices"] = slices
            contract_info["code_graph"] = mcg.to_dict()
            community_slices = mcg.graph_communities(max_communities=4, max_nodes=80)
            contract_info["code_communities"] = [{"nodes": s.nodes, "edges": s.edges, "metadata": s.metadata, "invariants": s.invariants or []} for s in community_slices]
            summaries = []
            for comm in community_slices:
                labels = [mcg.graph.nodes.get(n, {}).get("label") or n for n in comm.nodes]
                summaries.append({"summary": ", ".join(labels[:10]), "size": len(comm.nodes), "metadata": comm.metadata})
            if summaries:
                contract_info["graph_summaries"] = summaries
                targets = set([fn.split("(")[0] for fn in contract_info.get("external_functions", [])])
                for t in contract_info.get("taint_traces_struct") or []:
                    if t.get("source"):
                        targets.add(t["source"])
                hit_comm = []
                for comm in community_slices:
                    hits = sum(1 for n in comm.nodes if any(t in mcg.graph.nodes.get(n, {}).get("label", "") for t in targets))
                    if hits:
                        hit_comm.append({"metadata": comm.metadata, "hits": hits, "size": len(comm.nodes)})
                if hit_comm:
                    hit_comm.sort(key=lambda x: (-x["hits"], x["size"]))
                    contract_info["community_hits"] = hit_comm[:3]
                contract_info["community_ranked"] = self.dependency_refiner.rank_communities(summaries=summaries, queries=list(targets) or contract_info.get("state_vars", []), top_k=3)
            if project_context and hasattr(project_context, "merge_contract_graph"):
                try:
                    project_context.merge_contract_graph(contract_name, mcg.graph)
                except Exception as e:
                    logger.warning(f"Failed to merge contract graph: {e}")
            if project_context and hasattr(project_context, "analyze_system"):
                try:
                    contract_info["system_metrics"] = project_context.analyze_system()
                except Exception as e:
                    logger.warning(f"Failed to analyze system metrics: {e}")
            derived_invariants = [inv.replace("invariant::", "") for slice_entry in slices for inv in slice_entry.get("invariants", [])]
            if derived_invariants:
                contract_info["invariants"] = list(dict.fromkeys((contract_info.get("invariants") or []) + derived_invariants))
            if project_context and hasattr(project_context, "system_communities"):
                try:
                    contract_info["system_communities"] = project_context.system_communities(max_communities=3, max_nodes=120)
                except Exception as e:
                    logger.warning(f"Failed to get system communities: {e}")
        except Exception as exc:
            logger.warning("Code graph build skipped", extra={"error": str(exc)})
        try:
            selector_map = {fn.get("selector").replace("0x", ""): f"{contract_name}.{fn.get('name')}" for fn in contract_info.get("external_functions_detail", []) if fn.get("selector") and fn.get("name")}
            taints = trace_taint_paths(contract_source, abi_map=selector_map, contract_name=contract_name)
            contract_info["taint_traces"] = [f"{t['source']} -> {t['sink']} (line {t['line']})" for t in taints]
            contract_info["taint_traces_struct"] = taints
            for t in taints:
                fn_node = f"fn::{t['source']}"
                sink_label = t.get("resolved_target") or t["sink"]
                target_contract, target_fn_label = (sink_label.split(".", 1) if "." in sink_label and len(sink_label.split(".", 1)) == 2 and sink_label.split(".", 1)[0] else (contract_name, sink_label))
                sink_node = f"{target_contract}::call::{target_fn_label}"
                if not knowledge_graph.get_node(fn_node):
                    knowledge_graph.add_node(node_id=fn_node, node_type=NodeType.FUNCTION, name=t["source"], data={"visibility": t.get("visibility")}, discovered_by="taint_tracer", metadata={"component": "dependency"})
                if not knowledge_graph.get_node(sink_node):
                    knowledge_graph.add_node(node_id=sink_node, node_type=NodeType.DEPENDENCY, name=t["sink"], data={"type": "external_sink"}, discovered_by="taint_tracer", metadata={"component": "dependency"})
                knowledge_graph.add_edge(source=fn_node, target=sink_node, edge_type=EdgeType.CALLS, data={"line": t["line"], "taint": True, "target_contract": target_contract if target_contract != contract_name else None}, discovered_by="taint_tracer", metadata={"component": "dependency", "taint": True})
            if mcg:
                mcg.add_taint_traces(taints)
                contract_info["code_graph"] = mcg.to_dict()
            if project_context and hasattr(project_context, "add_taint_paths"):
                try:
                    project_context.add_taint_paths(contract_name, taints)
                except Exception as e:
                    logger.warning(f"Failed to add taint paths: {e}")
            if project_context and hasattr(project_context, "analyze_system"):
                try:
                    contract_info["system_metrics"] = project_context.analyze_system()
                except Exception as e:
                    logger.warning(f"Failed to refresh system metrics: {e}")
        except Exception as exc:
            logger.warning("Taint tracer skipped", extra={"error": str(exc)})
        try:
            contract_info["invariants"] = self.invariant_expander.add_invariants(contract_info, knowledge_graph)
        except Exception as exc:
            logger.warning("Invariant expansion skipped", extra={"error": str(exc)})
        try:
            from dataclasses import asdict
            logic_hypotheses = self.logic_scanner.scan(contract_source=contract_source, contract_info=contract_info, knowledge_graph=knowledge_graph, code_graph=mcg.graph if mcg else None)
            contract_info["logic_scan_findings"] = [asdict(h) for h in logic_hypotheses]
        except Exception as exc:
            logger.warning("Logic scan skipped", extra={"error": str(exc)})
        try:
            structural_findings = self.iris_lite.assess(contract_info, knowledge_graph)
            if structural_findings:
                contract_info["structural_findings"] = structural_findings
        except Exception as exc:
            logger.warning("IRIS-lite skipped", extra={"error": str(exc)})
        try:
            refined = self.dependency_refiner.refine(contract_info)
            if refined:
                contract_info["refined_dependencies"] = refined
        except Exception as exc:
            logger.warning("Dependency refine skipped", extra={"error": str(exc)})
        if getattr(knowledge_graph, "_semantic_enabled", False):
            knowledge_graph.index_semantic_snippets({f"{contract_name}::source": contract_source[:20000]}, metadata={"component": "contract_source"})
        if not contract_info.get("semantic_snippets"):
            pc = contract_info.get("project_context") or project_context
            if pc and hasattr(pc, "get_semantic_slices"):
                try:
                    contract_info["semantic_snippets"] = pc.get_semantic_slices(contract_name, budget=1200)
                except Exception as exc:
                    self.logger.warning(f"[Context] Failed to load semantic slices: {exc}")

        import os
        skip_bootstrap = self.disable_kb_bootstrap or bool(os.getenv("FRESH_ANALYSIS", "0") != "0")
        if skip_bootstrap:
            logger.info("KB bootstrap disabled - starting fresh", extra={"reason": "FRESH_ANALYSIS mode" if os.getenv("FRESH_ANALYSIS") else "disable_kb_bootstrap flag"})
        else:
            bootstrapped = False
            tried: Set[str] = set()
            dedup_source = contract_info.get("dedup_source")
            if dedup_source:
                tried.add(dedup_source)
                bootstrapped = knowledge_graph.bootstrap_from_existing(dedup_source)
                if bootstrapped:
                    logger.info("Bootstrapped knowledge graph", extra={"source": dedup_source})
                else:
                    logger.debug("Dedup source has no saved graph - proceeding fresh", extra={"source": dedup_source})
            if not bootstrapped and contract_name not in tried and knowledge_graph.bootstrap_from_existing(contract_name):
                logger.info("Bootstrapped knowledge graph from previous run", extra={"contract": contract_name})
        if self.enable_moa and self.moa_orchestrator:
            logger.info("Running MoA mode", extra={"specialists": 6, "mode": "parallel", "target_quality": 0.92})
            enriched_source = contract_info.get("onchain_context", "") + contract_source if "onchain_context" in contract_info else contract_source
            if "onchain_context" in contract_info:
                logger.debug("Prepended on-chain context to source", extra={"added_chars": len(contract_info["onchain_context"])})
            backoff = 5
            for attempt in range(5):
                try:
                    knowledge_graph, specialist_results, quality_score = self.moa_orchestrator.run_moa_analysis(contract_source=enriched_source, contract_info=contract_info, knowledge_graph=knowledge_graph)
                    break
                except Exception as exc:
                    if self._is_quota_error(exc):
                        if attempt < 4:
                            logger.warning("MoA quota hit - retrying", extra={"attempt": attempt+1, "backoff_seconds": backoff})
                            time.sleep(backoff)
                            backoff = min(backoff * 2, 60)
                            continue
                        logger.warning("MoA analysis skipped due to LLM quota exhaustion")
                        specialist_results, quality_score = {}, 0.0
                        break
                    raise
        else:
            logger.info("Running standard mode", extra={"specialists": 6, "mode": "A2A-enabled (peer-to-peer)" if self.enable_a2a else "independent", "a2a_enabled": self.enable_a2a})
            specialists = self.spawn_specialists()
            if self.enable_a2a and self.a2a_bus:
                from research.specialist_a2a_wrapper import SpecialistA2AWrapper
                logger.info("Wrapping specialists with A2A protocol")
                specialist_types = ["BusinessLogic", "StateFlow", "Invariant", "Economic", "Dependency", "AccessControl"]
                specialists_to_run = []
                for specialist, specialist_type in zip(specialists, specialist_types):
                    wrapper = SpecialistA2AWrapper(specialist=specialist, bus=self.a2a_bus, specialist_type=specialist_type)
                    if self.knowledge_base:
                        specialist.knowledge_base = self.knowledge_base
                        wrapper.knowledge_base = self.knowledge_base
                    specialists_to_run.append(wrapper)
                    logger.debug("Specialist wrapped", extra={"name": specialist.name, "type": specialist_type})
            else:
                specialists_to_run = specialists
            specialist_results = {}

            for idx, specialist_or_wrapper in enumerate(specialists_to_run):
                is_wrapper = hasattr(specialist_or_wrapper, 'analyze_with_a2a')
                specialist_name = specialist_or_wrapper.specialist.name if is_wrapper else specialist_or_wrapper.name
                logger.info("Running specialist", extra={"name": specialist_name, "mode": "A2A" if is_wrapper else "standard", "index": idx})
                specialist_timeout = 1800
                def run_specialist():
                    return specialist_or_wrapper.analyze_with_a2a(contract_source=contract_source, contract_info=contract_info, knowledge_graph=knowledge_graph) if is_wrapper else specialist_or_wrapper.analyze_contract(contract_source=contract_source, contract_info=contract_info, knowledge_graph=knowledge_graph)
                try:
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(run_specialist)
                        try:
                            results = future.result(timeout=specialist_timeout)
                        except FuturesTimeoutError:
                            logger.error("Specialist timeout", extra={"name": specialist_name, "timeout_seconds": specialist_timeout})
                            self.logger.error(f"Specialist {specialist_name} timed out after {specialist_timeout} seconds (30 minutes)")
                            results = []
                except Exception as exc:
                    if self._is_quota_error(exc):
                        logger.warning("Specialist skipped due to quota exhaustion", extra={"name": specialist_name})
                        results = []
                    else:
                        raise
                specialist_results[specialist_name] = results
                actual_specialist = specialist_or_wrapper.specialist if is_wrapper else specialist_or_wrapper
                self.cost_manager.log_cost(agent_name=actual_specialist.name, contract_name=contract_name, round_num=len(results), operation="research", cost=actual_specialist.cost_manager.get_current_cost())
            quality_score = self.calculate_research_quality(knowledge_graph=knowledge_graph, specialist_results=specialist_results, contract_info=contract_info)

        duration = time.time() - start_time
        total_cost = self.cost_manager.get_current_cost()
        num_agents = len(specialist_results) if self.enable_moa else (len(specialists) if 'specialists' in locals() else 0)
        self.logger.log_performance_metrics(contract_name=contract_name, stage="research", total_cost=total_cost, total_duration_seconds=duration, quality_score=quality_score, num_rounds=sum(len(results) for results in specialist_results.values()), num_agents=num_agents)
        graph_path = knowledge_graph.save()
        logger.info("Analysis complete", extra={"contract": contract_name, "quality_score": quality_score, "total_cost": total_cost, "duration_seconds": duration, "graph_path": graph_path})
        knowledge_graph.print_summary()
        quality_threshold = config.QUALITY_THRESHOLD
        if quality_score < quality_threshold:
            logger.warning("Quality score below threshold", extra={"quality_score": quality_score, "threshold": quality_threshold, "action": "consider_additional_rounds"})
        else:
            logger.info("Quality threshold met - ready for attack layer", extra={"quality_score": quality_score, "threshold": quality_threshold})
        return knowledge_graph, specialist_results, quality_score

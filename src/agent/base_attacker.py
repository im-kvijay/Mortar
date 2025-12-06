"""Base attack agent with JIT research, LLM-MCTS, and autonomous iteration"""

import re
import time
import os
import threading
from typing import Dict, Any, List, Optional, Tuple, TypedDict, TYPE_CHECKING
from dataclasses import dataclass
from abc import ABC, abstractmethod

from config import config
from utils.llm_backend import LLMBackend, LLMResponse
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from utils.caching import LRUCache
from kb.knowledge_graph import KnowledgeGraph

if TYPE_CHECKING:
    from agent.jit_research_gateway import JITResearchGateway


class ContractInfoDict(TypedDict, total=False):
    name: str
    source: str
    state_vars: List[str]
    system_context: Dict[str, Any]
    system_metrics: Dict[str, Any]
    code_slices: List[Dict[str, Any]]
    code_communities: List[Dict[str, Any]]
    graph_summaries: List[Dict[str, Any]]
    community_hits: List[Dict[str, Any]]
    community_ranked: List[Dict[str, Any]]
    system_communities: List[Dict[str, Any]]
    taint_traces: List[str]
    invariants: List[Any]
    semantic_snippets: List[Dict[str, Any]]
    economic_findings: List[Dict[str, Any]]
    logic_scan_findings: List[Dict[str, Any]]
    structural_findings: List[Dict[str, Any]]
    structural_coverage: Dict[str, Any]
    retrieval_summaries: List[Dict[str, Any]]


class KnowledgeDict(TypedDict, total=False):
    contract_facts: List[Dict[str, Any]]
    invariants: List[Dict[str, Any]]
    state_flows: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    patterns: List[Dict[str, Any]]


class JITResponseDict(TypedDict, total=False):
    question: str
    answer: str
    confidence: float
    evidence: List[str]
    specialist_type: str


@dataclass
class AttackHypothesis:
    hypothesis_id: str
    attack_type: str
    description: str
    target_function: str
    preconditions: List[str]
    steps: List[str]
    expected_impact: str
    confidence: float
    requires_research: List[str]
    evidence: List[str]
    from_kb: bool = False
    requires_verification: bool = True
    specialist_name: Optional[str] = None
    contract_name: Optional[str] = None
    pattern_id: Optional[str] = None


@dataclass
class JITResearchRequest:
    question: str
    focus_area: str
    urgency: str
    context: str
    max_cost: float = config.JIT_MAX_COST_PER_REQUEST
    timeout: int = config.JIT_REQUEST_TIMEOUT


@dataclass
class AttackRoundResult:
    round_num: int
    hypotheses: List[AttackHypothesis]
    jit_requests: List[JITResearchRequest]
    jit_responses: List[Dict[str, Any]]
    refined_hypotheses: List[AttackHypothesis]
    decision: str
    reasoning: str
    confidence: float
    cost: float


class BaseAttacker(ABC):
    """Base class for attack agents with JIT research and autonomous iteration"""

    def __init__(self, name: str, description: str, backend: LLMBackend, logger: ResearchLogger,
                 cost_manager: CostManager, knowledge_graph: KnowledgeGraph, research_gateway: Optional[Any] = None,
                 thinking_budget: int = config.EXTENDED_THINKING_BUDGET, verifier: Optional[Any] = None) -> None:
        self.name = name
        self.description = description
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager
        self.knowledge_graph = knowledge_graph
        self.research_gateway = research_gateway
        self.thinking_budget = thinking_budget
        self.verifier = verifier
        self.current_round: int = 0
        self.all_hypotheses: List[AttackHypothesis] = []
        self.jit_cache: LRUCache = LRUCache(maxsize=config.JIT_CACHE_MAX_SIZE)
        self.round_results: List[AttackRoundResult] = []
        self.llm_mcts_engine: Optional[Any] = None
        self.contract_name: Optional[str] = None
        self._mcts_init_lock: threading.Lock = threading.Lock()

    def _format_kb_knowledge(self, kb_knowledge: KnowledgeDict) -> str:
        """Format KB vulnerabilities for attack prompts"""
        vulnerabilities = kb_knowledge.get("vulnerabilities", [])
        if not vulnerabilities:
            return ""
        kb_section = "\n🔬 RESEARCH DISCOVERIES (from Phase 2):\n"
        for vuln in vulnerabilities[:10]:
            name = vuln.get("name", "Unknown")
            conf = vuln.get("confidence", 0)
            data = vuln.get("data", {})
            kb_section += f"\n- {name} (confidence: {conf:.2f})\n"
            for key in ["description", "trigger", "impact", "root_cause"]:
                if key in data:
                    kb_section += f"  {key.replace('_', ' ').title()}: {data[key]}\n"
        kb_section += "\n[WARNING] Use these discoveries to guide analysis. Convert to concrete attack hypotheses.\n"
        return kb_section

    def _format_contract_context(self, contract_info: ContractInfoDict) -> str:
        """Build compact context with semantic snippets, taint traces, and system metadata"""
        sections: List[str] = []
        total_budget = getattr(config, "CONTEXT_CHAR_BUDGET", 6000)

        system_context = contract_info.get("system_context")
        if system_context:
            if isinstance(system_context, dict):
                contracts = system_context.get("contracts") or []
                deps = system_context.get("dependencies") or {}
                system_lines = [f"Contracts: {', '.join(contracts[:8])}" if contracts else "",
                               f"Dependencies: {len(deps)} graphs" if deps else ""]
                system_lines = [line for line in system_lines if line]
                if system_lines:
                    sections.append("SYSTEM CONTEXT:\n" + "\n".join(system_lines))
            else:
                sections.append(f"SYSTEM CONTEXT:\n{system_context}")

        if contract_info.get("state_vars"):
            sections.append("STATE VARS: " + ", ".join(contract_info["state_vars"][:10]))

        sys_metrics = contract_info.get("system_metrics") or {}
        if sys_metrics:
            parts = []
            if sys_metrics.get("cycles"):
                parts.append(f"Cycles: {len(sys_metrics['cycles'])}")
            if sys_metrics.get("centrality"):
                parts.append("Central nodes: " + ", ".join(f"{n}({s:.2f})" for n, s in sys_metrics["centrality"][:3]))
            if parts:
                sections.append("SYSTEM METRICS:\n" + "\n".join(parts))

        for key, label, limit in [("code_slices", "CODE SLICES", 2), ("code_communities", "CODE COMMUNITIES", None),
                                  ("graph_summaries", "GRAPH SUMMARIES", 2), ("community_hits", "GRAPH HITS", None),
                                  ("community_ranked", "GRAPH RANKED", 2), ("system_communities", "SYSTEM COMMUNITIES", None)]:
            items = contract_info.get(key) or []
            if items:
                if key == "code_slices":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"Slice center {s.get('center')}: {len(s.get('nodes', []))} nodes" for s in items[:limit]))
                elif key == "code_communities":
                    sections.append(f"{label}: {len(items)} clusters (GraphRAG-lite)")
                elif key == "graph_summaries":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"- Community ({gs.get('metadata', {}).get('community','?')}): {gs.get('summary','')}"
                        for gs in items[:limit]))
                elif key == "community_hits":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"community {h.get('metadata',{}).get('community','?')}: {h.get('hits')} hits" for h in items))
                elif key == "community_ranked":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"community {rc.get('metadata',{}).get('community','?')}: score {rc.get('score')}"
                        for rc in items[:limit]))
                elif key == "system_communities":
                    sections.append(f"{label}: {len(items)} slices")

        if contract_info.get("taint_traces"):
            sections.append("TAINT PATHS:\n" + "\n".join(contract_info["taint_traces"][:5]))

        invariants = contract_info.get("invariants") or []
        inv_lines = []
        for inv in invariants[:5]:
            if isinstance(inv, str):
                inv_lines.append(inv)
            elif isinstance(inv, dict):
                inv_lines.append(inv.get("invariant") or inv.get("description") or str(inv))
        if inv_lines:
            sections.append("INVARIANTS:\n" + "\n".join(f"- {line}" for line in inv_lines))

        for key, label in [("semantic_snippets", "SEMANTIC HIGHLIGHTS"), ("economic_findings", "ECONOMIC SIGNALS"),
                          ("logic_scan_findings", "LOGIC SCANNER"), ("structural_findings", "STRUCTURAL CHECKS")]:
            items = contract_info.get(key) or []
            if items:
                if key == "semantic_snippets":
                    highlights = []
                    for snip in items[:3]:
                        meta = snip.get("metadata", {}) if isinstance(snip, dict) else {}
                        lab = meta.get("signature") or meta.get("name") or meta.get("type", "snippet")
                        content = (snip.get("content", "") if isinstance(snip, dict) else str(snip)).replace("\n", " ")
                        highlights.append(f"{lab}: {content[:140]}")
                    sections.append(f"{label}:\n" + "\n".join(f"- {h}" for h in highlights))
                elif key == "economic_findings":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"- {f.get('actor', 'econ')}: {f.get('scenario', '')} (margin {f.get('margin', '?')})"
                        for f in items[:2]))
                elif key == "logic_scan_findings":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"- {e.get('target_function', 'logic') if isinstance(e, dict) else 'logic'}: "
                        f"{e.get('description') if isinstance(e, dict) else str(e)}" for e in items[:3]))
                elif key == "structural_findings":
                    sections.append(f"{label}:\n" + "\n".join(
                        f"- {e.get('description') if isinstance(e, dict) else str(e)}" for e in items[:3]))

        structural_cov = contract_info.get("structural_coverage") or {}
        if structural_cov:
            sections.append(f"STRUCTURAL COVERAGE:\n- coverage={structural_cov.get('coverage_score', 0):.2f}, "
                          f"functions {structural_cov.get('functions_covered', 0)}/{structural_cov.get('functions_total', 0)}, "
                          f"taints {structural_cov.get('taint_count', 0)}, invariants {structural_cov.get('invariant_count', 0)}")

        context = "\n\n".join(sections)
        return context[:total_budget] + "\n...[truncated]" if len(context) > total_budget else context

    def _analyze_with_llm_mcts(self, contract_source: str, contract_info: ContractInfoDict) -> List[AttackRoundResult]:
        """LLM-MCTS hybrid search (AlphaZero-inspired): KB discoveries -> MCTS refinement -> hypotheses"""
        try:
            from agent.llm_mcts_engine import LLMMCTSEngine, LLMMCTSConfig
        except ImportError:
            self.logger.warning(f"[{self.name}] LLM-MCTS engine not available - falling back")
            return [AttackRoundResult(1, [], [], [], [], "stop", "LLM-MCTS engine module missing", 0.0, 0.0)]
        from config import config as global_config

        self.contract_name = contract_info.get("name", "Unknown")
        self.logger.info(f"[{self.name}] Starting LLM-MCTS attack analysis")

        kb_knowledge = self._query_kb(contract_info)
        vulnerabilities = kb_knowledge.get("vulnerabilities", [])
        if not vulnerabilities:
            return [AttackRoundResult(1, [], [], [], [], "stop", "No research discoveries", 0.0, 0.0)]

        seed_hypotheses = []
        for vuln in vulnerabilities[:3]:
            vuln_data = vuln.get("data", {})
            seed_hypotheses.append(AttackHypothesis(
                hypothesis_id=f"mcts_seed_{len(seed_hypotheses)}",
                attack_type=self.name.lower(),
                description=vuln_data.get("description", vuln.get("name", "Unknown")),
                target_function=vuln_data.get("trigger", "Unknown"),
                preconditions=vuln_data.get("preconditions", []),
                steps=[],
                expected_impact=vuln_data.get("impact", "Unknown"),
                confidence=vuln.get("confidence", 0.5),
                requires_research=[],
                evidence=[f"KB discovery: {vuln.get('name')}"]
            ))

        with self._mcts_init_lock:
            if not self.llm_mcts_engine:
                mcts_config = LLMMCTSConfig(
                    max_iterations=global_config.MCTS_MAX_ITERATIONS,
                    max_depth=global_config.MCTS_MAX_DEPTH,
                    exploration_constant=global_config.MCTS_EXPLORATION_CONSTANT,
                    value_weight=global_config.MCTS_VALUE_WEIGHT,
                    policy_top_k=global_config.MCTS_POLICY_TOP_K,
                    early_stop_value=global_config.MCTS_EARLY_STOP_VALUE
                )
                self.llm_mcts_engine = LLMMCTSEngine(self.logger, self.cost_manager, mcts_config)

        total_cost, refined_hypotheses = 0.0, []
        for i, hypothesis in enumerate(seed_hypotheses, 1):
            try:
                mcts_result = self.llm_mcts_engine.search(hypothesis, contract_source, contract_info)
                total_cost += mcts_result.cost
                if mcts_result.attack_path and mcts_result.confidence >= 0.5:
                    refined_hypotheses.append(AttackHypothesis(
                        hypothesis_id=f"mcts_{i}",
                        attack_type=hypothesis.attack_type,
                        description=f"MCTS-refined: {hypothesis.description}",
                        target_function=hypothesis.target_function,
                        preconditions=hypothesis.preconditions,
                        steps=[tx.function_name for tx in mcts_result.attack_path],
                        expected_impact=hypothesis.expected_impact,
                        confidence=mcts_result.confidence,
                        requires_research=[],
                        evidence=hypothesis.evidence + [f"MCTS explored {mcts_result.iterations} iterations"]
                    ))
            except Exception as e:
                self.logger.error(f"[{self.name}] MCTS search failed: {e}")

        self.all_hypotheses.extend(refined_hypotheses)
        return [AttackRoundResult(1, refined_hypotheses, [], [], refined_hypotheses, "stop",
                                 f"LLM-MCTS: {len(seed_hypotheses)} seeds → {len(refined_hypotheses)} refined",
                                 max((h.confidence for h in refined_hypotheses), default=0.0), total_cost)]

    @abstractmethod
    def get_system_prompt(self) -> str:
        """System prompt defining attack specialization and output format"""

    @abstractmethod
    def get_attack_prompt(self, contract_source: str, contract_info: ContractInfoDict,
                         round_num: int, kb_knowledge: KnowledgeDict) -> str:
        """Attack analysis prompt for this round"""

    def _parse_hypothesis_block(self, block: str, round_num: int, hypothesis_index: int) -> Optional[AttackHypothesis]:
        """Parse hypothesis block from LLM response"""
        lines = block.strip().split("\n")
        if len(lines) < 2:
            return None

        attack_type = lines[0].strip()
        description = target = impact = ""
        preconditions, steps, evidence, research_needed = [], [], [], []
        confidence = 0.7
        current_field = None

        for line in lines[1:]:
            line = line.strip()
            if line.startswith("Description:"):
                description, current_field = line.replace("Description:", "").strip(), "description"
            elif line.startswith("Target:"):
                target, current_field = line.replace("Target:", "").strip(), "target"
            elif line.startswith("Preconditions:"):
                current_field = "preconditions"
            elif line.startswith("Steps:"):
                current_field = "steps"
            elif line.startswith("Impact:"):
                impact, current_field = line.replace("Impact:", "").strip(), "impact"
            elif line.startswith("Confidence:"):
                try:
                    confidence = float(line.replace("Confidence:", "").strip())
                except (ValueError, TypeError):
                    pass
                current_field = None
            elif line.startswith("Evidence:"):
                current_field = "evidence"
            elif line.startswith("Research Needed:"):
                current_field = "research"
            elif line.startswith("---"):
                break
            elif line and current_field:
                line_clean = line.lstrip("-• ")
                if current_field == "preconditions":
                    preconditions.append(line_clean)
                elif current_field == "steps":
                    steps.append(line_clean)
                elif current_field == "evidence":
                    evidence.append(line_clean)
                elif current_field == "research":
                    research_needed.append(line_clean)

        if not description or not target:
            return None

        return AttackHypothesis(f"{self.name.lower()}_{round_num}_{hypothesis_index}", attack_type, description,
                               target, preconditions, steps, impact, confidence, research_needed, evidence,
                               specialist_name=self.name)

    def _default_extract_hypotheses(self, response: str, round_num: int) -> List[AttackHypothesis]:
        """Default hypothesis extraction from LLM response"""
        hypotheses = []
        for i, block in enumerate(response.split("HYPOTHESIS:")[1:], 1):
            hypothesis = self._parse_hypothesis_block(block, round_num, i)
            if hypothesis:
                hypotheses.append(hypothesis)
        return hypotheses

    def _default_should_continue(self, round_num: int, response: str, hypotheses: List[AttackHypothesis],
                                 max_rounds: int = 5) -> Tuple[bool, str, float]:
        """Default stopping logic with common heuristics"""
        decision_match = re.search(r'DECISION:\s*(continue|stop)', response, re.IGNORECASE)
        if decision_match and decision_match.group(1).lower() == "stop":
            reasoning_match = re.search(r'REASONING:\s*(.+?)(?=CONFIDENCE:|$)', response, re.IGNORECASE | re.DOTALL)
            confidence_match = re.search(r'CONFIDENCE:\s*([\d.]+)', response, re.IGNORECASE)
            reasoning = reasoning_match.group(1).strip() if reasoning_match else "Agent decided to stop"
            confidence = float(confidence_match.group(1)) if confidence_match else 0.8
            return False, reasoning, confidence

        if not hypotheses and round_num >= 2:
            return False, f"No {self.name.lower()} vulnerabilities found after 2 rounds", 0.6

        high_conf = [h for h in hypotheses if h.confidence >= config.ATTACK_HIGH_CONFIDENCE_THRESHOLD]
        if len(high_conf) >= 2:
            return False, f"Found {len(high_conf)} high-confidence {self.name.lower()} attacks", 0.9

        if round_num >= max_rounds:
            return False, f"Reached maximum rounds ({max_rounds})", 0.75

        return True, f"Continuing {self.name.lower()} attack exploration", 0.7

    @abstractmethod
    def extract_hypotheses(self, response: str, round_num: int) -> List[AttackHypothesis]:
        """Extract attack hypotheses from LLM response"""

    @abstractmethod
    def should_continue(self, round_num: int, response: str, hypotheses: List[AttackHypothesis]) -> Tuple[bool, str, float]:
        """Decide if should continue attacking: (continue, reasoning, confidence)"""

    def analyze_contract(self, contract_source: str, contract_info: ContractInfoDict) -> List[AttackRoundResult]:
        """Analyze contract for attack vectors with autonomous iteration and JIT research"""
        self.contract_name = contract_info.get("name", "Unknown")
        self.logger.info(f"[{self.name}] Starting attack analysis")

        if getattr(config, 'USE_MCTS_MODE', False):
            try:
                return self._analyze_with_llm_mcts(contract_source, contract_info)
            except Exception as e:
                self.logger.warning(f"[{self.name}] LLM-MCTS mode failed ({e}), falling back")

        results = []
        MAX_SAFETY_ROUNDS = 100
        round_num = 1

        while round_num <= MAX_SAFETY_ROUNDS:
            self.current_round = round_num
            self.logger.info(f"[{self.name}] Round {round_num}")
            hypotheses = jit_requests = jit_responses = []

            try:
                kb_knowledge = self._query_kb(contract_info)
                prompt = self.get_attack_prompt(contract_source, contract_info, round_num, kb_knowledge)
                response = self._call_llm(prompt)
                hypotheses = self.extract_hypotheses(response.text, round_num)

                jit_requests = self._extract_jit_requests(response.text, hypotheses)
                if jit_requests and self.research_gateway:
                    self.logger.info(f"[{self.name}] Requesting JIT research ({len(jit_requests)} questions)")
                    jit_responses = self._execute_jit_requests(jit_requests, contract_source, contract_info)
                    hypotheses = self._refine_with_jit(hypotheses, jit_responses, contract_source, contract_info)

                continue_analysis, reasoning, confidence = self.should_continue(round_num, response.text, hypotheses)
                round_result = AttackRoundResult(round_num, hypotheses, jit_requests, jit_responses, hypotheses,
                                                "continue" if continue_analysis else "stop", reasoning, confidence, response.cost)
                results.append(round_result)
                self.round_results.append(round_result)

                self.logger.log_specialist_decision(self.name, self.contract_name, round_num,
                                                   "continue" if continue_analysis else "stop", reasoning, confidence, len(hypotheses))

                if not continue_analysis:
                    self.logger.info(f"[{self.name}] Stopping: {reasoning}")
                    break

            except Exception as e:
                self.logger.error(f"[{self.name}] Error in round {round_num}: {e}")
                import traceback
                traceback.print_exc()

                if hypotheses:
                    self.logger.info(f"[{self.name}] Recording {len(hypotheses)} partial discoveries")
                    self.all_hypotheses.extend(hypotheses)
                    results.append(AttackRoundResult(round_num, hypotheses, [], [], hypotheses, "error",
                                                    f"Round failed: {str(e)}", 0.0, 0.0))
                break

            round_num += 1

        if round_num > MAX_SAFETY_ROUNDS:
            self.logger.error(f"[{self.name}] Safety limit hit after {MAX_SAFETY_ROUNDS} rounds")

        self.logger.info(f"[{self.name}] Complete: {len(results)} rounds, {len(self.all_hypotheses)} hypotheses")
        return results

    def request_research(self, question: str, focus_area: str, context: str, urgency: str = "medium",
                        max_cost: float = config.JIT_MAX_COST_PER_REQUEST, timeout: int = config.JIT_REQUEST_TIMEOUT,
                        contract_info: Optional[ContractInfoDict] = None) -> Optional[JITResponseDict]:
        """Request Just-In-Time research from specialist"""
        if not self.research_gateway:
            self.logger.warning(f"[{self.name}] No research gateway available")
            return None

        cache_key = f"{focus_area}:{question}"
        cached_result = self.jit_cache.get(cache_key)
        if cached_result is not None:
            self.logger.info(f"[{self.name}] JIT cache hit: {question[:50]}...")
            return cached_result

        self.logger.info(f"[{self.name}] JIT request: {question[:100]}...")
        try:
            response = self.research_gateway.request_analysis(
                question=question, specialist_type=focus_area, context=context, contract_info=contract_info,
                max_cost=max_cost, timeout=timeout, attacker_name=self.name, contract_name=self.contract_name)
            self.jit_cache.put(cache_key, response)
            return response
        except Exception as e:
            self.logger.error(f"[{self.name}] JIT request failed: {e}")
            return None

    def _query_kb(self, contract_info: ContractInfoDict) -> KnowledgeDict:
        """Query knowledge base for relevant information"""
        contract_name = contract_info.get("name", "Unknown")
        knowledge = {"contract_facts": [], "invariants": [], "state_flows": [], "vulnerabilities": [], "patterns": []}

        nodes = self.knowledge_graph.get_nodes_by_type("contract")
        for node in nodes:
            if node.get("name") == contract_name:
                knowledge["contract_facts"].append(node.get("data", {}))

        invariants = self.knowledge_graph.get_nodes_by_type("invariant")
        knowledge["invariants"] = [inv.get("data", {}) for inv in invariants[:10]]

        state_flows = self.knowledge_graph.get_nodes_by_type("state_variable")
        knowledge["state_flows"] = [sf.get("data", {}) for sf in state_flows[:10]]

        if hasattr(self.knowledge_graph, 'get_vulnerability_nodes'):
            vuln_nodes = self.knowledge_graph.get_vulnerability_nodes(min_confidence=0.5)
            knowledge["vulnerabilities"] = [{
                "name": node.name,
                "confidence": node.confidence,
                "type": node.node_type.value if hasattr(node.node_type, 'value') else str(node.node_type),
                "data": node.data,
                "evidence": node.data.get('evidence', []) if isinstance(node.data, dict) else []
            } for node in vuln_nodes]
        else:
            vuln_nodes = self.knowledge_graph.get_nodes_by_type("vulnerability")
            knowledge["vulnerabilities"] = [{"name": node.get("name", "Unknown"), "data": node.get("data", {})}
                                          for node in vuln_nodes]

        return knowledge

    @staticmethod
    def _is_quota_error(exc: Exception) -> bool:
        """Detect xAI quota exhaustion errors"""
        message = str(exc)
        return any(k in message for k in ("RESOURCE_EXHAUSTED", "spending limit", "credits", "rate limit", "quota")) if message else False

    def _call_llm(self, prompt: str) -> LLMResponse:
        """Call LLM with Extended Thinking and retry logic"""
        system_prompt = self.get_system_prompt()
        temperature = config.EXTENDED_THINKING_TEMPERATURE if self.thinking_budget > 0 else config.NORMAL_TEMPERATURE
        max_sleep = int(os.getenv("XAI_BACKOFF_MAX_SECONDS", "60"))
        backoff = 5

        for attempt in range(5):
            try:
                response = self.backend.generate(prompt=prompt, system_prompt=system_prompt,
                                                max_tokens=config.MAX_OUTPUT_TOKENS, temperature=temperature,
                                                thinking_budget=self.thinking_budget)
                break
            except Exception as exc:
                if self._is_quota_error(exc):
                    if attempt < 4:
                        self.logger.warning(f"[{self.name}] LLM quota exhausted (attempt {attempt+1}); sleeping {backoff}s")
                        time.sleep(backoff)
                        backoff = min(backoff * 2, max_sleep)
                        continue
                    self.logger.warning(f"[{self.name}] LLM quota exhausted; continuing without new hypotheses")
                    return LLMResponse("", None, 0, 0, 0, 0.0, getattr(self.backend, "model", "unknown"),
                                     {"quota_exhausted": True}, [])
                raise

        self.cost_manager.log_cost(self.name, self.contract_name, self.current_round,
                                  f"attack_round_{self.current_round}", response.cost)
        self.logger.log_ai_call(self.name, self.contract_name, self.current_round, "attack_analysis",
                              prompt, response.text, response.thinking if hasattr(response, 'thinking') else None,
                              response.cost, response.prompt_tokens, response.output_tokens, response.thinking_tokens)
        return response

    def _extract_jit_requests(self, response: str, hypotheses: List[AttackHypothesis]) -> List[JITResearchRequest]:
        """Extract JIT research requests from LLM response and hypothesis fields"""
        requests = []
        jit_pattern = r'(?:NEED TO KNOW|UNCERTAIN|QUESTION|JIT REQUEST):\s*(.+?)(?:\n|$)'
        matches = re.findall(jit_pattern, response, re.IGNORECASE)

        for match in matches:
            question = match.strip()
            if len(question) > 10:
                requests.append(JITResearchRequest(question, self._infer_focus_area(question), "high",
                                                  f"Needed for {self.name} attack hypothesis validation"))

        for hyp in hypotheses:
            for question in hyp.requires_research:
                requests.append(JITResearchRequest(question, self._infer_focus_area(question), "medium",
                                                  f"Needed to validate hypothesis: {hyp.description}"))

        return requests[:config.JIT_MAX_REQUESTS_PER_ROUND]

    def _infer_focus_area(self, question: str) -> str:
        """Infer which specialist should handle this question"""
        q = question.lower()
        if any(k in q for k in ["invariant", "always true", "holds", "broken"]):
            return "invariant"
        elif any(k in q for k in ["state", "modify", "update", "change"]):
            return "state_flow"
        elif any(k in q for k in ["access", "owner", "permission", "require", "onlyOwner"]):
            return "access_control"
        elif any(k in q for k in ["profit", "economic", "incentive", "cost"]):
            return "economic"
        elif any(k in q for k in ["external", "dependency", "oracle", "call"]):
            return "dependency"
        return "business_logic"

    def _execute_jit_requests(self, requests: List[JITResearchRequest], contract_source: str,
                             contract_info: ContractInfoDict) -> List[JITResponseDict]:
        """Execute JIT research requests"""
        responses = []
        for req in requests:
            response = self.request_research(req.question, req.focus_area, req.context, req.urgency,
                                           req.max_cost, req.timeout, contract_info)
            if response:
                responses.append(response)
        return responses

    def _refine_with_jit(self, hypotheses: List[AttackHypothesis], jit_responses: List[JITResponseDict],
                        contract_source: str, contract_info: ContractInfoDict) -> List[AttackHypothesis]:
        """Refine hypotheses with JIT research knowledge (update confidence and evidence)"""
        refined = []
        for hyp in hypotheses:
            relevant_jit = [resp for resp in jit_responses
                          if any(keyword in getattr(resp, 'question', '').lower()
                                for keyword in hyp.description.lower().split()[:5])]
            if relevant_jit:
                avg_jit_conf = sum(getattr(r, 'confidence', 0.0) for r in relevant_jit) / len(relevant_jit)
                hyp.confidence = config.JIT_CONFIDENCE_WEIGHT_OLD * hyp.confidence + config.JIT_CONFIDENCE_WEIGHT_NEW * avg_jit_conf
                for jit in relevant_jit:
                    hyp.evidence.append(f"JIT Research: {getattr(jit, 'answer', '')}")
            refined.append(hyp)
        return refined

"""specialist agent for vulnerability research."""

import copy
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, TypedDict, TYPE_CHECKING
import os
from dataclasses import dataclass
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import config

from research.specialist_tools import get_specialist_tools
from research.functional_tools import FunctionalAnalysisTools, get_functional_tool_definitions
from research.consolidated_tools import get_consolidated_tools
from research.memory import Discovery
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from utils.llm_backend import LLMBackend, create_backend

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from context.context_compressor import ContextCompressor


class ContractInfoDict(TypedDict, total=False):
    name: str
    source: str
    state_vars: List[str]
    retrieval_summaries: List[Dict[str, Any]]
    system_context: Dict[str, Any]
    semantic_snippets: List[Dict[str, Any]]
    taint_traces: List[str]
    invariants: List[Any]


class ToolCallDict(TypedDict, total=False):
    iteration: int
    id: str
    tool: str
    arguments: Dict[str, Any]
    status: str
    result: Any


class GraphUpdateDict(TypedDict, total=False):
    type: str
    node_id: str
    node_type: str
    name: str
    data: Dict[str, Any]
    confidence: float
    source: str
    target: str
    edge_type: str


class FunctionalAnalysisDict(TypedDict, total=False):
    tool: str
    result: Any
    metadata: Dict[str, Any]


class ReflectionDict(TypedDict, total=False):
    finding: str
    confidence: float
    critique: str
    revised_confidence: float
    keep: bool

try:
    from context.context_compressor import ContextCompressor, create_compressor
    CONTEXT_COMPRESSION_AVAILABLE = True
except ImportError:
    CONTEXT_COMPRESSION_AVAILABLE = False
    ContextCompressor = None


@dataclass
class EnhancedAnalysisResult:
    discoveries: List[Discovery]
    graph_updates: List[GraphUpdateDict]
    tool_calls: List[ToolCallDict]
    functional_analyses: List[FunctionalAnalysisDict]
    reflections: List[ReflectionDict]
    summary: str
    confidence: float
    areas_covered: List[str]
    total_discoveries: int
    cost: float
    duration_seconds: float
    thinking: Optional[str] = None
    thinking_tokens: int = 0
    prompt_tokens: int = 0
    output_tokens: int = 0
    analysis_complete: bool = False


class EnhancedAgenticSpecialist(ABC):

    def __init__(
        self,
        name: str,
        description: str,
        project_root: Optional[str] = None,
        backend: Optional[LLMBackend] = None,
        backend_type: Optional[str] = None,
        model: Optional[str] = None,
        cost_limit: Optional[float] = None,
        thinking_budget: Optional[int] = None,
        enable_interleaved_thinking: Optional[bool] = None,
        a2a_bus: Optional[Any] = None,
        a2a_agent_id: Optional[str] = None,
        a2a_check_interval: int = 3,
        knowledge_base: Optional[Any] = None
    ) -> None:
        self.name = name
        self.description = description
        self.project_root = project_root or str(config.PROJECT_ROOT)
        if thinking_budget is None:
            default_budget = config.EXTENDED_THINKING_BUDGET
            thinking_budget = default_budget if default_budget > 0 else None
        self.thinking_budget = thinking_budget

        if enable_interleaved_thinking is None:
            enable_interleaved_thinking = config.ENABLE_INTERLEAVED_THINKING
        self.enable_interleaved_thinking = enable_interleaved_thinking

        self.a2a_bus = a2a_bus
        self.a2a_agent_id = a2a_agent_id
        self.a2a_check_interval = a2a_check_interval
        self._a2a_last_check_index = 0
        self._a2a_pending_messages: List[Any] = []

        if backend is None:
            self.backend = create_backend(backend_type, model=model)
        else:
            self.backend = backend

        self.model = self.backend.model

        self.logger = ResearchLogger(project_root=self.project_root)
        self.cost_manager = CostManager(max_cost_per_contract=cost_limit)
        self.knowledge_base = knowledge_base
        self._current_contract_name: Optional[str] = None
        self._latest_web_scan: Optional[str] = None

        self.compressor: Optional[ContextCompressor] = None
        self.enable_context_compression = config.ENABLE_CONTEXT_COMPRESSION
        if self.enable_context_compression and CONTEXT_COMPRESSION_AVAILABLE:
            self.compressor = create_compressor(
                t_max=config.CONTEXT_COMPRESSION_T_MAX,
                t_retained=config.CONTEXT_COMPRESSION_T_RETAINED,
            )

    def _run_web_search(self, query: str, allowed_domains: Optional[List[str]] = None) -> Optional[str]:
        if not query or not self.backend:
            return None

        tools: List[Dict[str, Any]] = [{"type": "web_search"}]
        if allowed_domains:
            tools[0]["allowed_domains"] = allowed_domains

        system_prompt = (
            "You gather open-source intelligence that helps a smart contract audit. "
            "Summarize in <=3 concise bullet points with inline citations."
        )

        try:
            response = self.backend.generate(
                prompt=f"Target: {query}\nFocus on security incidents, public audits, and implementation details.",
                system_prompt=system_prompt,
                temperature=0.0,
                max_tokens=512,
                tools=tools,
                reasoning_effort=os.getenv("GROK_EFFORT", "low"),
            )
        except Exception as exc:
            self.logger.warning(f"[{self.name}] Web search failed: {exc}")
            return None

        summary = (response.text or "").strip()
        citations = None
        if isinstance(response.metadata, dict):
            citations = response.metadata.get("citations")

        if summary:
            capped = summary if len(summary) < 2000 else summary[:2000] + "…"
            self.logger.info(f"[{self.name}] Web search summary:\n{capped}")

        if citations:
            joined = ", ".join(citations)
            self.logger.info(f"[{self.name}] Web search citations: {joined}")

        self._latest_web_scan = summary
        return summary

    def _should_run_web_scan(self, contract_info: ContractInfoDict) -> bool:
        return False

    @abstractmethod
    def get_system_prompt(self) -> str:
        pass

    @abstractmethod
    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: ContractInfoDict
    ) -> str:
        pass

    def analyze_contract(
        self,
        contract_source: str,
        contract_info: ContractInfoDict,
        knowledge_graph: KnowledgeGraph,
        prior_discoveries: Optional[List[Discovery]] = None
    ) -> List[EnhancedAnalysisResult]:
        contract_name = contract_info.get("name", "Unknown")
        self._current_contract_name = contract_name

        logger.info("="*70)
        logger.info(f"[{self.name}] analysis starting", extra={"specialist": self.name, "contract": contract_name})
        logger.info("="*70)

        if self._should_run_web_scan(contract_info):
            query = contract_info.get("name", "Unknown")
            if query and query != "Unknown":
                self._run_web_search(f"{query} smart contract security history")

        self.cost_manager.start_contract(contract_name)
        start_time = time.time()

        functional_tools = FunctionalAnalysisTools(contract_source, contract_info, knowledge_graph=knowledge_graph)
        if hasattr(self, "attach_graph"):
            try:
                self.attach_graph(knowledge_graph, contract_name)
            except Exception as e:
                self.logger.warning(f"failed to attach graph: {e}")

        if config.USE_CONSOLIDATED_TOOLS:
            tools = get_consolidated_tools()
        else:
            tools = get_specialist_tools() + get_functional_tool_definitions()

        system_prompt = self._get_enhanced_system_prompt()
        analysis_prompt = self.get_analysis_prompt(contract_source, contract_info)
        retrieval = contract_info.get("retrieval_summaries") or []
        if retrieval:
            retrieval_lines = []
            for entry in retrieval[:5]:
                label = entry.get("summary") or entry.get("text") or str(entry)
                retrieval_lines.append(f"- {label}")
            analysis_prompt += "\n\ngraph context:\n" + "\n".join(retrieval_lines)
        if prior_discoveries:
            analysis_prompt += self._format_prior_discoveries(prior_discoveries)

        messages = [{"role": "user", "content": analysis_prompt}]

        MAX_MESSAGES = 150

        total_tool_calls = 0
        total_cost = 0.0
        total_thinking_tokens = 0
        total_output_tokens = 0
        total_prompt_tokens = 0
        max_iterations = max(1, int(os.getenv("AGENT_MAX_ITERATIONS", "100")))
        max_seconds = max(60.0, float(os.getenv("AGENT_MAX_SECONDS", "900")))

        discoveries: List[Discovery] = []
        graph_updates: List[Dict[str, Any]] = []
        functional_analyses: List[Dict[str, Any]] = []
        reflections: List[Dict[str, Any]] = []
        summary = "Analysis pending"
        confidence = 0.85
        areas_covered: List[str] = []
        tool_call_log: List[Dict[str, Any]] = []

        analysis_complete_called = False

        iterations_without_discovery = 0
        iterations_without_tools = 0
        last_discovery_count = 0
        max_iterations_no_discovery = int(os.getenv("AGENT_MAX_NO_DISCOVERY", "40"))
        max_iterations_no_tools = int(os.getenv("AGENT_MAX_NO_TOOLS", "5"))

        tool_reminder_interval = 30

        import time as time_module

        iterations_completed = 0
        loop_start_time = time_module.time()

        for iteration in range(max_iterations):
            iterations_completed = iteration + 1
            iter_start_time = time_module.time()

            should_remind = (
                iteration % tool_reminder_interval == 0 or
                (self.compressor and self.compressor.estimate_tokens(messages) > 50000)
            )
            if iteration > 0 and should_remind:
                tool_names = [t["name"] for t in tools]
                reminder = f"""tool reminder (iteration {iteration + 1})

functional: trace_state_variable, analyze_function_symbolically, check_invariant, run_static_analysis, reflect_on_finding, compare_with_pattern
recording: record_discovery (save immediately), update_knowledge_graph, analysis_complete (when done)

record discoveries immediately. call analysis_complete when exhausted.

available: {', '.join(tool_names[:15])}{"..." if len(tool_names) > 15 else ""}
"""
                messages.append({
                    "role": "user",
                    "content": [{
                        "type": "text",
                        "text": reminder
                    }]
                })

            a2a_start = time_module.time()
            a2a_time = 0.0
            if (
                iteration > 0
                and self.a2a_bus
                and self.a2a_agent_id
                and iteration % self.a2a_check_interval == 0
            ):
                peer_messages = self._handle_check_peer_messages([
                    "discovery",
                    "peer_review_request",
                    "peer_review",
                    "review_response"
                ])
                if peer_messages.startswith("=== PEER MESSAGES ==="):
                    num_messages = peer_messages.count("From:")
                    messages.append({
                        "role": "user",
                        "content": [{
                            "type": "text",
                            "text": "[a2a] new peer updates:\n" + peer_messages
                        }]
                    })
                a2a_time = time_module.time() - a2a_start

            if self.compressor:
                current_tokens = self.compressor.estimate_tokens(messages)
                compression_threshold = 0.6 if iteration > 30 else 0.75
                if current_tokens > self.compressor.t_max * compression_threshold:
                    messages, tokens_saved = self.compressor.process(messages)

            llm_start = time_module.time()

            DISCOVERY_PHASE_ITERATIONS = 25
            if iteration < DISCOVERY_PHASE_ITERATIONS:
                effective_thinking_budget = self.thinking_budget
            elif iteration < 50:
                effective_thinking_budget = self.thinking_budget // 2 if self.thinking_budget else None
            else:
                effective_thinking_budget = min(256, self.thinking_budget // 4) if self.thinking_budget else None

            try:
                response = self.backend.generate_with_tools_multi_turn(
                    messages=messages,
                    system_prompt=system_prompt,
                    tools=tools,
                    thinking_budget=effective_thinking_budget,
                    enable_interleaved_thinking=self.enable_interleaved_thinking if iteration < 50 else False,
                    max_tokens=config.MAX_OUTPUT_TOKENS
                )
            except Exception as e:
                self.logger.error(f"[{self.name}] llm error: {e}")
                if discoveries:
                    self._persist_partial_discoveries(discoveries)
                break
            llm_time = time_module.time() - llm_start

            total_cost += response.cost
            total_thinking_tokens += response.thinking_tokens
            total_output_tokens += response.output_tokens
            total_prompt_tokens += response.prompt_tokens
            total_tool_calls += len(response.tool_calls)

            for tool_call in response.tool_calls:
                if "function" in tool_call and "name" not in tool_call:
                    tool_call["name"] = tool_call["function"]["name"]
                    args = tool_call["function"].get("arguments", "{}")
                    if isinstance(args, str):
                        try:
                            tool_call["input"] = json.loads(args)
                        except json.JSONDecodeError:
                            tool_call["input"] = {}
                    else:
                        tool_call["input"] = args
                elif isinstance(tool_call.get("input"), str):
                    try:
                        tool_call["input"] = json.loads(tool_call["input"])
                    except json.JSONDecodeError:
                        tool_call["input"] = {"raw": tool_call["input"]}

            assistant_content = []
            raw_content = response.metadata.get("raw_content")
            if raw_content:
                for block in raw_content:
                    if getattr(block, "type", None) == "thinking":
                        thinking_block = {
                            "type": "thinking",
                            "thinking": block.thinking
                        }
                        if hasattr(block, "signature") and block.signature:
                            thinking_block["signature"] = block.signature
                        assistant_content.append(thinking_block)
                    elif getattr(block, "type", None) == "text":
                        assistant_content.append({
                            "type": "text",
                            "text": block.text
                        })
                    elif getattr(block, "type", None) == "tool_use":
                        assistant_content.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input
                        })
            else:
                if response.thinking:
                    assistant_content.append({
                        "type": "thinking",
                        "thinking": response.thinking
                    })
                if response.text:
                    assistant_content.append({
                        "type": "text",
                        "text": response.text
                    })
                for tool_call in response.tool_calls:
                    assistant_content.append({
                        "type": "tool_use",
                        "id": tool_call["id"],
                        "name": tool_call["name"],
                        "input": tool_call["input"]
                    })

            messages.append({
                "role": "assistant",
                "content": assistant_content
            })

            for tool_call in response.tool_calls:
                if tool_call["name"] == "analysis_complete":
                    analysis_complete_called = True
                    tool_input = tool_call.get("input") or {}
                    if isinstance(tool_input, str):
                        try:
                            tool_input = json.loads(tool_input)
                        except (json.JSONDecodeError, TypeError):
                            tool_input = {"raw": tool_input}
                    summary = str(tool_input.get("summary") or "Analysis complete")
                    try:
                        confidence = float(tool_input.get("confidence", confidence))
                    except (TypeError, ValueError):
                        confidence = confidence if confidence else 0.85
                    raw_areas = tool_input.get("areas_covered", [])
                    if isinstance(raw_areas, str):
                        areas_covered = [raw_areas]
                    elif isinstance(raw_areas, list):
                        areas_covered = raw_areas
                    else:
                        areas_covered = []
                    break

            tool_exec_start = time_module.time()
            tool_result_blocks: List[Dict[str, Any]] = []

            CRITICAL_TOOLS = {"record_discovery", "analysis_complete", "attack_analysis_complete"}

            for tool_call in response.tool_calls:
                tool_name = tool_call.get("name")
                tool_id = tool_call.get("id")
                raw_input = tool_call.get("input", {})

                if isinstance(raw_input, str):
                    try:
                        tool_input = json.loads(raw_input)
                    except (json.JSONDecodeError, TypeError):
                        tool_input = {"raw": raw_input}
                elif raw_input is None:
                    tool_input = {}
                else:
                    tool_input = raw_input

                tool_entry = {
                    "iteration": iteration + 1,
                    "id": tool_id,
                    "tool": tool_name,
                    "arguments": copy.deepcopy(tool_input),
                    "status": "success",
                    "result": None
                }

                result_content = None

                try:
                    if tool_name == "trace_state_variable":
                        variable_name = tool_input.get("variable_name")
                        if variable_name:
                            result = functional_tools.trace_state_variable(variable_name)
                            functional_analyses.append({"tool": tool_name, "result": result})
                            result_content = str(result)
                        else:
                            result_content = "trace_state_variable skipped: missing variable_name"
                            tool_entry["status"] = "error"

                    elif tool_name == "analyze_function_symbolically":
                        function_name = tool_input.get("function_name")
                        if function_name:
                            result = functional_tools.analyze_function_symbolically(function_name)
                            functional_analyses.append({"tool": tool_name, "result": result})
                            result_content = str(result)
                        else:
                            result_content = "analyze_function_symbolically skipped: missing function_name"
                            tool_entry["status"] = "error"

                    elif tool_name == "check_invariant":
                        invariant_description = tool_input.get("invariant_description")
                        code_evidence = tool_input.get("code_evidence")
                        if invariant_description and code_evidence:
                            result = functional_tools.check_invariant(invariant_description, code_evidence)
                            functional_analyses.append({"tool": tool_name, "result": result})
                            result_content = str(result)
                        else:
                            result_content = "check_invariant skipped: missing required arguments"
                            tool_entry["status"] = "error"

                    elif tool_name == "run_static_analysis":
                        focus = tool_input.get("focus", "all")
                        result = functional_tools.run_static_analysis(focus)
                        functional_analyses.append({"tool": tool_name, "result": result})
                        result_content = str(result)

                    elif tool_name == "reflect_on_finding":
                        finding = tool_input.get("finding")
                        confidence_value = tool_input.get("confidence")
                        if finding is not None and confidence_value is not None:
                            try:
                                confidence_float = float(confidence_value)
                            except (TypeError, ValueError):
                                confidence_float = 0.5
                            result = functional_tools.reflect_on_finding(finding, confidence_float)
                            reflections.append(result)
                            result_content = str(result)
                        else:
                            result_content = "reflect_on_finding skipped: missing required arguments"
                            tool_entry["status"] = "error"

                    elif tool_name == "compare_with_pattern":
                        pattern_name = tool_input.get("pattern_name")
                        if pattern_name:
                            result = functional_tools.compare_with_pattern(pattern_name)
                            functional_analyses.append({"tool": tool_name, "result": result})
                            result_content = str(result)
                        else:
                            result_content = "compare_with_pattern skipped: missing pattern_name"
                            tool_entry["status"] = "error"

                    elif tool_name == "check_peer_messages":
                        message_types = tool_input.get("message_types", [])
                        result_content = self._handle_check_peer_messages(message_types)

                    elif tool_name == "publish_discovery":
                        discovery_summary = tool_input.get("discovery_summary")
                        area_covered = tool_input.get("area_covered")
                        if discovery_summary and area_covered:
                            try:
                                confidence_float = float(tool_input.get("confidence", 0.8))
                            except (TypeError, ValueError):
                                confidence_float = 0.8
                            result_content = self._handle_publish_discovery(
                                discovery_summary=discovery_summary,
                                area_covered=area_covered,
                                confidence=confidence_float
                            )
                        else:
                            result_content = "publish_discovery skipped: missing required arguments"
                            tool_entry["status"] = "error"

                    elif tool_name == "request_peer_review":
                        finding = tool_input.get("finding")
                        question = tool_input.get("question")
                        if finding and question:
                            result_content = self._handle_request_peer_review(
                                finding=finding,
                                question=question,
                                target_specialist=tool_input.get("target_specialist")
                            )
                        else:
                            result_content = "request_peer_review skipped: missing required arguments"
                            tool_entry["status"] = "error"

                    elif tool_name == "record_discovery":
                        max_retries = 3 if tool_name in CRITICAL_TOOLS else 1

                        def record_discovery_fn():
                            raw_confidence = tool_input.get("confidence", 0.5)
                            try:
                                confidence_float = float(raw_confidence) if raw_confidence is not None else 0.5
                            except (TypeError, ValueError):
                                confidence_float = 0.5

                            discovery = Discovery(
                                round_num=iteration + 1,
                                discovery_type=tool_input.get("discovery_type", "unknown"),
                                content=tool_input.get("content", ""),
                                confidence=confidence_float,
                                evidence=tool_input.get("evidence", [])
                            )

                            self.logger.log_discovery(
                                agent_name=self.name,
                                contract_name=contract_name,
                                discovery_type=discovery.discovery_type,
                                content=discovery.content,
                                confidence=discovery.confidence,
                                evidence=discovery.evidence
                            )

                            return {"status": "recorded", "discovery": discovery}

                        result_content = self._execute_tool_with_retry(
                            tool_name,
                            record_discovery_fn,
                            max_retries
                        )

                        if isinstance(result_content, dict) and "discovery" in result_content:
                            discovery = result_content["discovery"]
                            discoveries.append(discovery)

                            if self.a2a_bus and self.a2a_agent_id and discovery.confidence >= 0.7:
                                self._handle_publish_discovery(
                                    discovery_summary=f"{discovery.discovery_type}: {discovery.content}",
                                    area_covered=discovery.discovery_type,
                                    confidence=discovery.confidence
                                )

                            result_content = f"Discovery recorded: {discovery.discovery_type}"

                    elif tool_name == "update_knowledge_graph":
                        action = tool_input.get("action")
                        if action == "add_node":
                            node_id = tool_input.get("node_id")
                            if node_id:
                                update = {
                                    "type": "node",
                                    "node_id": node_id,
                                    "node_type": tool_input.get("node_type"),
                                    "name": tool_input.get("name", node_id),
                                    "data": tool_input.get("data", {}),
                                    "confidence": 1.0
                                }
                                graph_updates.append(update)

                                node_type_value = update["node_type"]
                                if not node_type_value:
                                    node_type = NodeType.BUSINESS_LOGIC
                                else:
                                    try:
                                        node_type = NodeType(node_type_value)
                                    except ValueError:
                                        invalid_to_valid_map = {
                                            "economic_insight": NodeType.BUSINESS_LOGIC,
                                            "economic_finding": NodeType.BUSINESS_LOGIC,
                                            "state_insight": NodeType.STATE_VAR,
                                            "flow_insight": NodeType.VALUE_FLOW,
                                            "dependency_insight": NodeType.DEPENDENCY,
                                            "access_insight": NodeType.ACCESS_CONTROL,
                                            "invariant_insight": NodeType.INVARIANT,
                                        }
                                        node_type = invalid_to_valid_map.get(node_type_value, NodeType.BUSINESS_LOGIC)

                                knowledge_graph.add_node(
                                    node_id=update["node_id"],
                                    node_type=node_type,
                                    name=update["name"],
                                    data=update["data"],
                                    discovered_by=self.name,
                                    confidence=update["confidence"]
                                )
                                result_content = f"Node added: {update['node_id']}"
                            else:
                                result_content = "add_node skipped: missing node_id"
                                tool_entry["status"] = "error"

                        elif action == "add_edge":
                            source = tool_input.get("source")
                            target = tool_input.get("target")
                            if source and target:
                                update = {
                                    "type": "edge",
                                    "source": source,
                                    "target": target,
                                    "edge_type": tool_input.get("edge_type"),
                                    "data": tool_input.get("data", {}),
                                    "confidence": 1.0
                                }
                                graph_updates.append(update)

                                try:
                                    edge_type_value = update["edge_type"]
                                    try:
                                        edge_type = EdgeType(edge_type_value)
                                    except ValueError:
                                        edge_type = EdgeType.DEPENDS_ON

                                    knowledge_graph.add_edge(
                                        source=update["source"],
                                        target=update["target"],
                                        edge_type=edge_type,
                                        data=update["data"],
                                        discovered_by=self.name,
                                        confidence=update["confidence"]
                                    )
                                    result_content = f"Edge added: {update['source']} -> {update['target']}"
                                except Exception as edge_exc:
                                    result_content = f"Failed to add edge: {str(edge_exc)}"
                                    tool_entry["status"] = "error"
                            else:
                                result_content = "add_edge skipped: missing source or target"
                                tool_entry["status"] = "error"

                    elif tool_name == "query_knowledge_base":
                        result_content = self._handle_query_knowledge_base(tool_input or {})

                    elif tool_name == "get_relevant_patterns":
                        result_content = self._handle_get_relevant_patterns(tool_input or {})

                    elif tool_name == "analysis_complete":
                        max_retries = 3 if tool_name in CRITICAL_TOOLS else 1
                        result_content = self._execute_tool_with_retry(
                            tool_name,
                            lambda: "analysis complete",
                            max_retries
                        )
                        tool_entry["status"] = "complete"

                    else:
                        result_content = f"Unknown tool '{tool_name}'"
                        tool_entry["status"] = "error"

                except Exception as exc:
                    self.logger.error(f"[{self.name}] tool '{tool_name}' error: {exc}")
                    result_content = f"{tool_name} error: {exc}"
                    tool_entry["status"] = "error"

                tool_entry["result"] = result_content
                tool_call_log.append(tool_entry)

                if tool_name != "analysis_complete":
                    tool_result_blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "name": tool_name,
                        "content": result_content if result_content else "Success",
                        "is_error": tool_entry["status"] == "error"
                    })

            if tool_result_blocks:
                messages.append({
                    "role": "user",
                    "content": tool_result_blocks
                })
            elif not analysis_complete_called:
                messages.append({
                    "role": "user",
                    "content": [{"type": "text", "text": "continue analysis or call analysis_complete() when done"}]
                })

            if len(messages) > MAX_MESSAGES:
                if self.compressor:
                    messages, tokens_saved = self.compressor.process(messages)
                else:
                    first_msg = messages[0] if messages else None
                    last_msgs = messages[-50:] if len(messages) > 50 else messages[1:]

                    result = [first_msg] if first_msg else []
                    prev_role = first_msg.get("role") if first_msg else None

                    for msg in last_msgs:
                        curr_role = msg.get("role")
                        if curr_role != prev_role:
                            result.append(msg)
                            prev_role = curr_role

                    messages = result

            tool_exec_time = time_module.time() - tool_exec_start

            if self.compressor:
                messages, tokens_saved = self.compressor.process(messages)

            if analysis_complete_called:
                break

            if (time_module.time() - loop_start_time) > max_seconds:
                break

            iteration_tool_count = len(response.tool_calls)
            current_discovery_count = len(discoveries)

            if current_discovery_count > last_discovery_count:
                iterations_without_discovery = 0
                last_discovery_count = current_discovery_count
            else:
                iterations_without_discovery += 1

            if iteration_tool_count == 0:
                iterations_without_tools += 1
            else:
                iterations_without_tools = 0

            if iterations_without_discovery >= max_iterations_no_discovery and iteration > 20:
                break

            if iterations_without_tools >= max_iterations_no_tools:
                break

        duration = time.time() - start_time

        if not analysis_complete_called:
            summary = f"ended after {iterations_completed} iterations without analysis_complete()"
            if discoveries:
                inferred_areas = sorted({
                    getattr(d, "discovery_type", str(getattr(d, "content", "")[:32])).strip()
                    for d in discoveries
                    if getattr(d, "discovery_type", None)
                })
                areas_covered = [area for area in inferred_areas if area]
            confidence = min(confidence, 0.6)

        self.cost_manager.log_cost(
            agent_name=self.name,
            contract_name=contract_name,
            round_num=1,
            operation="analysis",
            cost=total_cost
        )

        logger.info("="*70)
        logger.info(f"[ok] [{self.name}] complete", extra={
            "specialist": self.name,
            "contract": contract_name,
            "discoveries": len(discoveries),
            "cost": total_cost,
            "duration": duration,
            "thinking_tokens": total_thinking_tokens
        })
        logger.info("="*70)

        result = EnhancedAnalysisResult(
            discoveries=list(discoveries),
            graph_updates=graph_updates,
            tool_calls=tool_call_log,
            functional_analyses=functional_analyses,
            reflections=reflections,
            summary=summary,
            confidence=confidence,
            areas_covered=areas_covered,
            total_discoveries=len(discoveries),
            cost=total_cost,
            duration_seconds=duration,
            thinking=None,
            thinking_tokens=total_thinking_tokens,
            prompt_tokens=total_prompt_tokens,
            output_tokens=total_output_tokens,
            analysis_complete=analysis_complete_called
        )

        self._current_contract_name = None
        return [result]

    def _persist_partial_discoveries(self, discoveries: List[Discovery]) -> None:
        try:
            if discoveries:
                for disc in discoveries:
                    self.logger.info(f"[{self.name}] partial: {disc.discovery_type} - {disc.content[:100]}")
        except Exception as e:
            self.logger.error(f"[{self.name}] failed to persist: {e}")

    def _execute_tool_with_retry(self, tool_name: str, tool_callable, max_retries: int = 1) -> Any:
        for attempt in range(max_retries):
            try:
                result = tool_callable()
                return result
            except Exception as exc:
                if attempt < max_retries - 1:
                    continue
                raise Exception(f"tool {tool_name} failed after {max_retries} attempts: {exc}")

    def _format_prior_discoveries(self, prior_discoveries: List[Discovery]) -> str:
        if not prior_discoveries:
            return ""

        lines = [
            "\n\n═══════════════════════════════════════════════════════════════════════════════",
            "previous specialist findings (build on these, avoid duplication):"
        ]

        for idx, discovery in enumerate(prior_discoveries[-20:], 1):
            confidence = getattr(discovery, "confidence", 0.0)
            dtype = getattr(discovery, "discovery_type", "unknown")
            content = getattr(discovery, "content", "").strip() or "(no details provided)"
            evidence = discovery.evidence if getattr(discovery, "evidence", None) else []

            lines.append(f"{idx}. [{dtype.upper()} | confidence={confidence:.2f}] {content}")
            if evidence:
                lines.append(f"    Evidence: {', '.join(evidence[:3])}")

        lines.append("focus on new insights, deeper validation, or cross-domain implications")
        lines.append("═══════════════════════════════════════════════════════════════════════════════")

        return "\n".join(lines)

    def _handle_query_knowledge_base(self, params: Dict[str, Any]) -> str:
        if not self.knowledge_base:
            return "kb not available"

        contract_name = self._current_contract_name or params.get("contract_name") or "unknown_contract"
        vuln_type = params.get("vulnerability_type")

        try:
            if vuln_type:
                patterns = self.knowledge_base.get_patterns_by_type(vuln_type)
                if not patterns:
                    patterns = self.knowledge_base.get_high_confidence_patterns()
            else:
                patterns = self.knowledge_base.get_relevant_patterns(contract_name, top_k=5)

            if not patterns:
                target = vuln_type or contract_name
                return f"No historical patterns found for '{target}'."

            return self._format_patterns_for_output(patterns)
        except Exception as exc:
            return f"kb query failed: {exc}"

    _pattern_cache: Dict[str, str] = {}

    def _handle_get_relevant_patterns(self, params: Dict[str, Any]) -> str:
        if not self.knowledge_base:
            return "kb not available"

        contract_name = self._current_contract_name or params.get("contract_name") or "unknown_contract"
        features = params.get("contract_features") or []

        cache_key = f"{contract_name}:{':'.join(sorted(features)) if features else 'all'}"
        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]

        try:
            if getattr(self.knowledge_base, "enable_graph_rag", False):
                query = " ".join(features) if features else None
                patterns = self.knowledge_base.get_relevant_patterns_with_graph(
                    contract_name=contract_name,
                    query=query,
                    top_k=5
                )
            else:
                patterns = self.knowledge_base.get_relevant_patterns(contract_name, top_k=5)

            if not patterns:
                result = "No patterns matched the provided features."
            else:
                result = self._format_patterns_for_output(patterns)

            if len(self._pattern_cache) > 100:
                self._pattern_cache.clear()
            self._pattern_cache[cache_key] = result

            return result
        except Exception as exc:
            return f"pattern query failed: {exc}"

    def _format_patterns_for_output(self, patterns: List[Any], limit: int = 5) -> str:
        summary = []
        for pattern in patterns[:limit]:
            summary.append({
                "id": getattr(pattern, "id", "unknown"),
                "name": getattr(pattern, "name", "unknown"),
                "type": getattr(pattern, "vuln_type", "unknown"),
                "confidence": round(float(getattr(pattern, "confidence", 0.0)), 2),
                "synthesized": getattr(pattern, "synthesized", False),
                "source_patterns": getattr(pattern, "source_patterns", []),
                "description": getattr(pattern, "description", "")[:200]
            })
        return json.dumps(summary, indent=2)

    def _handle_check_peer_messages(self, message_types: List[str] = None) -> str:
        if not self.a2a_bus or not self.a2a_agent_id:
            return "a2a not enabled"

        try:
            messages, new_index = self.a2a_bus.get_messages(
                self.a2a_agent_id,
                message_types=None,
                since_index=self._a2a_last_check_index
            )

            self._a2a_last_check_index = new_index

            all_messages = []
            if self._a2a_pending_messages:
                all_messages.extend(self._a2a_pending_messages)
                self._a2a_pending_messages = []
            all_messages.extend(messages)

            deliver: List[Any] = []
            if message_types:
                allowed = set(message_types)
                for msg in all_messages:
                    if msg.message_type.value in allowed:
                        deliver.append(msg)
                    else:
                        self._a2a_pending_messages.append(msg)
            else:
                deliver = all_messages

            if not deliver:
                return "no peer messages"

            result = "=== PEER MESSAGES ===\n\n"
            for msg in deliver:
                result += f"from: {msg.from_agent}\n"
                result += f"type: {msg.message_type.value}\n"
                result += f"content: {msg.payload}\n"
                if msg.metadata:
                    result += f"metadata: {msg.metadata}\n"
                result += "\n"

            return result
        except Exception as e:
            return f"peer message error: {e}"

    def _handle_publish_discovery(self, discovery_summary: str, area_covered: str, confidence: float = 0.8) -> str:
        if not self.a2a_bus or not self.a2a_agent_id:
            return "a2a not enabled"

        try:
            from agent.a2a_bus import A2AMessage, MessageType
            import uuid
            import time

            message = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=self.a2a_agent_id,
                to_agent="broadcast",
                message_type=MessageType.DISCOVERY,
                payload={
                    "discovery_summary": discovery_summary,
                    "area_covered": area_covered,
                    "confidence": confidence
                },
                metadata={"timestamp": time.time()}
            )

            self.a2a_bus.publish(message)
            return f"published to peers: {area_covered}"
        except Exception as e:
            return f"publish error: {e}"

    def _handle_request_peer_review(self, finding: str, question: str, target_specialist: str = None) -> str:
        if not self.a2a_bus or not self.a2a_agent_id:
            return "a2a not enabled"

        try:
            from agent.a2a_bus import A2AMessage, MessageType
            import uuid
            import time

            message = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=self.a2a_agent_id,
                to_agent=target_specialist or "broadcast",
                message_type=MessageType.PEER_REVIEW_REQUEST,
                payload={
                    "finding": finding,
                    "question": question
                },
                metadata={"timestamp": time.time()}
            )

            self.a2a_bus.publish(message)
            target = target_specialist or "all peers"
            return f"review requested from {target}"
        except Exception as e:
            return f"review request error: {e}"

    def _get_enhanced_system_prompt(self) -> str:
        from src.research.shared_prompts import SPECIALIST_ENHANCEMENT
        base_prompt = self.get_system_prompt()
        return base_prompt + "\n\n" + SPECIALIST_ENHANCEMENT


BaseSpecialist = EnhancedAgenticSpecialist
AnalysisResult = EnhancedAnalysisResult

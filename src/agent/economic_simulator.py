"""module docstring"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from config import config
from agent.base_attacker import AttackHypothesis
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
from kb.knowledge_base import KnowledgeBase
from utils.logging import ResearchLogger


@dataclass
class SimulationDiscovery:
    actor: str
    scenario: str
    target_function: Optional[str]
    steps: List[str]
    profit: float
    cost: float
    margin: float
    confidence: float
    evidence: List[str]

    def to_hypothesis(self, index: int) -> AttackHypothesis:
        """Convert discovery into an AttackHypothesis consumed by the attack orchestrator."""
        impact = f"Profit {self.profit:.2f} vs cost {self.cost:.2f} (margin {self.margin:.2f})"
        return AttackHypothesis(
            hypothesis_id=f"econ_sim_{self.actor.lower()}_{index}",
            attack_type=f"{self.actor.lower()}_economic",
            description=f"[{self.actor}] {self.scenario} (margin {self.margin:.2f})",
            target_function=self.target_function or "economic-path",
            preconditions=[
                "Capital is accessible for the opening leg (flash liquidity or surplus balance)",
                "Protocol allows the sequence without guard rails",
            ],
            steps=self.steps,
            expected_impact=impact,
            confidence=self.confidence,
            requires_research=[],
            evidence=self.evidence + [impact],
        )


@dataclass
class SimulationEnvironment:
    contract_info: Dict[str, Any]
    contract_source: str
    max_steps: int
    min_margin: float
    balance_vars: List[str]
    debt_vars: List[str]
    reserves_vars: List[str]

    @property
    def token_flows(self) -> List[Dict[str, Any]]:
        return self.contract_info.get("token_flows", [])

    @property
    def has_flashloans(self) -> bool:
        return bool(self.contract_info.get("flash_loan_capable"))

    @property
    def has_oracle(self) -> bool:
        return bool(self.contract_info.get("has_oracle"))

    @property
    def external_functions(self) -> List[str]:
        return [fn.lower() for fn in self.contract_info.get("external_functions", [])]

    @property
    def state_vars(self) -> List[str]:
        return [sv.lower() for sv in self.contract_info.get("state_vars", [])]


class EconomicSimAgent:
    """Base class for rational economic simulation actors."""

    name: str = "agent"

    def evaluate(self, env: SimulationEnvironment) -> List[SimulationDiscovery]:
        raise NotImplementedError

    @staticmethod
    def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
        return max(low, min(high, value))

    def _profit_confidence(self, margin: float, signal_strength: float) -> float:
        """Translate profit margin + signal strength into a confidence score."""
        base = 0.55 + margin * 0.35
        return self._clamp(base + signal_strength * 0.1)


class Arbitrageur(EconomicSimAgent):
    name = "Arbitrageur"

    def evaluate(self, env: SimulationEnvironment) -> List[SimulationDiscovery]:
        discoveries: List[SimulationDiscovery] = []
        flows = env.token_flows
        balances = env.balance_vars
        reserves = env.reserves_vars

        if not flows and not env.has_oracle:
            return discoveries

        # score individual flows for imbalance / missing checks
        imbalance_score = 0.0
        target_function = None
        for flow in flows:
            flow_type = (flow.get("flow_type") or "").lower()
            amount_expr = (flow.get("amount_expression") or "").lower()
            if flow_type in {"deposit", "withdrawal"}:
                imbalance_score += 0.25
            if "reward" in amount_expr or "bonus" in amount_expr:
                imbalance_score += 0.35
                target_function = target_function or flow.get("function")
            if not flow.get("has_balance_check", True):
                imbalance_score += 0.15
                target_function = target_function or flow.get("function")
            if not flow.get("has_allowance_check", True):
                imbalance_score += 0.10
            if balances or reserves:
                imbalance_score += 0.10

            # function-level hook for swaps/price-dependent functions
            func_name = (flow.get("function") or "").lower()
            if any(tok in func_name for tok in ("swap", "exchange", "price", "update")):
                imbalance_score += 0.20
                target_function = target_function or flow.get("function")
            if "fee" in amount_expr:
                imbalance_score += 0.05

        oracle_signal = 0.3 if env.has_oracle else 0.0
        flash_liquidity = 0.4 if env.has_flashloans else 0.15
        baseline_cost = 0.35 + (0.15 if env.has_flashloans else 0.30)
        profit = (1.0 + imbalance_score + oracle_signal) * (1.0 + flash_liquidity)
        margin = profit - baseline_cost

        if margin <= env.min_margin:
            return discoveries

        confidence = self._profit_confidence(margin, imbalance_score + oracle_signal + flash_liquidity)
        steps = [
            "Source capital via flash loan" if env.has_flashloans else "Source temporary capital from treasury",
            "Distort pricing through oracle touchpoint or imbalance in reward math",
            f"Exploit {target_function or 'value flow'} to harvest priced asset",
            "Restore state and unwind loan to crystallize spread",
        ][: env.max_steps]
        evidence = [
            f"Token flows analysed: {len(flows)}",
            f"Oracle dependencies present: {env.has_oracle}",
            f"Flash liquidity available: {env.has_flashloans}",
        ]
        scenario = "Cross-contract price imbalance via oracle/manipulated flows" if env.has_oracle else "Internal pricing skew exploitable for spread"
        discoveries.append(
            SimulationDiscovery(
                actor=self.name,
                scenario=scenario,
                target_function=target_function,
                steps=steps,
                profit=profit,
                cost=baseline_cost,
                margin=margin,
                confidence=confidence,
                evidence=evidence,
            )
        )
        return discoveries


class Liquidator(EconomicSimAgent):
    name = "Liquidator"

    def evaluate(self, env: SimulationEnvironment) -> List[SimulationDiscovery]:
        discoveries: List[SimulationDiscovery] = []
        liquidation_candidates = [fn for fn in env.external_functions if any(tok in fn for tok in ("liquidate", "seize", "auction"))]
        debt_signals = [sv for sv in env.state_vars if any(tok in sv for tok in ("debt", "collateral", "loan"))]
        reserves = env.reserves_vars

        if not liquidation_candidates and not debt_signals:
            return discoveries

        # assess buffer for under-collateralisation handling
        coverage_gaps = 0.0
        target_function = liquidation_candidates[0] if liquidation_candidates else None
        for flow in env.token_flows:
            if flow.get("flow_type", "").lower() in {"burn", "mint"}:
                coverage_gaps += 0.20
                target_function = target_function or flow.get("function")
            if not flow.get("updates_before_transfer", True):
                coverage_gaps += 0.25
            if not flow.get("has_balance_check", True):
                coverage_gaps += 0.15

        stress_multiplier = 1.0 + coverage_gaps + (0.15 if env.has_oracle else 0.0) + (0.1 if reserves else 0.0)
        profit = 0.9 * stress_multiplier + (0.20 if env.has_flashloans else 0.0)
        cost = 0.30 + (0.20 if env.has_flashloans else 0.45)
        margin = profit - cost

        if margin <= env.min_margin:
            return discoveries

        confidence = self._profit_confidence(margin, coverage_gaps + (0.1 if debt_signals else 0.0))
        optimistic_ltv = "Push collateral value down (oracle skew) to trigger liquidation" if env.has_oracle else "Exploit stale collateral ratios to force liquidation"
        steps = [
            optimistic_ltv,
            f"Call {target_function or 'liquidation path'} to seize collateral",
            "Flip seized assets on secondary market to realise profit",
        ][: env.max_steps]

        evidence = [
            f"Liquidation entrypoints: {', '.join(liquidation_candidates) if liquidation_candidates else 'heuristic'}",
            f"Debt/collateral state vars detected: {', '.join(debt_signals) if debt_signals else 'none'}",
            f"Coverage gaps score: {coverage_gaps:.2f}",
        ]
        discoveries.append(
            SimulationDiscovery(
                actor=self.name,
                scenario="Forced liquidation from stale collateral checks",
                target_function=target_function,
                steps=steps,
                profit=profit,
                cost=cost,
                margin=margin,
                confidence=confidence,
                evidence=evidence,
            )
        )
        return discoveries


class EconomicSimulator:
    """
    Game-theoretic simulator that runs bounded rational agents against contract context.
    """

    def __init__(
        self,
        knowledge_graph: KnowledgeGraph,
        knowledge_base: Optional[KnowledgeBase] = None,
        logger: Optional[ResearchLogger] = None,
        max_steps: int = config.ECON_SIM_MAX_STEPS,
        min_margin: float = config.ECON_SIM_MIN_MARGIN,
    ):
        self.knowledge_graph = knowledge_graph
        self.knowledge_base = knowledge_base
        self.logger = logger or ResearchLogger()
        self.max_steps = max_steps
        self.min_margin = min_margin
        self.agents: List[EconomicSimAgent] = [Arbitrageur(), Liquidator()]

    def simulate(self, contract_info: Dict[str, Any], contract_source: str = "") -> Dict[str, Any]:
        """
        Execute all simulation agents and emit discoveries + hypotheses.
        """
        lowers = {sv.lower(): sv for sv in contract_info.get("state_vars", [])}
        balance_vars = [v for k, v in lowers.items() if "balance" in k or "asset" in k or "cash" in k]
        debt_vars = [v for k, v in lowers.items() if "debt" in k or "loan" in k or "borrow" in k]
        reserves_vars = [v for k, v in lowers.items() if "reserve" in k or "collateral" in k or "pool" in k]
        env = SimulationEnvironment(
            contract_info=contract_info,
            contract_source=contract_source,
            max_steps=self.max_steps,
            min_margin=self.min_margin,
            balance_vars=balance_vars,
            debt_vars=debt_vars,
            reserves_vars=reserves_vars,
        )
        discoveries: List[SimulationDiscovery] = []
        for agent in self.agents:
            agent_results = agent.evaluate(env)
            if agent_results:
                self.logger.info(
                    f"[EconomicSimulator] {agent.name} found {len(agent_results)} profitable path(s)"
                )
            discoveries.extend(agent_results)

        hypotheses: List[AttackHypothesis] = []
        for idx, disc in enumerate(discoveries):
            self._record_in_graph(disc, contract_info.get("name", "Unknown"))
            self._record_in_kb(disc, contract_info.get("name", "Unknown"))
            hypotheses.append(disc.to_hypothesis(idx))

        summaries = [
            {
                "actor": d.actor,
                "scenario": d.scenario,
                "target_function": d.target_function,
                "profit": d.profit,
                "cost": d.cost,
                "margin": d.margin,
                "confidence": d.confidence,
                "evidence": d.evidence,
            }
            for d in discoveries
        ]

        return {
            "discoveries": discoveries,
            "hypotheses": hypotheses,
            "summaries": summaries,
        }

    def _record_in_graph(self, discovery: SimulationDiscovery, contract_name: str) -> None:
        """Persist discovery into the knowledge graph for downstream prompts."""
        node_id = f"econ::{contract_name}::{discovery.actor}::{discovery.target_function or 'system'}"
        data = {
            "scenario": discovery.scenario,
            "profit": discovery.profit,
            "cost": discovery.cost,
            "margin": discovery.margin,
            "steps": discovery.steps,
            "evidence": discovery.evidence,
            "source": "economic_simulator",
        }
        try:
            self.knowledge_graph.add_node(
                node_id=node_id,
                node_type=NodeType.BUSINESS_LOGIC,
                name=discovery.scenario,
                data=data,
                discovered_by="EconomicSimulator",
                confidence=discovery.confidence,
                metadata={"actor": discovery.actor},
            )
            if discovery.target_function:
                fn_node = f"fn::{discovery.target_function}"
                self.knowledge_graph.add_edge(
                    source=fn_node,
                    target=node_id,
                    edge_type=EdgeType.DEPENDS_ON,
                    data={"margin": discovery.margin, "profit": discovery.profit},
                    discovered_by="EconomicSimulator",
                    confidence=discovery.confidence,
                )
        except (AttributeError, KeyError, ValueError) as exc:
            # knowledge graph operations may fail due to invalid node types or missing data
            self.logger.warning(f"[EconomicSimulator] Failed to write to knowledge graph: {exc}", exc_info=True)

    def _record_in_kb(self, discovery: SimulationDiscovery, contract_name: str) -> None:
        """Record discovery into the persistent knowledge base if available."""
        if not self.knowledge_base:
            return
        entry = self.knowledge_base.contract_knowledge.get(contract_name, {})
        econ_entries = entry.get("economic_simulator", [])
        econ_entries.append(
            {
                "actor": discovery.actor,
                "scenario": discovery.scenario,
                "target_function": discovery.target_function,
                "profit": discovery.profit,
                "cost": discovery.cost,
                "margin": discovery.margin,
                "confidence": discovery.confidence,
                "evidence": discovery.evidence,
            }
        )
        entry["economic_simulator"] = econ_entries
        # ensure the entry stays registered
        self.knowledge_base.contract_knowledge[contract_name] = entry

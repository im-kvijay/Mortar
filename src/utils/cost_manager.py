"""cost management system. purpose: - track all ai api costs in real-time - enforce budget limits (i..."""

from typing import Optional, Dict, List
from dataclasses import dataclass, field
from datetime import datetime
import json
import threading

class BudgetExceededError(Exception):
    """raised when budget limit is exceeded."""

@dataclass
class CostEntry:
    """single cost entry."""

    timestamp: str
    agent_name: str
    contract_name: str
    round_num: int
    operation: str
    cost: float
    cumulative_cost: float
    metadata: Dict = field(default_factory=dict)

class CostManager:
    """tracks and manages ai api costs. usage: # # unlimited (default) cost_mgr = costmanager() # # with..."""

    def __init__(
        self,
        max_cost_per_contract: Optional[float] = None,
        max_cost_total: Optional[float] = None
    ):
        """initialize cost manager. args: max_cost_per_contract: maximum cost per contract (none = unlimited..."""
        self.max_cost_per_contract = max_cost_per_contract
        self.max_cost_total = max_cost_total

#        # thread safety lock (rlock for reentrant locking - prevents deadlock when
        self._lock = threading.RLock()

#        # tracking
        self.current_cost = 0.0
        self.total_cost = 0.0
        self.cost_log: list[CostEntry] = []
        self.costs_by_contract: dict[str, float] = {}
        self.costs_by_agent: dict[str, float] = {}
        self.current_contract: Optional[str] = None

    def start_contract(self, contract_name: str):
        """start tracking costs for a new contract. resets current_cost, updates current_contract."""
        with self._lock:
            self.current_contract = contract_name
            self.current_cost = 0.0
            if contract_name not in self.costs_by_contract:
                self.costs_by_contract[contract_name] = 0.0

    def log_cost(
        self,
        agent_name: str,
        contract_name: str,
        round_num: int,
        operation: str,
        cost: float,
        metadata: Optional[dict] = None
    ):
        """log a cost entry. updates: - current_cost (for current contract) - total_cost (across all contrac..."""
        timestamp = datetime.now().isoformat()

        with self._lock:
#            # update totals
            self.current_cost += cost
            self.total_cost += cost

#            # update by-contract tracking
            if contract_name not in self.costs_by_contract:
                self.costs_by_contract[contract_name] = 0.0
            self.costs_by_contract[contract_name] += cost

#            # update by-agent tracking
            if agent_name not in self.costs_by_agent:
                self.costs_by_agent[agent_name] = 0.0
            self.costs_by_agent[agent_name] += cost

#            # create log entry
            entry = CostEntry(
                timestamp=timestamp,
                agent_name=agent_name,
                contract_name=contract_name,
                round_num=round_num,
                operation=operation,
                cost=cost,
                cumulative_cost=self.current_cost,
                metadata=metadata or {}
            )
            self.cost_log.append(entry)

    def check_budget(self) -> None:
        """check if budget limits are exceeded. raises: budgetexceedederror: if budget limit exceeded"""
        with self._lock:
#            # check per-contract limit
            if self.max_cost_per_contract is not None:
                if self.current_cost >= self.max_cost_per_contract:
                    raise BudgetExceededError(
                        f"Cost ${self.current_cost:.2f} exceeds per-contract limit "
                        f"${self.max_cost_per_contract:.2f}"
                    )

#            # check total limit
            if self.max_cost_total is not None:
                if self.total_cost >= self.max_cost_total:
                    raise BudgetExceededError(
                        f"Total cost ${self.total_cost:.2f} exceeds total limit "
                        f"${self.max_cost_total:.2f}"
                    )

    def would_exceed_budget(self, proposed_cost: float) -> bool:
        """check if proposed cost would exceed budget (call before spending). args: proposed_cost: cost to c..."""
        with self._lock:
#            # check per-contract limit
            if self.max_cost_per_contract is not None:
                if (self.current_cost + proposed_cost) >= self.max_cost_per_contract:
                    return True

#            # check total limit
            if self.max_cost_total is not None:
                if (self.total_cost + proposed_cost) >= self.max_cost_total:
                    return True

            return False

    def get_current_cost(self) -> float:
        """get current contract cost."""
        with self._lock:
            return self.current_cost

    def get_total_cost(self) -> float:
        """get total cost across all contracts."""
        with self._lock:
            return self.total_cost

    def get_costs_by_contract(self) -> Dict[str, float]:
        """get cost breakdown by contract."""
        with self._lock:
            return self.costs_by_contract.copy()

    def get_costs_by_agent(self) -> Dict[str, float]:
        """get cost breakdown by agent."""
        with self._lock:
            return self.costs_by_agent.copy()

    def get_cost_summary(self) -> Dict:
        """get  cost summary. returns: dict with current_cost, total_cost, by_contract, by_agent"""
        with self._lock:
            return {
                "current_contract": self.current_contract,
                "current_cost": self.current_cost,
                "total_cost": self.total_cost,
                "costs_by_contract": self.costs_by_contract.copy(),
                "costs_by_agent": self.costs_by_agent.copy(),
                "num_calls": len(self.cost_log),
                "limits": {
                    "max_per_contract": self.max_cost_per_contract,
                    "max_total": self.max_cost_total
                }
            }

    def save_to_json(self, filepath: str):
        """save cost log to json file."""
        with self._lock:
            log_copy = list(self.cost_log)
            summary_copy = {
                "current_contract": self.current_contract,
                "current_cost": self.current_cost,
                "total_cost": self.total_cost,
                "costs_by_contract": self.costs_by_contract.copy(),
                "costs_by_agent": self.costs_by_agent.copy(),
                "num_calls": len(self.cost_log),
                "limits": {
                    "max_per_contract": self.max_cost_per_contract,
                    "max_total": self.max_cost_total
                }
            }

#        # now iterate over copies outside the lock
        data = {
            "summary": summary_copy,
            "log": [
                {
                    "timestamp": entry.timestamp,
                    "agent_name": entry.agent_name,
                    "contract_name": entry.contract_name,
                    "round_num": entry.round_num,
                    "operation": entry.operation,
                    "cost": entry.cost,
                    "cumulative_cost": entry.cumulative_cost,
                    "metadata": entry.metadata
                }
                for entry in log_copy
            ]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def get_average_cost_per_call(self) -> float:
        """get average cost per api call."""
        if len(self.cost_log) == 0:
            return 0.0
        return self.total_cost / len(self.cost_log)

    def get_contract_summary(self, contract_name: str) -> Dict:
        """get cost summary for a specific contract. args: contract_name: name of contract returns: dict wit..."""
        entries = [e for e in self.cost_log if e.contract_name == contract_name]

        if not entries:
            return {
                "contract_name": contract_name,
                "total_cost": 0.0,
                "num_calls": 0,
                "agents": [],
                "rounds": []
            }

        agents = list(set(e.agent_name for e in entries))
        rounds = list(set(e.round_num for e in entries))

        return {
            "contract_name": contract_name,
            "total_cost": sum(e.cost for e in entries),
            "num_calls": len(entries),
            "agents": agents,
            "rounds": sorted(rounds),
            "avg_cost_per_call": sum(e.cost for e in entries) / len(entries)
        }

    def print_summary(self):
        """print cost summary to console."""
        print("\n" + "="*60)
        print("COST SUMMARY")
        print("="*60)
        print(f"Current Contract: {self.current_contract or 'None'}")
        print(f"Current Cost: ${self.current_cost:.4f}")
        print(f"Total Cost: ${self.total_cost:.4f}")
        print("\nLimits:")
        print(f"  Per-Contract: ${self.max_cost_per_contract if self.max_cost_per_contract else 'Unlimited'}")
        print(f"  Total: ${self.max_cost_total if self.max_cost_total else 'Unlimited'}")
        print("\nCosts by Contract:")
        for contract, cost in sorted(self.costs_by_contract.items(), key=lambda x: x[1], reverse=True):
            print(f"  {contract}: ${cost:.4f}")
        print("\nCosts by Agent:")
        for agent, cost in sorted(self.costs_by_agent.items(), key=lambda x: x[1], reverse=True):
            print(f"  {agent}: ${cost:.4f}")
        print(f"\nTotal API Calls: {len(self.cost_log)}")
        print(f"Average Cost per Call: ${self.get_average_cost_per_call():.4f}")
        print("="*60 + "\n")

# example usage
if __name__ == "__main__":
#    # create cost manager with limit
    cost_mgr = CostManager(max_cost_per_contract=5.00)

#    # start tracking a contract
    cost_mgr.start_contract("UnstoppableVault")

#    # log some costs
    cost_mgr.log_cost("StateFlow", "UnstoppableVault", round_num=1, operation="analysis", cost=0.15)
    cost_mgr.log_cost("Invariant", "UnstoppableVault", round_num=1, operation="analysis", cost=0.12)
    cost_mgr.log_cost("StateFlow", "UnstoppableVault", round_num=2, operation="synthesis", cost=0.08)

#    # check budget
    try:
        cost_mgr.check_budget()
        print("[OK] Within budget")
    except BudgetExceededError as e:
        print(f"[ERROR] {e}")

#    # print summary
    cost_mgr.print_summary()

#    # get contract summary
    summary = cost_mgr.get_contract_summary("UnstoppableVault")
    print(f"\nUnstoppableVault Summary: {summary}")

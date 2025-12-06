"""s for Cost Manager"""

import unittest
import tempfile
import json
from pathlib import Path
from src.utils.cost_manager import (
    CostManager,
    CostEntry,
    BudgetExceededError
)

class TestCostManager(unittest.TestCase):
    """Test CostManager functionality"""

    def test_cost_manager_initialization(self):
        # unlimited
        cm = CostManager()
        self.assertIsNone(cm.max_cost_per_contract)
        self.assertIsNone(cm.max_cost_total)
        self.assertEqual(cm.current_cost, 0.0)
        self.assertEqual(cm.total_cost, 0.0)

        # with limits
        cm_limited = CostManager(max_cost_per_contract=5.0, max_cost_total=20.0)
        self.assertEqual(cm_limited.max_cost_per_contract, 5.0)
        self.assertEqual(cm_limited.max_cost_total, 20.0)

    def test_start_contract(self):
        cm = CostManager()

        cm.start_contract("Contract1")
        self.assertEqual(cm.current_contract, "Contract1")
        self.assertEqual(cm.current_cost, 0.0)
        self.assertIn("Contract1", cm.costs_by_contract)

        # add some cost
        cm.log_cost("Agent1", "Contract1", 1, "test", 1.5)
        self.assertEqual(cm.current_cost, 1.5)

        # start new contract should reset current_cost
        cm.start_contract("Contract2")
        self.assertEqual(cm.current_contract, "Contract2")
        self.assertEqual(cm.current_cost, 0.0)
        self.assertEqual(cm.total_cost, 1.5)  # total should persist

    def test_log_cost_basic(self):
        cm = CostManager()
        cm.start_contract("TestContract")

        cm.log_cost(
            agent_name="StateFlow",
            contract_name="TestContract",
            round_num=1,
            operation="analysis",
            cost=0.25,
            metadata={"model": "x-ai/grok-4.1-fast"}
        )
        self.assertEqual(cm.current_cost, 0.25)
        self.assertEqual(cm.total_cost, 0.25)
        self.assertEqual(cm.costs_by_contract["TestContract"], 0.25)
        self.assertEqual(cm.costs_by_agent["StateFlow"], 0.25)
        self.assertEqual(len(cm.cost_log), 1)

    def test_log_cost_multiple_agents(self):
        cm = CostManager()
        cm.start_contract("TestContract")

        cm.log_cost("Agent1", "TestContract", 1, "op1", 0.10)
        cm.log_cost("Agent2", "TestContract", 1, "op2", 0.15)
        cm.log_cost("Agent1", "TestContract", 2, "op3", 0.12)
        self.assertEqual(cm.costs_by_agent["Agent1"], 0.22)
        self.assertEqual(cm.costs_by_agent["Agent2"], 0.15)
        self.assertEqual(cm.total_cost, 0.37)

    def test_log_cost_multiple_contracts(self):
        cm = CostManager()

        cm.start_contract("Contract1")
        cm.log_cost("Agent1", "Contract1", 1, "op1", 1.0)

        cm.start_contract("Contract2")
        cm.log_cost("Agent1", "Contract2", 1, "op2", 2.0)
        self.assertEqual(cm.costs_by_contract["Contract1"], 1.0)
        self.assertEqual(cm.costs_by_contract["Contract2"], 2.0)
        self.assertEqual(cm.total_cost, 3.0)
        self.assertEqual(cm.current_cost, 2.0)  # current contract cost

    def test_budget_check_no_limits(self):
        cm = CostManager()  # no limits
        cm.start_contract("TestContract")
        cm.log_cost("Agent1", "TestContract", 1, "op1", 100.0)  # large cost

        try:
            cm.check_budget()
        except BudgetExceededError:
            self.fail("Budget check raised exception with no limits")

    def test_budget_check_per_contract_limit(self):
        cm = CostManager(max_cost_per_contract=1.0)
        cm.start_contract("TestContract")

        # under limit
        cm.log_cost("Agent1", "TestContract", 1, "op1", 0.5)
        try:
            cm.check_budget()
        except BudgetExceededError:
            self.fail("Budget check raised exception under limit")

        # at limit - should raise
        cm.log_cost("Agent1", "TestContract", 1, "op2", 0.5)
        with self.assertRaises(BudgetExceededError) as context:
            cm.check_budget()
        self.assertIn("per-contract limit", str(context.exception))

    def test_budget_check_total_limit(self):
        cm = CostManager(max_cost_total=2.0)

        # contract 1
        cm.start_contract("Contract1")
        cm.log_cost("Agent1", "Contract1", 1, "op1", 1.0)
        cm.check_budget()

        # contract 2 - push over total limit
        cm.start_contract("Contract2")
        cm.log_cost("Agent1", "Contract2", 1, "op2", 1.0)

        with self.assertRaises(BudgetExceededError) as context:
            cm.check_budget()
        self.assertIn("total limit", str(context.exception))

    def test_get_cost_summary(self):
        cm = CostManager(max_cost_per_contract=5.0)
        cm.start_contract("TestContract")
        cm.log_cost("Agent1", "TestContract", 1, "op1", 0.5)
        cm.log_cost("Agent2", "TestContract", 1, "op2", 0.3)

        summary = cm.get_cost_summary()

        self.assertEqual(summary["current_contract"], "TestContract")
        self.assertEqual(summary["current_cost"], 0.8)
        self.assertEqual(summary["total_cost"], 0.8)
        self.assertEqual(summary["num_calls"], 2)
        self.assertEqual(summary["limits"]["max_per_contract"], 5.0)
        self.assertIn("TestContract", summary["costs_by_contract"])
        self.assertIn("Agent1", summary["costs_by_agent"])

    def test_get_contract_summary(self):
        cm = CostManager()
        cm.start_contract("TestContract")
        cm.log_cost("Agent1", "TestContract", 1, "op1", 0.5)
        cm.log_cost("Agent2", "TestContract", 1, "op2", 0.3)
        cm.log_cost("Agent1", "TestContract", 2, "op3", 0.2)

        summary = cm.get_contract_summary("TestContract")

        self.assertEqual(summary["contract_name"], "TestContract")
        self.assertEqual(summary["total_cost"], 1.0)
        self.assertEqual(summary["num_calls"], 3)
        self.assertIn("Agent1", summary["agents"])
        self.assertIn("Agent2", summary["agents"])
        self.assertEqual(summary["rounds"], [1, 2])
        self.assertAlmostEqual(summary["avg_cost_per_call"], 1.0 / 3)

    def test_get_contract_summary_nonexistent(self):
        cm = CostManager()
        summary = cm.get_contract_summary("NonExistent")

        self.assertEqual(summary["total_cost"], 0.0)
        self.assertEqual(summary["num_calls"], 0)
        self.assertEqual(summary["agents"], [])

    def test_average_cost_per_call(self):
        cm = CostManager()
        cm.start_contract("TestContract")

        # no calls yet
        self.assertEqual(cm.get_average_cost_per_call(), 0.0)

        # add calls
        cm.log_cost("Agent1", "TestContract", 1, "op1", 0.3)
        cm.log_cost("Agent1", "TestContract", 1, "op2", 0.5)
        cm.log_cost("Agent1", "TestContract", 1, "op3", 0.4)

        self.assertAlmostEqual(cm.get_average_cost_per_call(), 0.4)

    def test_save_to_json(self):
        cm = CostManager()
        cm.start_contract("TestContract")
        cm.log_cost("Agent1", "TestContract", 1, "op1", 0.5,
                   metadata={"model": "x-ai/grok-4-fast"})

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name

        try:
            cm.save_to_json(filepath)

            # read back and verify
            with open(filepath, 'r') as f:
                data = json.load(f)

            self.assertIn("summary", data)
            self.assertIn("log", data)
            self.assertEqual(data["summary"]["total_cost"], 0.5)
            self.assertEqual(len(data["log"]), 1)
            self.assertEqual(data["log"][0]["agent_name"], "Agent1")
            self.assertEqual(data["log"][0]["metadata"]["model"], "x-ai/grok-4-fast")

        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_cost_entry_dataclass(self):
        entry = CostEntry(
            timestamp="2025-10-21T10:00:00",
            agent_name="Agent1",
            contract_name="TestContract",
            round_num=1,
            operation="analysis",
            cost=0.25,
            cumulative_cost=0.25,
            metadata={"tokens": 1000}
        )

        self.assertEqual(entry.agent_name, "Agent1")
        self.assertEqual(entry.cost, 0.25)
        self.assertEqual(entry.metadata["tokens"], 1000)

    def test_get_costs_by_contract(self):
        cm = CostManager()
        cm.start_contract("Contract1")
        cm.log_cost("Agent1", "Contract1", 1, "op1", 1.0)

        costs1 = cm.get_costs_by_contract()
        costs2 = cm.get_costs_by_contract()
        self.assertIsNot(costs1, costs2)
        self.assertEqual(costs1, costs2)

        # modifying copy shouldn't affect original
        costs1["Contract1"] = 999.0
        self.assertEqual(cm.costs_by_contract["Contract1"], 1.0)

    def test_get_costs_by_agent(self):
        cm = CostManager()
        cm.start_contract("Contract1")
        cm.log_cost("Agent1", "Contract1", 1, "op1", 1.0)

        costs1 = cm.get_costs_by_agent()
        costs2 = cm.get_costs_by_agent()
        self.assertIsNot(costs1, costs2)
        self.assertEqual(costs1, costs2)

if __name__ == '__main__':
    unittest.main()

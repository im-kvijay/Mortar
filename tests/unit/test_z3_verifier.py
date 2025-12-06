import unittest

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from utils.logging import ResearchLogger
from config import config
from verification.formal_spec_extractor import StateVariable, FormalSpec, Action
from verification.z3_verifier import Z3Verifier, VerificationResult

class TestZ3Verifier(unittest.TestCase):
    def setUp(self):
        self.logger = ResearchLogger(project_root=str(PROJECT_ROOT))
        self.verifier = Z3Verifier(logger=self.logger, timeout_ms=1000, enable_mcts_fallback=False)
        self._orig_failure_ratio = config.Z3_MAX_FAILED_CONSTRAINT_RATIO
        config.Z3_MAX_FAILED_CONSTRAINT_RATIO = 0.0

    def tearDown(self):
        config.Z3_MAX_FAILED_CONSTRAINT_RATIO = self._orig_failure_ratio

    def test_sat_spec(self):
        spec = FormalSpec(
            hypothesis_id="test_sat",
            state_variables=[
                StateVariable("balance_before", "uint256", "100", "attacker balance before attack"),
                StateVariable("balance_after", "uint256", "?", "attacker balance after attack"),
            ],
            preconditions=["balance_before == 100"],
            actions=[
                Action(
                    step_num=1,
                    function_name="drain",
                    caller="attacker",
                    parameters={"amount": "50"},
                    state_changes=["balance_after == balance_before + amount"],
                    constraints=["amount > 0"]
                )
            ],
            postconditions=["balance_after == 150"],
            invariants_to_check=[],
            economic_constraints=["balance_after > balance_before"],
            extraction_confidence=1.0,
            notes=""
        )

        result = self.verifier.verify(spec)
        self.assertEqual(result.result, VerificationResult.SAT)
        self.assertGreater(result.confidence, 0.9)

    def test_malformed_constraints_return_unknown(self):
        spec = FormalSpec(
            hypothesis_id="bad_spec",
            state_variables=[
                StateVariable("value_before", "uint256", "100", "value"),
                StateVariable("value_after", "uint256", "?", "value"),
            ],
            preconditions=["value_before == 100"],
            actions=[
                Action(
                    step_num=1,
                    function_name="bad",
                    caller="attacker",
                    parameters={},
                    state_changes=["value_after += 10"],  # invalid syntax
                    constraints=["value_after == > value_before"]  # invalid syntax
                )
            ],
            postconditions=["value_after > value_before"],
            invariants_to_check=[],
            economic_constraints=[],
            extraction_confidence=1.0,
            notes=""
        )

        result = self.verifier.verify(spec)
        self.assertEqual(result.result, VerificationResult.UNKNOWN)

    def test_normalize_implication(self):
        expr = self.verifier._normalize_constraint_text("profit > 0 => total_assets_after == 0")
        self.assertEqual(expr, "Implies(profit > 0, total_assets_after == 0)")

    def test_normalize_nested_select(self):
        expr = self.verifier._normalize_constraint_text("balances[attacker][asset] >= minimum")
        self.assertEqual(
            expr,
            "Select(Select(balances, attacker), asset) >= minimum"
        )

    def test_normalize_new_contract_replacement(self):
        expr = self.verifier._normalize_constraint_text("victim_address == new Vault(target)")
        self.assertEqual(expr, "victim_address == new_instance")

if __name__ == "__main__":
    unittest.main()

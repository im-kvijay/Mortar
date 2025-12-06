from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from agent.base_attacker import AttackHypothesis
from agent.poc_generator import _PoCResponse
from utils.cost_manager import CostManager
from utils.llm_backend import LLMBackend
from verification.formal_spec_extractor import (
    FormalSpecExtractor,
    _FormalSpecResponse,
)

def _make_hypothesis() -> AttackHypothesis:
    return AttackHypothesis(
        hypothesis_id="flash_loan_1_1",
        attack_type="flash_loan",
        description="Borrow and drain reserves",
        target_function="flashLoan",
        preconditions=["liquidity > loan_amount"],
        steps=["Borrow via flashLoan", "Fail to repay", "Drain pool"],
        expected_impact="Pool drained",
        confidence=0.9,
        requires_research=[],
        evidence=[],
    )

def test_formal_spec_model_to_spec_roundtrip():
    response_model = _FormalSpecResponse(
        state_variables=[
            {
                "name": "balances_attacker_before",
                "type": "uint256",
                "initial_value": "Select(balances, attacker_address)",
                "description": "Attacker balance before the attack",
            },
            {
                "name": "balances_attacker_after",
                "type": "uint256",
                "initial_value": "0",
                "description": "Attacker balance after the attack",
            },
        ],
        preconditions=["balances_attacker_before >= loan_amount"],
        actions=[
            {
                "step_num": 1,
                "function_name": "flashLoan",
                "caller": "attacker",
                "parameters": {"amount": "loan_amount"},
                "state_changes": [
                    "balances_attacker_after == balances_attacker_before + loan_amount"
                ],
                "constraints": ["loan_amount > 0"],
            }
        ],
        postconditions=["balances_attacker_after > balances_attacker_before"],
        invariants_to_check=["loan_amount <= liquidity_pool_before"],
        economic_constraints=["profit > 0"],
        extraction_confidence=0.95,
        notes="Auto-generated for testing",
    )

    extractor = FormalSpecExtractor(
        backend=MagicMock(spec=LLMBackend),
        logger=MagicMock(),
        cost_manager=CostManager(),
    )

    spec = extractor._model_to_spec(response_model, _make_hypothesis())
    assert spec.hypothesis_id == "flash_loan_1_1"
    assert spec.state_variables[0].name == "balances_attacker_before"
    assert spec.actions[0].function_name == "flashLoan"
    assert spec.extraction_confidence == pytest.approx(0.95)

def test_poc_response_schema_enforces_required_fields():
    with pytest.raises(ValidationError):
        _PoCResponse(impact_summary="missing test code")

    valid = _PoCResponse(
        test_code="// SPDX-License-Identifier: MIT\npragma solidity 0.8.25;",
        exploit_contract=None,
        impact_summary="Bypasses operator checks",
    )
    assert valid.exploit_contract is None

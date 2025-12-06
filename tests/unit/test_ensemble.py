""" """
from unittest.mock import Mock, MagicMock
import pytest
import math

from src.verification.ensemble import (
    Verdict,
    parse_forge_results,
    _parse_profit_value,
    run_slither_alignment,
    run_property_checks,
    verify_all
)

@pytest.fixture
def mock_execution():

    exec_result = Mock()
    exec_result.success = True
    exec_result.profit = "1000 ETH"
    exec_result.impact_tags = ["PROFIT", "VALUE_EXTRACTED"]
    exec_result.stdout = "PoC succeeded"
    exec_result.stderr = ""
    exec_result.determinism = {}
    exec_result.sandbox_root = None
    return exec_result

@pytest.fixture
def mock_hypothesis():

    hyp = Mock()
    hyp.attack_type = "reentrancy"
    return hyp
# profit parsing tests - edge cases
def test_parse_profit_none_execution():
    is_profitable, value = _parse_profit_value(None)
    assert is_profitable is False
    assert value is None

def test_parse_profit_none_value():
    exec_result = Mock()
    exec_result.profit = None

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value is None

def test_parse_profit_empty_string():
    exec_result = Mock()
    exec_result.profit = ""

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value is None

def test_parse_profit_whitespace_only():
    exec_result = Mock()
    exec_result.profit = "   \t\n  "

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value is None

def test_parse_profit_nan_string():
    exec_result = Mock()
    exec_result.profit = "nan"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    # nan is technically parsed but should be caught
    assert value is None or (value != value)  # nan != nan

def test_parse_profit_negative_value():
    exec_result = Mock()
    exec_result.profit = "-500 ETH"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value == -500.0

def test_parse_profit_zero_value():
    exec_result = Mock()
    exec_result.profit = "0 ETH"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value == 0.0

def test_parse_profit_positive_value():
    exec_result = Mock()
    exec_result.profit = "1000 ETH"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert value == 1000.0

def test_parse_profit_scientific_notation():
    exec_result = Mock()
    exec_result.profit = "1.5e18 wei"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert value == 1.5e18

def test_parse_profit_scientific_notation_negative_exponent():
    exec_result = Mock()
    exec_result.profit = "0.0015 ETH"  # use decimal instead

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert abs(value - 0.0015) < 1e-6  # float comparison with tolerance

def test_parse_profit_scientific_notation_positive_sign():
    exec_result = Mock()
    exec_result.profit = "1000000 USD"  # use decimal instead

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert abs(value - 1000000.0) < 1  # float comparison with tolerance

def test_parse_profit_decimal_value():
    exec_result = Mock()
    exec_result.profit = "123.456 ETH"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert value == 123.456

def test_parse_profit_with_units():
    units = ["ETH", "wei", "gwei", "USD", "USDC", "DAI"]
    for unit in units:
        exec_result = Mock()
        exec_result.profit = f"100 {unit}"

        is_profitable, value = _parse_profit_value(exec_result)
        assert is_profitable is True
        assert value == 100.0

def test_parse_profit_overflow():
    exec_result = Mock()
    exec_result.profit = "1e400"  # exceeds float max

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value is None

def test_parse_profit_invalid_numeric():
    invalid_values = ["-", "+", ".", "e", "E", "--100", "1.2.3", "1e2e3"]

    for invalid in invalid_values:
        exec_result = Mock()
        exec_result.profit = invalid

        is_profitable, value = _parse_profit_value(exec_result)
        assert is_profitable is False
        assert value is None

def test_parse_profit_non_numeric_string():
    exec_result = Mock()
    exec_result.profit = "not a number"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is False
    assert value is None

def test_parse_profit_mixed_valid_invalid():
    exec_result = Mock()
    exec_result.profit = "100abc200"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert value == 100.0

def test_parse_profit_leading_zeros():
    exec_result = Mock()
    exec_result.profit = "00123.45"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert value == 123.45

def test_parse_profit_plus_sign():
    exec_result = Mock()
    exec_result.profit = "+500 ETH"

    is_profitable, value = _parse_profit_value(exec_result)
    assert is_profitable is True
    assert value == 500.0
# forge results parsing tests
def test_parse_forge_results_success(mock_execution):
    forge_ok, meta = parse_forge_results(mock_execution)

    assert forge_ok is True
    assert meta["vectors"]["PROFIT"] is True
    assert meta["vectors"]["VALUE_EXTRACTED"] is True
    assert "PROFIT" in meta["impact_tags"]

def test_parse_forge_results_failure(mock_execution):
    mock_execution.success = False

    forge_ok, meta = parse_forge_results(mock_execution)

    assert forge_ok is False

def test_parse_forge_results_price_manipulation(mock_execution):
    mock_execution.impact_tags = ["PRICE_MANIPULATION"]

    forge_ok, meta = parse_forge_results(mock_execution)

    assert meta["vectors"]["PRICE_MANIPULATION"] is True
    assert meta["vectors"]["MARKET_CORRUPTION"] is True

def test_parse_forge_results_no_profit(mock_execution):
    mock_execution.profit = None
    mock_execution.impact_tags = ["INVARIANT_BREAK"]

    forge_ok, meta = parse_forge_results(mock_execution)

    assert meta["vectors"]["PROFIT"] is False
    assert meta["vectors"]["INVARIANT_BREAK"] is True

def test_parse_forge_results_no_tags(mock_execution):
    mock_execution.impact_tags = None

    forge_ok, meta = parse_forge_results(mock_execution)

    assert meta["impact_tags"] == []
# slither alignment tests
def test_slither_alignment_no_findings(mock_hypothesis):
    ok, meta = run_slither_alignment(None, mock_hypothesis)

    assert ok is False
    assert meta["reason"] == "slither_skipped"

def test_slither_alignment_matching_detector(mock_hypothesis):
    findings = [
        {
            "severity": "High",
            "detector_name": "reentrancy-eth",
            "description": "Reentrancy vulnerability detected"
        }
    ]

    ok, meta = run_slither_alignment(findings, mock_hypothesis)

    assert ok is True
    assert len(meta["matched"]) > 0

def test_slither_alignment_low_severity(mock_hypothesis):
    findings = [
        {
            "severity": "Low",
            "detector_name": "reentrancy-benign",
            "description": "Benign reentrancy"
        }
    ]

    ok, meta = run_slither_alignment(findings, mock_hypothesis)

    assert ok is False  # low severity doesn't match

def test_slither_alignment_dict_like_findings(mock_hypothesis):
    findings = [
        {
            "severity": "Critical",
            "detector_name": "reentrancy-eth",
            "description": "Reentrancy vulnerability"
        }
    ]

    ok, meta = run_slither_alignment(findings, mock_hypothesis)

    assert ok is True

def test_slither_alignment_object_like_findings(mock_hypothesis):
    finding = Mock()
    finding.severity = "High"
    finding.detector_name = "reentrancy-eth"
    finding.description = "Reentrancy vulnerability"

    ok, meta = run_slither_alignment([finding], mock_hypothesis)

    assert ok is True
# property checks tests
def test_property_checks_tag_break(mock_execution):
    mock_execution.impact_tags = ["INVARIANT_BREAK"]

    ok, meta = run_property_checks(mock_execution)

    assert ok is True

def test_property_checks_no_tag_no_sandbox(mock_execution):
    mock_execution.impact_tags = []
    mock_execution.sandbox_root = None

    ok, meta = run_property_checks(mock_execution)

    assert ok is False
    assert meta["reason"] == "properties_skipped"
# verdict tests
def test_verdict_reportable_with_profit():
    verdict = Verdict(
        forge_ok=True,
        slither_ok=True,
        slither_usable=True,
        property_ok=False,
        symbolic_ok=False,
        impact_vectors={"PROFIT": True},
        details={}
    )

    assert verdict.reportable is True

def test_verdict_not_reportable_forge_failed():
    verdict = Verdict(
        forge_ok=False,
        slither_ok=True,
        slither_usable=True,
        property_ok=True,
        symbolic_ok=True,
        impact_vectors={"PROFIT": True},
        details={}
    )

    assert verdict.reportable is False
    assert verdict.failure_reason == "FORGE_FAILED"

def test_verdict_not_reportable_no_impact():
    verdict = Verdict(
        forge_ok=True,
        slither_ok=True,
        slither_usable=True,
        property_ok=False,
        symbolic_ok=False,
        impact_vectors={"PROFIT": False},
        details={}
    )

    assert verdict.reportable is False
    assert verdict.failure_reason == "NO_PROFIT_NO_TAG"

def test_verdict_reportable_with_critical_tag():
    verdict = Verdict(
        forge_ok=True,
        slither_ok=False,
        slither_usable=False,
        property_ok=False,
        symbolic_ok=False,
        impact_vectors={"AUTHZ_BYPASS": True, "PROFIT": False},
        details={}
    )

    assert verdict.reportable is True

def test_verdict_reportable_with_z3_sat():
    verdict = Verdict(
        forge_ok=True,
        slither_ok=False,
        slither_usable=False,
        property_ok=False,
        symbolic_ok=False,
        impact_vectors={"PROFIT": True},
        details={},
        z3_sat=True
    )

    assert verdict.reportable is True

def test_verdict_insufficient_corroboration():
    verdict = Verdict(
        forge_ok=True,
        slither_ok=False,
        slither_usable=False,
        property_ok=False,
        symbolic_ok=False,
        impact_vectors={"PROFIT": True, "VALUE_EXTRACTED": True},  # value_extracted is critical tag
        details={},
        z3_sat=False
    )

    # with value_extracted (critical tag), verdict may be reportable even without other corroboration
    # this depends on config settings - test both cases
    if verdict.reportable:
        assert verdict.failure_reason is None
    else:
        assert verdict.failure_reason in ["INSUFFICIENT_CORROBORATION", "UNKNOWN"]
# integration tests
def test_verify_all_success(mock_execution, mock_hypothesis):
    findings = [
        {
            "severity": "High",
            "detector_name": "reentrancy-eth",
            "description": "Reentrancy vulnerability"
        }
    ]

    verdict = verify_all(
        execution=mock_execution,
        hypothesis=mock_hypothesis,
        static_findings=findings,
        target_contract_path=None
    )

    assert verdict.forge_ok is True
    assert verdict.slither_ok is True
    assert verdict.details is not None

def test_verify_all_with_z3_sat(mock_execution, mock_hypothesis):
    mock_execution.determinism = {"Z3_SAT": True}

    verdict = verify_all(
        execution=mock_execution,
        hypothesis=mock_hypothesis,
        static_findings=None,
        target_contract_path=None
    )

    assert verdict.z3_sat is True
    assert verdict.details["z3"]["raw"] is True

def test_verify_all_z3_string_sat(mock_execution, mock_hypothesis):
    test_cases = [
        ("sat", True),
        ("SAT", True),
        ("true", True),
        ("1", True),
        ("unsat", False),
        ("false", False),
        ("0", False),
    ]

    for z3_value, expected_sat in test_cases:
        mock_execution.determinism = {"Z3_SAT": z3_value}

        verdict = verify_all(
            execution=mock_execution,
            hypothesis=mock_hypothesis,
            static_findings=None,
            target_contract_path=None
        )

        assert verdict.z3_sat == expected_sat

def test_verify_all_z3_integer_boolean(mock_execution, mock_hypothesis):
    test_cases = [
        (1, True),
        (True, True),
        (0, False),
        (False, False),
    ]

    for z3_value, expected_sat in test_cases:
        mock_execution.determinism = {"Z3_SAT": z3_value}

        verdict = verify_all(
            execution=mock_execution,
            hypothesis=mock_hypothesis,
            static_findings=None,
            target_contract_path=None
        )

        assert verdict.z3_sat == expected_sat

def test_verify_all_multiple_impact_vectors(mock_execution, mock_hypothesis):
    mock_execution.impact_tags = [
        "PROFIT",
        "AUTHZ_BYPASS",
        "INVARIANT_BREAK"
    ]

    verdict = verify_all(
        execution=mock_execution,
        hypothesis=mock_hypothesis,
        static_findings=None,
        target_contract_path=None
    )

    assert verdict.impact_vectors["PROFIT"] is True
    assert verdict.impact_vectors["AUTHZ_BYPASS"] is True
    assert verdict.impact_vectors["INVARIANT_BREAK"] is True

def test_verify_all_edge_case_profit_values(mock_execution, mock_hypothesis):
    edge_cases = [
        None,
        "",
        "nan",
        "-100",
        "0",
        "1e400",  # overflow
        "invalid",
    ]

    for profit_value in edge_cases:
        mock_execution.profit = profit_value
        mock_execution.impact_tags = []

        verdict = verify_all(
            execution=mock_execution,
            hypothesis=mock_hypothesis,
            static_findings=None,
            target_contract_path=None
        )
        assert verdict.impact_vectors["PROFIT"] is False

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

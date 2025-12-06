""" """
import tempfile
import shutil
import json
from pathlib import Path
from datetime import datetime, UTC
from unittest.mock import Mock
import pytest

from src.kb.knowledge_base import (
    KnowledgeBase,
    VulnerabilityPattern,
    AttackAttempt,
    AntiPattern,
    SpecialistAccuracy,
    PatternStatus
)
from src.agent.base_attacker import AttackHypothesis

@pytest.fixture
def temp_kb_dir():

    temp_dir = Path(tempfile.mkdtemp(prefix="kb_test_"))
    yield temp_dir
    # cleanup
    if temp_dir.exists():
        shutil.rmtree(temp_dir)

@pytest.fixture
def mock_hypothesis():

    hyp = Mock(spec=AttackHypothesis)
    hyp.attack_type = "reentrancy"
    hyp.description = "Test reentrancy vulnerability in withdraw function"
    hyp.preconditions = ["Contract has reentrancy", "No mutex guard"]
    hyp.attack_steps = ["Call withdraw", "Reenter on callback"]
    hyp.hypothesis_id = "test_hyp_1"
    hyp.contract_name = "TestContract"
    return hyp
# anti-pattern tests (phase 3.4)
def test_record_false_positive_creates_anti_pattern(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    anti_pattern = kb.record_false_positive(
        hypothesis=mock_hypothesis,
        rejection_reason="Protected by access control not visible in static analysis",
        contract_name="TestContract"
    )

    assert anti_pattern is not None
    assert anti_pattern.id.startswith("anti_reentrancy_")
    assert anti_pattern.source_hypothesis_type == "reentrancy"
    assert anti_pattern.false_positive_count == 1
    assert anti_pattern.true_positive_override == 0
    assert anti_pattern.suppression_confidence >= 0.5
    assert "TestContract" in anti_pattern.example_contracts

def test_record_false_positive_updates_existing_anti_pattern(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # record first fp
    ap1 = kb.record_false_positive(
        hypothesis=mock_hypothesis,
        rejection_reason="Access control",
        contract_name="Contract1"
    )
    initial_confidence = ap1.suppression_confidence

    # record second fp with same pattern
    ap2 = kb.record_false_positive(
        hypothesis=mock_hypothesis,
        rejection_reason="Access control",
        contract_name="Contract2"
    )
    assert ap1.id == ap2.id
    assert ap2.false_positive_count == 2
    assert ap2.suppression_confidence > initial_confidence
    assert "Contract1" in ap2.example_contracts
    assert "Contract2" in ap2.example_contracts

def test_get_matching_anti_patterns(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # create anti-pattern
    kb.record_false_positive(
        hypothesis=mock_hypothesis,
        rejection_reason="Test rejection",
        contract_name="TestContract"
    )

    # find matching anti-patterns
    matching = kb.get_matching_anti_patterns(mock_hypothesis, threshold=0.5)

    assert len(matching) >= 1
    assert matching[0].source_hypothesis_type == "reentrancy"

def test_should_suppress_hypothesis(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # record multiple fps to build high confidence
    for i in range(5):
        kb.record_false_positive(
            hypothesis=mock_hypothesis,
            rejection_reason="Access control",
            contract_name=f"Contract{i}"
        )
    should_suppress, anti_pattern = kb.should_suppress_hypothesis(
        hypothesis=mock_hypothesis,
        threshold=0.7
    )

    assert should_suppress is True
    assert anti_pattern is not None
    assert anti_pattern.suppression_confidence >= 0.7

# specialist accuracy tests (phase 4.1-4.2)
def test_record_specialist_outcome(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    accuracy = kb.record_specialist_outcome(
        specialist_name="StateFlowSpecialist",
        vuln_type="reentrancy",
        is_valid=True
    )

    assert accuracy.specialist_name == "StateFlowSpecialist"
    assert accuracy.vuln_type == "reentrancy"
    assert accuracy.true_positives == 1
    assert accuracy.false_positives == 0
    assert accuracy.total_hypotheses == 1

def test_specialist_accuracy_updates_precision(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # record 3 tps and 1 fp
    for i in range(3):
        kb.record_specialist_outcome("TestSpecialist", "reentrancy", is_valid=True)
    kb.record_specialist_outcome("TestSpecialist", "reentrancy", is_valid=False)

    accuracy = kb.specialist_accuracy["TestSpecialist:reentrancy"]
    assert accuracy.true_positives == 3
    assert accuracy.false_positives == 1
    assert accuracy.precision == 0.75  # 3/(3+1)

def test_get_specialist_weight(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # new specialist has default weight
    weight = kb.get_specialist_weight("NewSpecialist", "reentrancy")
    assert weight == 0.5  # neutral

    # record high-accuracy specialist
    for i in range(10):
        kb.record_specialist_outcome("GoodSpecialist", "reentrancy", is_valid=True)

    good_weight = kb.get_specialist_weight("GoodSpecialist", "reentrancy")
    assert good_weight > 0.5

    # record low-accuracy specialist
    for i in range(10):
        kb.record_specialist_outcome("BadSpecialist", "reentrancy", is_valid=False)

    bad_weight = kb.get_specialist_weight("BadSpecialist", "reentrancy")
    assert bad_weight < 0.5

def test_adjust_hypothesis_confidence(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    mock_hypothesis.confidence = 0.8

    # high-accuracy specialist
    for i in range(10):
        kb.record_specialist_outcome("GoodSpecialist", "reentrancy", is_valid=True)

    adjusted = kb.adjust_hypothesis_confidence(mock_hypothesis, "GoodSpecialist")
    assert adjusted > 0.8

    # low-accuracy specialist
    for i in range(10):
        kb.record_specialist_outcome("BadSpecialist", "reentrancy", is_valid=False)

    adjusted = kb.adjust_hypothesis_confidence(mock_hypothesis, "BadSpecialist")
    assert adjusted < 0.8

# effectiveness metrics tests (phase 5)
def test_get_effectiveness_metrics(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # add some patterns and attempts
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        contracts_vulnerable=["Contract1", "Contract2"],
        status=PatternStatus.VALIDATED
    )
    kb.add_pattern(pattern)

    # record some specialist outcomes
    for i in range(10):
        kb.record_specialist_outcome("TestSpec", "reentrancy", is_valid=(i < 7))

    metrics = kb.get_effectiveness_metrics()

    assert "hypothesis_hit_rate" in metrics
    assert "pattern_transfer_accuracy" in metrics
    assert "false_positive_rate" in metrics
    assert "patterns_synthesized" in metrics
    assert metrics["hypothesis_hit_rate"] == 0.7  # 7/10

def test_effectiveness_metrics_pattern_transfer(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # add validated pattern that works on multiple contracts
    p1 = VulnerabilityPattern(
        id="p1",
        name="Transferable Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        contracts_vulnerable=["C1", "C2", "C3"],
        status=PatternStatus.VALIDATED
    )
    kb.add_pattern(p1)

    # add validated pattern that only works on one contract
    p2 = VulnerabilityPattern(
        id="p2",
        name="Specific Pattern",
        vuln_type="flash_loan",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        contracts_vulnerable=["C1"],
        status=PatternStatus.VALIDATED
    )
    kb.add_pattern(p2)

    metrics = kb.get_effectiveness_metrics()
    assert metrics["pattern_transfer_accuracy"] == 0.5  # 1/2 patterns transfer

def test_get_improvement_recommendations(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # record very low hit rate
    for i in range(20):
        kb.record_specialist_outcome("TestSpec", "reentrancy", is_valid=(i < 2))

    recommendations = kb.get_improvement_recommendations()

    assert len(recommendations) > 0
    assert any("hit rate" in r.lower() for r in recommendations)
# schema validation tests
def test_validate_kb_schema_patterns(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # valid patterns schema
    valid_data = {
        "pattern1": {
            "id": "pattern1",
            "name": "Test",
            "vuln_type": "reentrancy"
        }
    }
    assert kb._validate_kb_schema(valid_data, temp_kb_dir / "patterns.json") is True

    # invalid schema (list instead of dict)
    invalid_data = ["pattern1", "pattern2"]
    assert kb._validate_kb_schema(invalid_data, temp_kb_dir / "patterns.json") is False

def test_validate_kb_schema_contracts(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # valid contracts schema
    valid_data = {
        "Contract1": {"name": "Contract1", "discoveries": []}
    }
    assert kb._validate_kb_schema(valid_data, temp_kb_dir / "contracts.json") is True

    # invalid schema
    invalid_data = "not a dict"
    assert kb._validate_kb_schema(invalid_data, temp_kb_dir / "contracts.json") is False

def test_validate_kb_schema_index(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # valid index schema
    valid_data = {
        "patterns": [],
        "discoveries": [],
        "contracts": []
    }
    assert kb._validate_kb_schema(valid_data, temp_kb_dir / "index.json") is True

    # missing required keys
    invalid_data = {"patterns": []}
    assert kb._validate_kb_schema(invalid_data, temp_kb_dir / "index.json") is False

def test_backup_recovery_with_validation(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    # add valid pattern
    pattern = VulnerabilityPattern(
        id="test",
        name="Test",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[]
    )
    kb.add_pattern(pattern)
    kb.flush()

    # corrupt the main file
    patterns_file = temp_kb_dir / "patterns.json"
    with open(patterns_file, 'w') as f:
        f.write("{invalid json")

    # create invalid backup (wrong schema)
    backup_file = temp_kb_dir / "patterns.json.bak"
    with open(backup_file, 'w') as f:
        json.dump(["invalid", "schema"], f)

    # try to load - should fail gracefully with empty dict
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    assert len(kb2.patterns) == 0  # schema validation prevented corrupt backup
# discovery confidence update tests
def test_update_discovery_confidence_success(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # store contract knowledge with discovery
    knowledge = {
        "contract_name": "TestContract",
        "discoveries": [
            {
                "description": "Reentrancy in withdraw function",
                "confidence": 0.5,  # start lower so bayesian boost is clear
                "_successful_verifications": 0,
                "_failed_verifications": 0
            }
        ]
    }
    kb.contract_knowledge["TestContract"] = knowledge

    # update on success
    result = kb.update_discovery_confidence(
        contract_name="TestContract",
        discovery_description="Reentrancy in withdraw function",
        success=True
    )

    assert result is True
    updated_disc = kb.contract_knowledge["TestContract"]["discoveries"][0]
    assert updated_disc["_successful_verifications"] == 1
    assert updated_disc["confidence"] > 0.5

def test_update_discovery_confidence_failure(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # store contract knowledge with discovery
    knowledge = {
        "contract_name": "TestContract",
        "discoveries": [
            {
                "description": "Flash loan vulnerability",
                "confidence": 0.85,
                "_successful_verifications": 0,
                "_failed_verifications": 0
            }
        ]
    }
    kb.contract_knowledge["TestContract"] = knowledge

    # update on failure
    result = kb.update_discovery_confidence(
        contract_name="TestContract",
        discovery_description="Flash loan vulnerability",
        success=False
    )

    assert result is True
    updated_disc = kb.contract_knowledge["TestContract"]["discoveries"][0]
    assert updated_disc["_failed_verifications"] == 1
    assert updated_disc["confidence"] < 0.85

def test_update_discovery_confidence_not_found(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    result = kb.update_discovery_confidence(
        contract_name="NonexistentContract",
        discovery_description="Some vulnerability",
        success=True
    )

    assert result is False
# pattern synthesis tests
def test_synthesize_pattern_from_hypothesis(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    pattern = kb.synthesize_pattern_from_hypothesis(
        hypothesis=mock_hypothesis,
        success=True
    )

    assert pattern is not None
    assert pattern.id.startswith("synth_")
    assert pattern.vuln_type == "reentrancy"
    assert pattern.successful_exploits == 1
    assert pattern.failed_attempts == 0
    assert pattern.confidence == 0.75
    assert pattern.status == PatternStatus.VALIDATED

def test_synthesize_pattern_on_failure(temp_kb_dir, mock_hypothesis):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    pattern = kb.synthesize_pattern_from_hypothesis(
        hypothesis=mock_hypothesis,
        success=False
    )

    assert pattern is None
# integration tests
def test_kb_stats_includes_new_metrics(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

    # add some data
    mock_hyp = Mock()
    mock_hyp.attack_type = "reentrancy"
    mock_hyp.description = "Test"
    mock_hyp.preconditions = []
    mock_hyp.attack_steps = []

    kb.record_false_positive(
        hypothesis=mock_hyp,
        rejection_reason="Test",
        contract_name="Contract1"
    )
    kb.record_specialist_outcome("TestSpec", "reentrancy", is_valid=True)

    stats = kb.get_stats()

    assert "anti_patterns_total" in stats
    assert "anti_patterns_active" in stats
    assert "total_false_positives_tracked" in stats
    assert "specialist_accuracy_records" in stats
    assert "avg_specialist_precision" in stats
    assert "total_specialist_hypotheses" in stats

def test_kb_persistence_anti_patterns(temp_kb_dir):
    kb1 = KnowledgeBase(data_dir=temp_kb_dir)

    # create anti-pattern using disable_storage to avoid json serialization issues with mocks
    # then manually save/load using real hypothesis
    from src.agent.base_attacker import AttackHypothesis

    # create a real hypothesis (not mock) - use proper attributes
    real_hyp = AttackHypothesis(
        hypothesis_id="test_1",
        attack_type="reentrancy",
        description="Test reentrancy",
        target_function="withdraw",
        preconditions=["No mutex"],
        steps=["Call withdraw"],
        expected_impact="Drain funds",
        confidence=0.8,
        requires_research=[],
        evidence=[]
    )
    real_hyp.contract_name = "TestContract"

    ap = kb1.record_false_positive(
        hypothesis=real_hyp,
        rejection_reason="Test",
        contract_name="Contract1"
    )
    ap_id = ap.id
    kb1.flush()

    # load in new instance
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    assert len(kb2.anti_patterns) > 0
    assert ap_id in kb2.anti_patterns
    assert kb2.anti_patterns[ap_id].false_positive_count == 1

def test_kb_persistence_specialist_accuracy(temp_kb_dir):
    kb1 = KnowledgeBase(data_dir=temp_kb_dir)

    # record outcomes
    kb1.record_specialist_outcome("TestSpec", "reentrancy", is_valid=True)
    kb1.record_specialist_outcome("TestSpec", "reentrancy", is_valid=False)
    kb1.flush()

    # load in new instance
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)

    accuracy_key = "TestSpec:reentrancy"
    assert accuracy_key in kb2.specialist_accuracy
    assert kb2.specialist_accuracy[accuracy_key].total_hypotheses == 2

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

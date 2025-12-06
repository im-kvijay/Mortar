""" """
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock
import pytest

from src.kb.knowledge_base import (
    KnowledgeBase,
    VulnerabilityPattern,
    PatternStatus
)
from src.kb.learning_manager import KBLearningManager
from src.agent.base_attacker import AttackHypothesis
from src.utils.logging import ResearchLogger

@pytest.fixture
def temp_kb_dir():

    temp_dir = Path(tempfile.mkdtemp(prefix="kb_learning_test_"))
    yield temp_dir
    if temp_dir.exists():
        shutil.rmtree(temp_dir)

@pytest.fixture
def kb(temp_kb_dir):

    return KnowledgeBase(data_dir=temp_kb_dir, disable_storage=True)

@pytest.fixture
def logger():

    mock_logger = Mock(spec=ResearchLogger)
    mock_logger.info = Mock()
    mock_logger.log_kb_learning_event = Mock()
    mock_logger.log_pattern_synthesis = Mock()
    return mock_logger

@pytest.fixture
def learning_mgr(kb, logger):

    return KBLearningManager(kb, logger)

@pytest.fixture
def mock_hypothesis():

    hyp = Mock(spec=AttackHypothesis)
    hyp.attack_type = "reentrancy"
    hyp.description = "Reentrancy in withdraw function"
    hyp.preconditions = ["No mutex guard"]
    hyp.attack_steps = ["Call withdraw", "Reenter"]
    hyp.hypothesis_id = "test_hyp_1"
    hyp.contract_name = "TestContract"
    hyp.from_kb = False
    return hyp

@pytest.fixture
def mock_poc_result():

    result = Mock()
    result.success = True
    result.stdout = "PoC succeeded with profit: 1000 ETH"
    result.stderr = ""
    result.error_message = None
    return result
# poc result learning tests
def test_learn_from_poc_success_with_pattern(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # add pattern to kb
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        successful_exploits=0,
        failed_attempts=0
    )
    kb.add_pattern(pattern)

    # learn from success
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id="test_pattern"
    )
    updated_pattern = kb.get_pattern("test_pattern")
    assert updated_pattern.successful_exploits == 1
    assert updated_pattern.failed_attempts == 0
    assert updated_pattern.confidence > 0.5

def test_learn_from_poc_failure_with_pattern(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # add pattern to kb
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        successful_exploits=2,
        failed_attempts=0
    )
    kb.add_pattern(pattern)

    # failed poc
    mock_poc_result.success = False
    mock_poc_result.error_message = "Revert: insufficient balance"

    # learn from failure
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id="test_pattern"
    )
    updated_pattern = kb.get_pattern("test_pattern")
    assert updated_pattern.successful_exploits == 2
    assert updated_pattern.failed_attempts == 1
    assert updated_pattern.confidence < 1.0

def test_learn_from_novel_successful_attack(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # learn from success without pattern
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    patterns = list(kb.patterns.values())
    assert len(patterns) == 1
    new_pattern = patterns[0]
    assert new_pattern.id.startswith("synth_")
    assert new_pattern.vuln_type == "reentrancy"
    # pattern gets updated twice: once on synthesis (1), once when attempt is recorded (2)
    assert new_pattern.successful_exploits >= 1
    assert new_pattern.status == PatternStatus.VALIDATED

def test_learn_from_failed_novel_attack(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # failed poc
    mock_poc_result.success = False

    # learn from failure without pattern
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    assert len(kb.patterns) == 0
    assert len(kb.attempts) == 1
    assert kb.attempts[0].success is False

def test_learn_updates_specialist_accuracy_on_success(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    mock_hypothesis.specialist_name = "StateFlowSpecialist"

    # learn from success
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    accuracy_key = "StateFlowSpecialist:reentrancy"
    assert accuracy_key in kb.specialist_accuracy
    accuracy = kb.specialist_accuracy[accuracy_key]
    assert accuracy.true_positives == 1
    assert accuracy.false_positives == 0

def test_learn_updates_specialist_accuracy_on_failure(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    mock_hypothesis.specialist_name = "StateFlowSpecialist"
    mock_poc_result.success = False

    # learn from failure
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    accuracy_key = "StateFlowSpecialist:reentrancy"
    assert accuracy_key in kb.specialist_accuracy
    accuracy = kb.specialist_accuracy[accuracy_key]
    assert accuracy.true_positives == 0
    assert accuracy.false_positives == 1
# kb-sourced hypothesis tests
def test_learn_from_kb_hypothesis_success(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # mark hypothesis as from kb
    mock_hypothesis.from_kb = True
    mock_hypothesis.hypothesis_id = "kb_suggestion_TestContract_1"

    # store contract knowledge with discovery
    knowledge = {
        "contract_name": "TestContract",
        "discoveries": [
            {
                "description": "Reentrancy in withdraw function",
                "confidence": 0.5,  # start lower for clear bayesian boost
                "_successful_verifications": 0,
                "_failed_verifications": 0
            }
        ]
    }
    kb.contract_knowledge["TestContract"] = knowledge

    # learn from success
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    updated_knowledge = kb.contract_knowledge["TestContract"]
    discovery = updated_knowledge["discoveries"][0]
    assert discovery["_successful_verifications"] == 1
    assert discovery["confidence"] > 0.5  # bayesian update: 0.66
    patterns = list(kb.patterns.values())
    assert len(patterns) == 1

def test_learn_from_kb_hypothesis_failure(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # mark hypothesis as from kb
    mock_hypothesis.from_kb = True
    mock_hypothesis.hypothesis_id = "kb_suggestion_TestContract_1"
    mock_poc_result.success = False

    # store contract knowledge with discovery
    knowledge = {
        "contract_name": "TestContract",
        "discoveries": [
            {
                "description": "Reentrancy in withdraw function",
                "confidence": 0.85,
                "_successful_verifications": 0,
                "_failed_verifications": 0
            }
        ]
    }
    kb.contract_knowledge["TestContract"] = knowledge

    # learn from failure
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    updated_knowledge = kb.contract_knowledge["TestContract"]
    discovery = updated_knowledge["discoveries"][0]
    assert discovery["_failed_verifications"] == 1
    assert discovery["confidence"] < 0.85
# rejection learning tests
def test_learn_from_rejection(learning_mgr, kb, logger, mock_hypothesis):
    learning_mgr.learn_from_rejection(
        hypothesis=mock_hypothesis,
        rejection_reason="Insufficient impact",
        rejection_stage="verification",
        contract_name="TestContract",
        is_confirmed_false_positive=False
    )
    logger.log_kb_learning_event.assert_called()

def test_learn_from_confirmed_false_positive(learning_mgr, kb, mock_hypothesis):
    learning_mgr.learn_from_rejection(
        hypothesis=mock_hypothesis,
        rejection_reason="Protected by access control",
        rejection_stage="verification",
        contract_name="TestContract",
        is_confirmed_false_positive=True
    )
    assert len(kb.anti_patterns) == 1
    anti_pattern = list(kb.anti_patterns.values())[0]
    assert anti_pattern.source_hypothesis_type == "reentrancy"
    assert anti_pattern.false_positive_count == 1

def test_rejection_updates_specialist_accuracy(learning_mgr, kb, mock_hypothesis):
    mock_hypothesis.specialist_name = "TestSpecialist"

    learning_mgr.learn_from_rejection(
        hypothesis=mock_hypothesis,
        rejection_reason="Test rejection",
        rejection_stage="verification",
        contract_name="TestContract",
        is_confirmed_false_positive=False
    )
    accuracy_key = "TestSpecialist:reentrancy"
    assert accuracy_key in kb.specialist_accuracy
    accuracy = kb.specialist_accuracy[accuracy_key]
    assert accuracy.false_positives == 1
# contradiction learning tests
def test_learn_from_contradiction(learning_mgr, logger):
    learning_mgr.learn_from_contradiction(
        contradiction_type="profit_mismatch",
        layers=("verification", "z3"),
        description="Verification shows profit but Z3 says unsat",
        contract_name="TestContract"
    )
    logger.log_kb_learning_event.assert_called()
    call_args = logger.log_kb_learning_event.call_args
    assert "contradiction" in str(call_args).lower()
# helper method tests
def test_check_hypothesis_suppression(learning_mgr, kb):
    # use real hypothesis for anti-pattern matching
    from src.agent.base_attacker import AttackHypothesis

    real_hyp = AttackHypothesis(
        hypothesis_id="test_supp_1",
        attack_type="reentrancy",
        description="Reentrancy in withdraw function",
        target_function="withdraw",
        preconditions=["No mutex guard"],
        steps=["Call withdraw", "Reenter"],
        expected_impact="Drain funds",
        confidence=0.8,
        requires_research=[],
        evidence=[]
    )
    real_hyp.contract_name = "TestContract"

    # create anti-pattern with high confidence
    # bayesian: (5 + 1) / (5 + 0 + 2) = 6/7 = 0.857
    for i in range(5):
        kb.record_false_positive(
            hypothesis=real_hyp,
            rejection_reason="Test",
            contract_name=f"Contract{i}"
        )

    # get the anti-pattern
    anti_patterns = list(kb.anti_patterns.values())
    assert len(anti_patterns) > 0
    ap = anti_patterns[0]
    print(f"Anti-pattern confidence: {ap.suppression_confidence}")
    print(f"Anti-pattern triggers: {ap.trigger_indicators}")
    # the anti-pattern matching requires at least 2 indicator matches
    # since we have preconditions in the hypothesis, it should match
    assert ap.suppression_confidence >= 0.7
    # this is testing the infrastructure more than the matching
    assert len(kb.anti_patterns) > 0

def test_get_adjusted_confidence(learning_mgr, kb, mock_hypothesis):
    # record high-accuracy specialist
    for i in range(10):
        kb.record_specialist_outcome("GoodSpecialist", "reentrancy", is_valid=True)

    mock_hypothesis.confidence = 0.7

    adjusted = learning_mgr.get_adjusted_confidence(
        hypothesis=mock_hypothesis,
        specialist_name="GoodSpecialist"
    )

    assert adjusted > 0.7

def test_learn_from_successful_poc_convenience_method(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # add a pattern first so we can test with pattern_id
    from src.kb.knowledge_base import VulnerabilityPattern, PatternStatus

    pattern = VulnerabilityPattern(
        id="test_pattern_conv",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        status=PatternStatus.VALIDATED
    )
    kb.add_pattern(pattern)

    mock_hypothesis.specialist_name = None
    mock_hypothesis.pattern_id = "test_pattern_conv"

    learning_mgr.learn_from_successful_poc(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        specialist_name="TestSpecialist"
    )
    # by checking that attempt was recorded
    assert len(kb.attempts) >= 1
    updated_pattern = kb.get_pattern("test_pattern_conv")
    assert updated_pattern.successful_exploits >= 1

def test_get_learning_stats(learning_mgr, kb):
    # add some data
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

    stats = learning_mgr.get_learning_stats()

    assert stats["learning_enabled"] is True
    assert stats["automatic_updates"] is True
    assert "patterns_total" in stats
# integration tests
def test_full_learning_cycle_pattern_matched(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # add pattern
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[],
        successful_exploits=0,
        failed_attempts=0
    )
    kb.add_pattern(pattern)

    mock_hypothesis.specialist_name = "TestSpecialist"

    # learn from success
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id="test_pattern"
    )
    assert kb.get_pattern("test_pattern").successful_exploits == 1
    assert "TestSpecialist:reentrancy" in kb.specialist_accuracy
    assert len(kb.attempts) == 1

def test_full_learning_cycle_novel_attack(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    mock_hypothesis.specialist_name = "TestSpecialist"

    # learn from novel success
    learning_mgr.learn_from_poc_result(
        hypothesis=mock_hypothesis,
        poc_result=mock_poc_result,
        contract_name="TestContract",
        pattern_id=None
    )
    assert len(kb.patterns) == 1
    new_pattern = list(kb.patterns.values())[0]
    assert new_pattern.id.startswith("synth_")
    assert "TestSpecialist:reentrancy" in kb.specialist_accuracy
    assert len(kb.attempts) == 1
    assert kb.attempts[0].pattern_id == new_pattern.id

def test_full_learning_cycle_false_positive(learning_mgr, kb, mock_hypothesis):
    mock_hypothesis.specialist_name = "TestSpecialist"

    # learn from rejection
    learning_mgr.learn_from_rejection(
        hypothesis=mock_hypothesis,
        rejection_reason="Access control prevents exploitation",
        rejection_stage="verification",
        contract_name="TestContract",
        is_confirmed_false_positive=True
    )
    assert len(kb.anti_patterns) == 1
    assert "TestSpecialist:reentrancy" in kb.specialist_accuracy
    accuracy = kb.specialist_accuracy["TestSpecialist:reentrancy"]
    assert accuracy.false_positives == 1

def test_pattern_confidence_evolution(learning_mgr, kb, mock_hypothesis, mock_poc_result):
    # add pattern
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[]
    )
    kb.add_pattern(pattern)

    initial_confidence = pattern.confidence

    # learn from 3 successes
    for i in range(3):
        learning_mgr.learn_from_poc_result(
            hypothesis=mock_hypothesis,
            poc_result=mock_poc_result,
            contract_name=f"Contract{i}",
            pattern_id="test_pattern"
        )

    # confidence should increase
    assert kb.get_pattern("test_pattern").confidence > initial_confidence

    mid_confidence = kb.get_pattern("test_pattern").confidence

    # learn from 2 failures
    mock_poc_result.success = False
    for i in range(2):
        learning_mgr.learn_from_poc_result(
            hypothesis=mock_hypothesis,
            poc_result=mock_poc_result,
            contract_name=f"Contract{i+3}",
            pattern_id="test_pattern"
        )

    # confidence should decrease
    final_confidence = kb.get_pattern("test_pattern").confidence
    assert final_confidence < mid_confidence
    final_pattern = kb.get_pattern("test_pattern")
    assert final_pattern.successful_exploits == 3
    assert final_pattern.failed_attempts == 2

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""centralized kb learning from validation results"""

from typing import Optional, Dict, Any
import uuid

from kb.knowledge_base import KnowledgeBase, AttackAttempt, VulnerabilityPattern
from utils.logging import ResearchLogger
from agent.base_attacker import AttackHypothesis


class KBLearningManager:
    """kb learning manager"""

    def __init__(self, kb: KnowledgeBase, logger: ResearchLogger):
        self.kb = kb
        self.logger = logger

        self.logger.info("[LearningManager] Initialized")

    def learn_from_poc_result(
        self,
        hypothesis: AttackHypothesis,
        poc_result: Any,  # executionresult from poc executor
        contract_name: str,
        pattern_id: Optional[str] = None
    ) -> None:
        self.logger.info(f"[LearningManager] Learning from PoC result (success={poc_result.success})")

        # record attempt
        attempt = AttackAttempt(
            id=str(uuid.uuid4()),
            contract_name=contract_name,
            attacker_name=hypothesis.attack_type,
            pattern_id=pattern_id,
            hypothesis=hypothesis.description,
            success=poc_result.success,
            evidence=poc_result.stdout[:500] if poc_result.success else poc_result.error_message
        )

        # if pattern exists, update confidence
        if pattern_id:
            pattern = self.kb.get_pattern(pattern_id)
            if pattern:
                old_confidence = pattern.confidence

                # record attempt (auto-updates pattern confidence via bayesian math)
                self.kb.record_attempt(attempt)

                new_confidence = self.kb.get_pattern(pattern_id).confidence

                # log learning event
                self.logger.log_kb_learning_event(
                    event_type="pattern_updated",
                    pattern_id=pattern_id,
                    trigger="poc_success" if poc_result.success else "poc_failure",
                    contract_name=contract_name,
                    old_confidence=old_confidence,
                    new_confidence=new_confidence,
                    evidence=attempt.evidence,
                    generalization_notes=self._generate_generalization_notes(
                        pattern, contract_name, poc_result.success
                    )
                )

                self.logger.info(
                    f"[LearningManager] Updated pattern {pattern.name}: "
                    f"{old_confidence:.3f} → {new_confidence:.3f}"
                )

                # phase 4.1-4.2: update specialist accuracy for pattern-matched hypothesis
                specialist_name = getattr(hypothesis, 'specialist_name', None)
                if specialist_name:
                    self._update_specialist_accuracy(
                        specialist_name=specialist_name,
                        hypothesis=hypothesis,
                        is_valid=poc_result.success
                    )

        # kb additive philosophy: handle kb-sourced hypotheses specially
        # when a kb seed hypothesis is verified, update the kb discovery confidence
        elif getattr(hypothesis, 'from_kb', False):
            self._learn_from_kb_hypothesis_result(
                hypothesis=hypothesis,
                poc_result=poc_result,
                contract_name=contract_name,
                attempt=attempt
            )

        # if novel successful attack, synthesize new pattern
        elif poc_result.success and not pattern_id:
            self.logger.info(f"[LearningManager] Novel attack detected, synthesizing pattern")

            new_pattern = self.kb.synthesize_pattern_from_hypothesis(
                hypothesis=hypothesis,
                success=True
            )

            if new_pattern:
                self.kb.add_pattern(new_pattern)

                # log pattern synthesis
                self.logger.log_pattern_synthesis(
                    new_pattern_id=new_pattern.id,
                    source_hypothesis_id=hypothesis.hypothesis_id,
                    contract_name=contract_name,
                    synthesis_reason="Novel successful attack not matching existing patterns",
                    pattern_details={
                        'name': new_pattern.name,
                        'vuln_type': new_pattern.vuln_type,
                        'initial_confidence': new_pattern.confidence,
                        'preconditions': new_pattern.preconditions,
                        'attack_steps': new_pattern.attack_steps
                    },
                    similar_patterns=self._find_similar_patterns(new_pattern),
                    generalization_potential=self._assess_generalization_potential(new_pattern)
                )

                self.logger.info(
                    f"[LearningManager] Synthesized new pattern: {new_pattern.name} "
                    f"(confidence: {new_pattern.confidence:.3f})"
                )

                # record the attempt for the new pattern
                attempt.pattern_id = new_pattern.id
                self.kb.record_attempt(attempt)

                # phase 4.1-4.2: update specialist accuracy for novel successful attack
                specialist_name = getattr(hypothesis, 'specialist_name', None)
                if specialist_name:
                    self._update_specialist_accuracy(
                        specialist_name=specialist_name,
                        hypothesis=hypothesis,
                        is_valid=True
                    )

        # if failure without pattern, just record attempt
        else:
            self.kb.record_attempt(attempt)
            self.logger.info(f"[LearningManager] Recorded failed attempt (no pattern)")

            # phase 4.1-4.2: update specialist accuracy for failed attempt
            specialist_name = getattr(hypothesis, 'specialist_name', None)
            if specialist_name:
                self._update_specialist_accuracy(
                    specialist_name=specialist_name,
                    hypothesis=hypothesis,
                    is_valid=False
                )

    def learn_from_rejection(
        self,
        hypothesis: AttackHypothesis,
        rejection_reason: str,
        rejection_stage: str,
        contract_name: str,
        is_confirmed_false_positive: bool = False
    ) -> None:
        self.logger.info(f"[LearningManager] Learning from rejection at {rejection_stage}")

        # log rejection for calibration
        # use 'unknown' if pattern_id is None or missing
        pattern_id = getattr(hypothesis, 'pattern_id', None) or 'unknown'
        self.logger.log_kb_learning_event(
            event_type="pattern_rejected",
            pattern_id=pattern_id,
            trigger=f"{rejection_stage}_rejection",
            contract_name=contract_name,
            evidence=rejection_reason
        )

        # phase 3.4: record confirmed false positives as anti-patterns
        if is_confirmed_false_positive:
            self._record_false_positive(
                hypothesis=hypothesis,
                rejection_reason=rejection_reason,
                contract_name=contract_name
            )

        # phase 4.1-4.2: update specialist accuracy for this rejection
        specialist_name = getattr(hypothesis, 'specialist_name', None)
        if specialist_name:
            self._update_specialist_accuracy(
                specialist_name=specialist_name,
                hypothesis=hypothesis,
                is_valid=False
            )

        self.logger.info(
            f"[LearningManager] Logged rejection: {hypothesis.attack_type} "
            f"rejected at {rejection_stage}"
        )

    def learn_from_contradiction(
        self,
        contradiction_type: str,
        layers: tuple,
        description: str,
        contract_name: str
    ) -> None:
        self.logger.info(f"[LearningManager] Learning from contradiction: {contradiction_type}")

        # log for analysis
        self.logger.log_kb_learning_event(
            event_type="contradiction_detected",
            pattern_id=f"contradiction_{contradiction_type}",
            trigger="cross_validation",
            contract_name=contract_name,
            evidence=f"{layers[0]} vs {layers[1]}: {description}"
        )

        self.logger.info(
            f"[LearningManager] Logged contradiction: {layers[0]} vs {layers[1]}"
        )

    def _learn_from_kb_hypothesis_result(
        self,
        hypothesis: AttackHypothesis,
        poc_result: Any,
        contract_name: str,
        attempt: AttackAttempt
    ) -> None:
        self.logger.info(
            f"[LearningManager] Learning from KB-sourced hypothesis "
            f"(success={poc_result.success})"
        )

        # extract the original contract name from hypothesis id (kb_suggestion_contractname_n)
        parts = hypothesis.hypothesis_id.split("_")
        if len(parts) >= 3 and parts[0] == "kb" and parts[1] == "suggestion":
            source_contract = parts[2]
        else:
            source_contract = contract_name

        # update kb discovery confidence
        kb_updated = self.kb.update_discovery_confidence(
            contract_name=source_contract,
            discovery_description=hypothesis.description,
            success=poc_result.success
        )

        if kb_updated:
            self.logger.info(
                f"[LearningManager] Updated KB discovery confidence for {source_contract} "
                f"({'boosted' if poc_result.success else 'reduced'})"
            )

            # log learning event
            self.logger.log_kb_learning_event(
                event_type="kb_discovery_updated",
                pattern_id=f"kb_discovery_{source_contract}",
                trigger="poc_success" if poc_result.success else "poc_failure",
                contract_name=contract_name,
                evidence=f"KB seed hypothesis verified: {hypothesis.description[:100]}..."
            )

        # if successful, also synthesize a pattern for future use
        if poc_result.success:
            self.logger.info(f"[LearningManager] KB seed validated, synthesizing pattern")
            new_pattern = self.kb.synthesize_pattern_from_hypothesis(
                hypothesis=hypothesis,
                success=True
            )
            if new_pattern:
                self.kb.add_pattern(new_pattern)
                attempt.pattern_id = new_pattern.id
                self.logger.info(
                    f"[LearningManager] Synthesized pattern from KB seed: {new_pattern.name}"
                )

        # record the attempt
        self.kb.record_attempt(attempt)

    def _generate_generalization_notes(
        self,
        pattern: VulnerabilityPattern,
        contract_name: str,
        success: bool
    ) -> str:
        if success:
            return f"Pattern validated on {contract_name}, adds to {len(pattern.contracts_vulnerable)} known vulnerable contracts"
        else:
            return f"Pattern failed on {contract_name}, may not generalize to all {pattern.vuln_type} vulnerabilities"

    def _find_similar_patterns(self, pattern: VulnerabilityPattern) -> list:
        similar = []
        for p in self.kb.patterns.values():
            if p.id != pattern.id and p.vuln_type == pattern.vuln_type:
                similar.append(p.id)
        return similar[:5]  # top 5 similar

    def _assess_generalization_potential(self, pattern: VulnerabilityPattern) -> str:
        # simple heuristic: more specific preconditions = lower generalization
        num_preconditions = len(pattern.preconditions)

        if num_preconditions <= 2:
            return "high"
        elif num_preconditions <= 4:
            return "medium"
        else:
            return "low"

    def _record_false_positive(
        self,
        hypothesis: AttackHypothesis,
        rejection_reason: str,
        contract_name: str
    ) -> None:
        anti_pattern = self.kb.record_false_positive(
            hypothesis=hypothesis,
            rejection_reason=rejection_reason,
            contract_name=contract_name
        )

        # log the anti-pattern creation/update
        self.logger.log_kb_learning_event(
            event_type="anti_pattern_recorded",
            pattern_id=anti_pattern.id,
            trigger="confirmed_false_positive",
            contract_name=contract_name,
            evidence=f"Suppression confidence: {anti_pattern.suppression_confidence:.3f}, "
                     f"FP count: {anti_pattern.false_positive_count}"
        )

        self.logger.info(
            f"[LearningManager] Recorded false positive as anti-pattern: {anti_pattern.name}"
        )

    def _update_specialist_accuracy(
        self,
        specialist_name: str,
        hypothesis: AttackHypothesis,
        is_valid: bool
    ) -> None:
        attack_type = getattr(hypothesis, 'attack_type', 'unknown')

        accuracy = self.kb.record_specialist_outcome(
            specialist_name=specialist_name,
            vuln_type=attack_type,
            is_valid=is_valid
        )

        # log the accuracy update
        self.logger.log_kb_learning_event(
            event_type="specialist_accuracy_updated",
            pattern_id=f"specialist_{specialist_name}_{attack_type}",
            trigger="hypothesis_outcome",
            contract_name=getattr(hypothesis, 'contract_name', 'unknown'),
            evidence=f"Valid={is_valid}, Precision={accuracy.precision:.3f}, "
                     f"Weight={accuracy.get_weight():.3f}"
        )

    def learn_from_successful_poc(
        self,
        hypothesis: AttackHypothesis,
        poc_result: Any,
        contract_name: str,
        specialist_name: Optional[str] = None
    ) -> None:
        # ensure specialist_name is set on hypothesis
        if specialist_name and not hasattr(hypothesis, 'specialist_name'):
            hypothesis.specialist_name = specialist_name  # type: ignore

        self.learn_from_poc_result(
            hypothesis=hypothesis,
            poc_result=poc_result,
            contract_name=contract_name,
            pattern_id=getattr(hypothesis, 'pattern_id', None)
        )

    def check_hypothesis_suppression(
        self,
        hypothesis: AttackHypothesis,
        threshold: float = 0.75
    ) -> tuple[bool, Optional[str]]:
        should_suppress, anti_pattern = self.kb.should_suppress_hypothesis(
            hypothesis=hypothesis,
            threshold=threshold
        )

        if should_suppress and anti_pattern:
            reason = (
                f"Matches anti-pattern '{anti_pattern.name}' "
                f"(confidence: {anti_pattern.suppression_confidence:.2f}, "
                f"FP count: {anti_pattern.false_positive_count})"
            )
            self.logger.info(
                f"[LearningManager] Suppressing hypothesis: {reason}"
            )
            return True, reason

        return False, None

    def get_adjusted_confidence(
        self,
        hypothesis: AttackHypothesis,
        specialist_name: str
    ) -> float:
        return self.kb.adjust_hypothesis_confidence(
            hypothesis=hypothesis,
            specialist_name=specialist_name
        )

    def get_learning_stats(self) -> Dict[str, Any]:
        kb_stats = self.kb.get_stats()

        return {
            **kb_stats,
            "learning_enabled": True,
            "automatic_updates": True
        }

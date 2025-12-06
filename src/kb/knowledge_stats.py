"""knowledge base statistics and metrics"""
import logging
from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.kb.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)


class KnowledgeStats:
    """kb statistics and metrics"""

    def __init__(self, kb: "KnowledgeBase"):
        """
        Initialize KnowledgeStats.

        Args:
            kb: Reference to the parent KnowledgeBase
        """
        self._kb = kb

    def get_stats(self) -> Dict:
        """Get KB statistics including Phase 3.4/4.1-4.2 metrics"""
        from src.kb.knowledge_base import PatternStatus

        kb = self._kb

        # Base stats
        stats = {
            "contracts_analyzed": len(kb.contract_knowledge),
            "patterns_total": len(kb.patterns),
            "patterns_validated": len([p for p in kb.patterns.values()
                                      if p.status == PatternStatus.VALIDATED]),
            "patterns_high_confidence": len(kb.get_high_confidence_patterns()),
            "attempts_total": len(kb.attempts),
            "attempts_successful": len(kb.get_successful_attempts()),
            "success_rate": len(kb.get_successful_attempts()) / len(kb.attempts)
                           if kb.attempts else 0.0
        }

        # Anti-pattern stats (Phase 3.4)
        stats["anti_patterns_total"] = len(kb.anti_patterns)
        stats["anti_patterns_active"] = len([
            ap for ap in kb.anti_patterns.values()
            if ap.should_suppress()
        ])
        stats["total_false_positives_tracked"] = sum(
            ap.false_positive_count for ap in kb.anti_patterns.values()
        )

        # Specialist accuracy stats (Phase 4.1-4.2)
        stats["specialist_accuracy_records"] = len(kb.specialist_accuracy)
        if kb.specialist_accuracy:
            precisions = [sa.precision for sa in kb.specialist_accuracy.values()]
            stats["avg_specialist_precision"] = sum(precisions) / len(precisions)
            stats["total_specialist_hypotheses"] = sum(
                sa.total_hypotheses for sa in kb.specialist_accuracy.values()
            )
        else:
            stats["avg_specialist_precision"] = 0.0
            stats["total_specialist_hypotheses"] = 0

        return stats

    def print_stats(self):
        """Print KB statistics"""
        stats = self.get_stats()
        print("\n[KB] Knowledge Base Statistics:")
        print(f"  Contracts analyzed: {stats['contracts_analyzed']}")
        print(f"  Vulnerability patterns: {stats['patterns_total']}")
        print(f"    - Validated: {stats['patterns_validated']}")
        print(f"    - High confidence (>=0.7): {stats['patterns_high_confidence']}")
        print(f"  Attack attempts: {stats['attempts_total']}")
        print(f"    - Successful: {stats['attempts_successful']}")
        print(f"    - Success rate: {stats['success_rate']:.1%}")
        print(f"  Anti-patterns: {stats['anti_patterns_total']}")
        print(f"    - Active (suppressing): {stats['anti_patterns_active']}")
        print(f"    - Total FPs tracked: {stats['total_false_positives_tracked']}")
        print(f"  Specialist accuracy: {stats['specialist_accuracy_records']} records")
        print(f"    - Avg precision: {stats['avg_specialist_precision']:.1%}")
        print(f"    - Total hypotheses: {stats['total_specialist_hypotheses']}")

    def get_effectiveness_metrics(self) -> Dict[str, Any]:
        """get metrics tracking kb effectiveness over time"""
        from src.kb.knowledge_base import PatternStatus

        kb = self._kb
        metrics = {}

        # Hypothesis hit rate (from specialist accuracy data)
        total_hypotheses = sum(sa.total_hypotheses for sa in kb.specialist_accuracy.values())
        total_tps = sum(sa.true_positives for sa in kb.specialist_accuracy.values())
        metrics["hypothesis_hit_rate"] = total_tps / total_hypotheses if total_hypotheses > 0 else 0.0
        metrics["hypothesis_hit_rate_target"] = 0.6

        # Pattern transfer accuracy (validated patterns that work on multiple contracts)
        transferable_patterns = [
            p for p in kb.patterns.values()
            if len(p.contracts_vulnerable) > 1 and p.status == PatternStatus.VALIDATED
        ]
        total_validated = len([p for p in kb.patterns.values() if p.status == PatternStatus.VALIDATED])
        metrics["pattern_transfer_accuracy"] = len(transferable_patterns) / total_validated if total_validated > 0 else 0.0
        metrics["pattern_transfer_accuracy_target"] = 0.8

        # False positive rate (from anti-patterns)
        total_fps = sum(ap.false_positive_count for ap in kb.anti_patterns.values())
        total_attempts = len(kb.attempts)
        metrics["false_positive_rate"] = total_fps / total_attempts if total_attempts > 0 else 0.0
        metrics["false_positive_rate_target"] = 0.1  # Want < 10%

        # Pattern emergence (synthesized patterns)
        synthesized_count = len([
            p for p in kb.patterns.values()
            if p.discovered_by == "system_synthesis" or p.id.startswith("synth_")
        ])
        metrics["patterns_synthesized"] = synthesized_count
        metrics["pattern_emergence_target"] = 5  # Per 100 audits

        # Average pattern confidence
        if kb.patterns:
            metrics["avg_pattern_confidence"] = sum(p.confidence for p in kb.patterns.values()) / len(kb.patterns)
        else:
            metrics["avg_pattern_confidence"] = 0.0

        # KB-sourced hypothesis success rate
        kb_attempts = [a for a in kb.attempts if "kb_suggestion" in a.hypothesis.lower() or "kb seed" in a.hypothesis.lower()]
        kb_successes = [a for a in kb_attempts if a.success]
        metrics["kb_hypothesis_success_rate"] = len(kb_successes) / len(kb_attempts) if kb_attempts else 0.0

        # Cross-contract pattern coverage
        if kb.patterns:
            avg_contracts_per_pattern = sum(len(p.contracts_vulnerable) for p in kb.patterns.values()) / len(kb.patterns)
            metrics["avg_contracts_per_pattern"] = avg_contracts_per_pattern
        else:
            metrics["avg_contracts_per_pattern"] = 0.0

        return metrics

    def print_effectiveness_metrics(self):
        """Print KB effectiveness metrics for Phase 5 tracking."""
        metrics = self.get_effectiveness_metrics()
        print("\n[KB] Effectiveness Metrics (Phase 5):")
        print(f"  Hypothesis hit rate: {metrics['hypothesis_hit_rate']:.1%} (target: >{metrics['hypothesis_hit_rate_target']:.0%})")
        print(f"  Pattern transfer accuracy: {metrics['pattern_transfer_accuracy']:.1%} (target: >{metrics['pattern_transfer_accuracy_target']:.0%})")
        print(f"  False positive rate: {metrics['false_positive_rate']:.1%} (target: <{metrics['false_positive_rate_target']:.0%})")
        print(f"  Patterns synthesized: {metrics['patterns_synthesized']} (target: {metrics['pattern_emergence_target']}+ per 100 audits)")
        print(f"  Avg pattern confidence: {metrics['avg_pattern_confidence']:.2f}")
        print(f"  KB hypothesis success rate: {metrics['kb_hypothesis_success_rate']:.1%}")
        print(f"  Avg contracts per pattern: {metrics['avg_contracts_per_pattern']:.1f}")

    def get_improvement_recommendations(self) -> List[str]:
        """
        Analyze KB metrics and provide recommendations for improvement.

        Returns:
            List of actionable recommendations
        """
        recommendations = []
        metrics = self.get_effectiveness_metrics()

        # Check hypothesis hit rate
        if metrics["hypothesis_hit_rate"] < metrics["hypothesis_hit_rate_target"]:
            if metrics["hypothesis_hit_rate"] < 0.3:
                recommendations.append(
                    "CRITICAL: Hypothesis hit rate is very low. Consider:\n"
                    "  - Increasing research depth\n"
                    "  - Enabling FRESH_ANALYSIS mode\n"
                    "  - Reviewing specialist prompts for quality"
                )
            else:
                recommendations.append(
                    f"Hypothesis hit rate ({metrics['hypothesis_hit_rate']:.0%}) below target. "
                    "Consider adding more context to specialist prompts."
                )

        # Check false positive rate
        if metrics["false_positive_rate"] > metrics["false_positive_rate_target"]:
            recommendations.append(
                f"False positive rate ({metrics['false_positive_rate']:.0%}) too high. "
                "Anti-patterns are helping reduce this - continue auditing to build anti-pattern library."
            )

        # Check pattern transfer
        if metrics["pattern_transfer_accuracy"] < metrics["pattern_transfer_accuracy_target"] and len(self._kb.patterns) > 5:
            recommendations.append(
                f"Pattern transfer accuracy ({metrics['pattern_transfer_accuracy']:.0%}) below target. "
                "Patterns may be too specific. Consider generalizing preconditions."
            )

        # Check pattern synthesis
        if metrics["patterns_synthesized"] < 3 and len(self._kb.attempts) > 50:
            recommendations.append(
                "Few patterns synthesized despite many attempts. "
                "Enable GraphRAG for community-based pattern discovery."
            )

        # Check KB hypothesis effectiveness
        if metrics["kb_hypothesis_success_rate"] < 0.5 and len(self._kb.attempts) > 20:
            recommendations.append(
                "KB-sourced hypotheses have low success rate. "
                "Consider reducing KB seed confidence or re-training patterns."
            )

        if not recommendations:
            recommendations.append("KB metrics are healthy! Continue auditing to improve further.")

        return recommendations

    def get_specialist_accuracy_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all specialist accuracy data.

        Returns:
            Dictionary with specialist accuracy statistics
        """
        kb = self._kb
        summary = {
            "total_specialists": set(),
            "total_vuln_types": set(),
            "total_hypotheses": 0,
            "total_true_positives": 0,
            "total_false_positives": 0,
            "by_specialist": {},
            "by_vuln_type": {}
        }

        for accuracy in kb.specialist_accuracy.values():
            summary["total_specialists"].add(accuracy.specialist_name)
            summary["total_vuln_types"].add(accuracy.vuln_type)
            summary["total_hypotheses"] += accuracy.total_hypotheses
            summary["total_true_positives"] += accuracy.true_positives
            summary["total_false_positives"] += accuracy.false_positives

            # By specialist
            if accuracy.specialist_name not in summary["by_specialist"]:
                summary["by_specialist"][accuracy.specialist_name] = {
                    "precision": [],
                    "total": 0
                }
            summary["by_specialist"][accuracy.specialist_name]["precision"].append(accuracy.precision)
            summary["by_specialist"][accuracy.specialist_name]["total"] += accuracy.total_hypotheses

            # By vuln type
            if accuracy.vuln_type not in summary["by_vuln_type"]:
                summary["by_vuln_type"][accuracy.vuln_type] = {
                    "precision": [],
                    "total": 0
                }
            summary["by_vuln_type"][accuracy.vuln_type]["precision"].append(accuracy.precision)
            summary["by_vuln_type"][accuracy.vuln_type]["total"] += accuracy.total_hypotheses

        # Compute averages
        summary["total_specialists"] = len(summary["total_specialists"])
        summary["total_vuln_types"] = len(summary["total_vuln_types"])

        for specialist, data in summary["by_specialist"].items():
            if data["precision"]:
                data["avg_precision"] = sum(data["precision"]) / len(data["precision"])
            del data["precision"]

        for vuln_type, data in summary["by_vuln_type"].items():
            if data["precision"]:
                data["avg_precision"] = sum(data["precision"]) / len(data["precision"])
            del data["precision"]

        return summary

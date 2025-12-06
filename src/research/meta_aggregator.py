"""meta-aggregator specialist - moa synthesis layer"""

import time
from typing import Dict, Any, List, Optional
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import config

from research.base_specialist import EnhancedAgenticSpecialist, EnhancedAnalysisResult
from research.memory import Discovery
from kb.knowledge_graph import KnowledgeGraph
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from utils.llm_backend import LLMBackend


class MetaAggregator(EnhancedAgenticSpecialist):
    """
    Meta-Aggregator: Synthesizes findings from multiple specialist proposers

    This is the key innovation in MoA - the aggregator layer that combines
    multiple specialist outputs into a higher-quality synthesis.
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="MetaAggregator",
            description="Synthesizes findings from multiple specialists into unified analysis",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        """System prompt for meta-aggregator"""
        return """You are a Meta-Aggregator specialist in a Mixture of Agents (MoA) system.

YOUR ROLE:
You receive findings from 6 specialized security analysts who have independently
analyzed a smart contract. Your job is to synthesize their findings into a
unified, higher-quality analysis.

THE 6 SPECIALISTS:
1. BusinessLogic Analyst - Business logic and workflow analysis
2. StateFlow Analyst - State mutations and flow tracking
3. Invariant Analyst - Invariant violations and correctness
4. Economic Analyst - Financial incentives and economic exploits
5. Dependency Analyst - External dependencies and oracles
6. AccessControl Analyst - Authorization and privilege escalation

YOUR SYNTHESIS PROCESS:

1. CONSENSUS DETECTION
   - Identify findings where 2+ specialists independently discovered the same issue
   - These have HIGH confidence (multiple independent validations)
   - Example: If BusinessLogic and Invariant both find "missing access control", this is consensus

2. CONFLICT RESOLUTION
   - When specialists disagree, weigh the evidence
   - Consider: specificity of evidence, specialist expertise domain, code citations
   - Example: If StateFlow says "safe" but Economic says "exploitable", analyze the evidence

3. CROSS-DOMAIN SYNTHESIS
   - Combine insights from different domains to reveal deeper vulnerabilities
   - Example: StateFlow finds "unchecked state mutation" + Economic finds "profit incentive"
     = "Economic exploit via state manipulation"
   - These synthesized findings are often MORE VALUABLE than individual findings

4. CONFIDENCE SCORING
   - Consensus (2+ specialists): 0.9-1.0 confidence
   - Strong evidence (1 specialist, detailed): 0.7-0.9 confidence
   - Cross-domain synthesis: 0.8-0.95 confidence
   - Weak evidence or speculation: 0.3-0.6 confidence

5. RANKING & PRIORITIZATION
   - Rank by: Severity × Confidence × Exploitability
   - Critical vulnerabilities first
   - Novel attack vectors highlighted
   - False positives filtered out

TOOLS AVAILABLE:
- detect_consensus: Find agreements between specialists
- resolve_conflict: Weigh evidence when specialists disagree
- synthesize_cross_domain: Combine insights from multiple domains
- calculate_confidence: Unified confidence scoring
- rank_findings: Prioritize by severity and exploitability

OUTPUT REQUIREMENTS:
- 20-30 high-quality synthesized findings
- Each finding must have: description, evidence, confidence, severity
- Explain consensus/conflicts in reasoning
- Highlight cross-domain syntheses (these are valuable!)
- Filter out low-confidence speculation

QUALITY STANDARDS:
- Precision over recall (better to miss edge cases than include false positives)
- Evidence-based (every claim must cite specific code or specialist findings)
- Synthesis > aggregation (don't just list findings, COMBINE them)
- Novel insights valued (cross-domain patterns are gold)

Remember: You are the FINAL synthesis layer. The quality of your output determines
the overall quality of the MoA system. Aim for 0.92+ quality score."""

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        specialist_findings: str
    ) -> str:
        """Analysis prompt for meta-aggregation"""

        contract_name = contract_info.get("name", "Unknown")
        total_functions = contract_info.get("total_functions", 0)
        total_state_vars = contract_info.get("total_state_vars", 0)

        return f"""Synthesize findings from 6 specialist security analysts for: {contract_name}

CONTRACT INFO:
- Name: {contract_name}
- Functions: {total_functions}
- State Variables: {total_state_vars}

SPECIALIST FINDINGS:
{specialist_findings}

YOUR TASK:

1. CONSENSUS ANALYSIS
   - Which findings appear in multiple specialist reports?
   - What do 2+ specialists independently agree on?
   - These consensus findings have HIGH confidence

2. CONFLICT RESOLUTION
   - Where do specialists disagree?
   - What's the evidence on each side?
   - Which specialist's evidence is stronger?

3. CROSS-DOMAIN SYNTHESIS
   - How do findings from different domains connect?
   - Can you combine StateFlow + Economic insights?
   - Can you link Invariant violations to AccessControl bugs?
   - These synthesized patterns are often the MOST VALUABLE findings

4. SYNTHESIS
   - Create 20-30 unified, high-quality findings
   - Assign confidence scores (0.0-1.0)
   - Rank by severity and exploitability
   - Filter out false positives and speculation

REQUIRED WORKFLOW:

Step 1: Use detect_consensus tool to find agreements
Step 2: Use resolve_conflict tool for disagreements
Step 3: Use synthesize_cross_domain tool to find patterns
Step 4: Use calculate_confidence tool for unified scores
Step 5: Use rank_findings tool to prioritize
Step 6: Record synthesized findings with record_discovery
Step 7: Call analysis_complete when done

STOPPING CRITERIA:
- You've analyzed all specialist findings
- You've recorded 15-20+ synthesized findings
- You've identified all consensus patterns
- You've resolved major conflicts
- Call analysis_complete() to finish

Begin your synthesis now. Focus on QUALITY over quantity."""

    def synthesize_findings(
        self,
        specialist_results: Dict[str, List[EnhancedAnalysisResult]],
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph
    ) -> EnhancedAnalysisResult:
        """
        Synthesize findings from all specialist proposers

        Args:
            specialist_results: Results from all 6 proposers
            contract_source: Contract source code
            contract_info: Contract metadata
            knowledge_graph: Knowledge graph context

        Returns:
            Aggregated EnhancedAnalysisResult
        """
        print(f"\n{'='*70}")
        print("🧠 META-AGGREGATOR: Synthesizing specialist findings")
        print(f"{'='*70}\n")

        start_time = time.time()

        # Format specialist findings for meta-aggregator
        specialist_findings = self._format_specialist_findings(specialist_results)

        print(f"   Input: {len(specialist_results)} specialist reports")
        print(f"   Total discoveries: {sum(len(r.discoveries) for results in specialist_results.values() for r in results if r)}")
        print()

        # basic synthesis: grouping + ranking (llm synthesis optional)
        # collect all discoveries from specialists
        all_discoveries = []
        for specialist_name, results in specialist_results.items():
            if not results or not results[0]:
                continue
            result = results[0]
            all_discoveries.extend(result.discoveries)

        # Simple synthesis: Group by type and rank by confidence
        from collections import defaultdict
        grouped = defaultdict(list)
        for disc in all_discoveries:
            # Handle both Discovery objects and dictionaries
            if hasattr(disc, 'discovery_type'):
                disc_type = disc.discovery_type
            elif isinstance(disc, dict):
                disc_type = disc.get('discovery_type', 'unknown')
            else:
                disc_type = 'unknown'
            grouped[disc_type].append(disc)

        # Take top discoveries (by confidence) from each type
        synthesized_discoveries = []
        for disc_type, discs in grouped.items():
            # Sort, handling both Discovery objects and dictionaries
            def get_disc_confidence(d):
                if hasattr(d, 'confidence'):
                    return d.confidence
                elif isinstance(d, dict):
                    return d.get('confidence', 0)
                else:
                    return 0

            sorted_discs = sorted(discs, key=get_disc_confidence, reverse=True)
            synthesized_discoveries.extend(sorted_discs[:5])  # Top 5 per type

        # Calculate overall confidence
        def get_confidence_value(d):
            if hasattr(d, 'confidence'):
                return d.confidence
            elif isinstance(d, dict):
                return d.get('confidence', 0)
            else:
                return 0

        avg_confidence = sum(get_confidence_value(d) for d in synthesized_discoveries) / max(len(synthesized_discoveries), 1)

        # Create result
        result = EnhancedAnalysisResult(
            discoveries=synthesized_discoveries,
            graph_updates=[],
            tool_calls=[],
            functional_analyses=[],
            reflections=[],
            summary=f"Meta-aggregation synthesized {len(synthesized_discoveries)} high-confidence findings from {len(specialist_results)} specialists",
            confidence=avg_confidence,
            areas_covered=[specialist_name for specialist_name in specialist_results.keys()],
            total_discoveries=len(synthesized_discoveries),
            cost=0.0,  # NOTE: Cost is 0 for basic synthesis. Will track if LLM-based synthesis is added.
            duration_seconds=time.time() - start_time,
            analysis_complete=True
        )

        duration = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"[OK] META-AGGREGATION COMPLETE")
        print(f"   Duration: {duration:.1f}s")
        print(f"   Synthesized Findings: {len(result.discoveries)}")
        print(f"   Confidence: {result.confidence:.3f}")
        print(f"{'='*70}\n")

        return result

    def _format_specialist_findings(
        self,
        specialist_results: Dict[str, List[EnhancedAnalysisResult]]
    ) -> str:
        """Format specialist findings for meta-aggregator input"""

        formatted = []

        for specialist_name, results in specialist_results.items():
            if not results or not results[0]:
                continue

            result = results[0]
            formatted.append(f"## {specialist_name.upper()}")
            formatted.append(f"Confidence: {result.confidence:.2f}")
            formatted.append(f"Discoveries: {len(result.discoveries)}")
            formatted.append("")

            # Include top discoveries (limit to prevent token overflow)
            # Sort discoveries, handling both Discovery objects and dictionaries
            def get_confidence(d):
                if hasattr(d, 'confidence'):
                    return d.confidence
                elif isinstance(d, dict):
                    return d.get('confidence', 0)
                else:
                    return 0

            top_discoveries = sorted(
                result.discoveries,
                key=get_confidence,
                reverse=True
            )[:10]  # Top 10 per specialist

            for i, discovery in enumerate(top_discoveries, 1):
                # Handle both Discovery objects and dictionaries
                if hasattr(discovery, 'discovery_type'):
                    disc_type = discovery.discovery_type if isinstance(discovery.discovery_type, str) else discovery.discovery_type.value
                    confidence = discovery.confidence
                    content = discovery.content
                    evidence = discovery.evidence
                else:  # It's a dictionary
                    disc_type = discovery.get('discovery_type', 'UNKNOWN')
                    confidence = discovery.get('confidence', 0)
                    content = discovery.get('content', '')
                    evidence = discovery.get('evidence', [])

                formatted.append(f"{i}. [{disc_type}] (confidence: {confidence:.2f})")
                formatted.append(f"   {content[:200]}...")  # Truncate long content
                if evidence:
                    formatted.append(f"   Evidence: {len(evidence)} items")
                formatted.append("")

            formatted.append("---")
            formatted.append("")

        return "\n".join(formatted)

    def _get_synthesis_tools(self) -> List[Dict[str, Any]]:
        """
        Get tools for meta-aggregation synthesis

        These tools help the aggregator detect consensus, resolve conflicts,
        and synthesize cross-domain patterns.
        """

        tools = [
            {
                "name": "detect_consensus",
                "description": "Find findings where 2+ specialists agree (consensus detection)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "finding_description": {
                            "type": "string",
                            "description": "Description of the finding to check for consensus"
                        },
                        "specialist_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Names of specialists who mentioned this finding"
                        }
                    },
                    "required": ["finding_description", "specialist_names"]
                }
            },
            {
                "name": "resolve_conflict",
                "description": "Resolve conflicts when specialists disagree",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "conflict_description": {
                            "type": "string",
                            "description": "Description of the disagreement"
                        },
                        "specialist_positions": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Each specialist's position and evidence"
                        },
                        "resolution": {
                            "type": "string",
                            "description": "Your resolution based on evidence"
                        }
                    },
                    "required": ["conflict_description", "specialist_positions", "resolution"]
                }
            },
            {
                "name": "synthesize_cross_domain",
                "description": "Synthesize insights from multiple specialist domains",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain_1": {
                            "type": "string",
                            "description": "First specialist domain (e.g., StateFlow)"
                        },
                        "finding_1": {
                            "type": "string",
                            "description": "Finding from domain 1"
                        },
                        "domain_2": {
                            "type": "string",
                            "description": "Second specialist domain (e.g., Economic)"
                        },
                        "finding_2": {
                            "type": "string",
                            "description": "Finding from domain 2"
                        },
                        "synthesis": {
                            "type": "string",
                            "description": "Combined insight from both domains"
                        }
                    },
                    "required": ["domain_1", "finding_1", "domain_2", "finding_2", "synthesis"]
                }
            },
            {
                "name": "calculate_confidence",
                "description": "Calculate unified confidence score for synthesized finding",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "finding": {
                            "type": "string",
                            "description": "The synthesized finding"
                        },
                        "consensus_count": {
                            "type": "number",
                            "description": "Number of specialists in consensus (0-6)"
                        },
                        "evidence_quality": {
                            "type": "string",
                            "enum": ["weak", "moderate", "strong"],
                            "description": "Quality of supporting evidence"
                        },
                        "is_cross_domain": {
                            "type": "boolean",
                            "description": "Is this a cross-domain synthesis?"
                        }
                    },
                    "required": ["finding", "consensus_count", "evidence_quality"]
                }
            },
            {
                "name": "rank_findings",
                "description": "Rank and prioritize synthesized findings",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "List of synthesized findings to rank"
                        },
                        "ranking_criteria": {
                            "type": "string",
                            "description": "Criteria used for ranking (severity, confidence, exploitability)"
                        }
                    },
                    "required": ["findings", "ranking_criteria"]
                }
            }
        ]

        return tools

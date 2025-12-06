"""ace integration - wraps v3 specialists with self-improving playbooks."""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Type

from research.base_specialist import EnhancedAgenticSpecialist, EnhancedAnalysisResult
from agent.ace_framework import ACEFramework
from utils.logging import ResearchLogger
from utils.llm_backend import LLMBackend
from kb.knowledge_graph import KnowledgeGraph


class ACEWrappedSpecialist:
    """wraps ace-enhanced specialists for standard pipeline compatibility."""

    def __init__(
        self,
        ace_framework: ACEFramework,
        specialist_name: str,
        logger: ResearchLogger
    ):
        self.ace_framework = ace_framework
        self.name = specialist_name
        self.logger = logger

    def analyze_contract(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: Optional[KnowledgeGraph] = None
    ) -> EnhancedAnalysisResult:
        """analyze contract using ace-enhanced specialist with playbook injection."""
        return self.ace_framework.analyze_contract(
            contract_source=contract_source,
            contract_info=contract_info
        )


def create_ace_specialist(
    specialist_class: Type[EnhancedAgenticSpecialist],
    backend: LLMBackend,
    logger: ResearchLogger,
    project_root: Path,
    enable_ace: bool = True,
    **specialist_kwargs
) -> EnhancedAgenticSpecialist:
    """create specialist with optional ace wrapper for self-improving playbooks."""
    # Create base specialist instance
    specialist = specialist_class(
        backend=backend,
        project_root=project_root,
        **specialist_kwargs
    )

    if not enable_ace:
        # Return standard specialist without ACE
        return specialist

    # Wrap with ACE framework
    specialist_name = specialist.name

    # Create playbook directory
    playbook_dir = project_root / "data" / "ace_playbooks"
    playbook_dir.mkdir(parents=True, exist_ok=True)

    # Playbook path for this specialist
    playbook_path = playbook_dir / f"{specialist_name.lower().replace(' ', '_')}.json"

    # Create ACE framework
    ace_framework = ACEFramework(
        base_specialist=specialist,
        backend=backend,
        logger=logger,
        playbook_path=str(playbook_path)
    )

    logger.info(f"[ACE Integration] Wrapped {specialist_name} with ACE framework")
    logger.info(f"[ACE Integration] Playbook: {playbook_path}")

    # Return wrapped specialist
    return ACEWrappedSpecialist(
        ace_framework=ace_framework,
        specialist_name=specialist_name,
        logger=logger
    )


def create_all_ace_specialists(
    backend: LLMBackend,
    logger: ResearchLogger,
    project_root: Path,
    enable_ace: bool = True,
    **specialist_kwargs
) -> Dict[str, EnhancedAgenticSpecialist]:
    """create all 6 v3 specialists with optional ace wrapping."""
    # Import V3 specialist classes
    from research.business_logic import EnhancedBusinessLogicAnalyst
    from research.state_flow import EnhancedStateFlowAnalyst
    from research.invariant import EnhancedInvariantAnalyst
    from research.economic import EnhancedEconomicAnalyst
    from research.dependency import EnhancedDependencyAnalyst
    from research.access_control import EnhancedAccessControlAnalyst

    specialist_classes = [
        EnhancedBusinessLogicAnalyst,
        EnhancedStateFlowAnalyst,
        EnhancedInvariantAnalyst,
        EnhancedEconomicAnalyst,
        EnhancedDependencyAnalyst,
        EnhancedAccessControlAnalyst
    ]

    specialists = {}

    for specialist_class in specialist_classes:
        specialist = create_ace_specialist(
            specialist_class=specialist_class,
            backend=backend,
            logger=logger,
            project_root=project_root,
            enable_ace=enable_ace,
            **specialist_kwargs
        )
        specialists[specialist.name] = specialist

    if enable_ace:
        logger.info(f"[ACE Integration] Created {len(specialists)} ACE-wrapped specialists")
    else:
        logger.info(f"[ACE Integration] Created {len(specialists)} standard specialists")

    return specialists


def get_ace_statistics(project_root: Path) -> Dict[str, Any]:
    """get ace playbook growth statistics across specialists."""
    playbook_dir = project_root / "data" / "ace_playbooks"

    if not playbook_dir.exists():
        return {
            "total_playbooks": 0,
            "total_patterns": 0,
            "specialists": []
        }

    import json

    total_patterns = 0
    specialist_stats = []

    for playbook_file in playbook_dir.glob("*.json"):
        try:
            with open(playbook_file, 'r') as f:
                data = json.load(f)
                entries = data.get('entries', [])
                num_patterns = len(entries)
                total_patterns += num_patterns

                specialist_stats.append({
                    'specialist': playbook_file.stem,
                    'patterns': num_patterns,
                    'last_updated': data.get('last_updated', 'unknown')
                })
        except Exception:
            continue

    return {
        "total_playbooks": len(specialist_stats),
        "total_patterns": total_patterns,
        "specialists": specialist_stats
    }

"""contract analysis layer"""
from .contract_discovery import ContractDiscoverySystem
from .static_analyzer import StaticAnalyzer, analyze_project as run_static_analysis
from .attack_surface import AttackSurfaceExtractor, extract_all_attack_surfaces

__all__ = [
    "ContractDiscoverySystem",
    "StaticAnalyzer",
    "AttackSurfaceExtractor",
    "run_static_analysis",
    "extract_all_attack_surfaces",
    "analyze_project",
]

def analyze_project(project_root: str):
    """run complete cal pipeline"""
    print("="*80)
    print("cal - layer 1")
    print("="*80)

    print("\n[1/3] discovery")
    discovery = ContractDiscoverySystem(project_root)
    project = discovery.discover()

    print("\n[2/3] static analysis")
    analyzer = StaticAnalyzer(project.project_root)
    static_findings = analyzer.analyze(project)

    print("\n[3/3] attack surface")
    attack_surfaces = extract_all_attack_surfaces(project)

    print("\n" + "="*80)
    print(f"contracts: {project.total_contracts} | findings: {len(static_findings)} | surfaces: {len(attack_surfaces)}")
    print("="*80)

    return {
        "project": project,
        "static_findings": static_findings,
        "attack_surfaces": attack_surfaces,
    }

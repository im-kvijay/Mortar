from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, UTC
from pathlib import Path


class VulnerabilityType(Enum):
    """vulnerability classification"""
    ACCESS_CONTROL = "access_control"
    LOGIC_ERROR = "logic_error"
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    INPUT_VALIDATION = "input_validation"
    ORACLE_MANIPULATION = "oracle_manipulation"
    UNCHECKED_CALL = "unchecked_call"
    INTEGER_OVERFLOW = "integer_overflow"
    FRONT_RUNNING = "front_running"
    CENTRALIZATION = "centralization"
    DOS = "denial_of_service"
    PRICE_MANIPULATION = "price_manipulation"
    GOVERNANCE_ATTACK = "governance_attack"
    SIGNATURE_REPLAY = "signature_replay"
    DELEGATE_CALL = "delegatecall_vulnerability"
    INITIALIZATION = "initialization_flaw"
    TIME_MANIPULATION = "time_manipulation"
    ARBITRARY_CALL = "arbitrary_external_call"
    READ_ONLY_REENTRANCY = "read_only_reentrancy"
    CROSS_FUNCTION_REENTRANCY = "cross_function_reentrancy"
    CROSS_CONTRACT_REENTRANCY = "cross_contract_reentrancy"
    ABI_ENCODING = "abi_encoding_manipulation"
    MERKLE_PROOF = "merkle_proof_vulnerability"
    CREATE2 = "create2_vulnerability"

    UNKNOWN = "unknown"


class Severity(Enum):
    """severity classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ContractType(Enum):
    """contract classification"""
    VAULT = "vault"
    POOL = "pool"
    LENDING = "lending"
    EXCHANGE = "exchange"
    ORACLE = "oracle"
    GOVERNANCE = "governance"
    TOKEN = "token"
    NFT = "nft"
    PROXY = "proxy"
    FACTORY = "factory"
    ROUTER = "router"
    BRIDGE = "bridge"
    STAKING = "staking"
    UNKNOWN = "unknown"


@dataclass
class ContractInfo:
    """single smart contract metadata with lazy source loading"""
    name: str
    file_path: Path
    solidity_version: str
    contract_type: ContractType = ContractType.UNKNOWN
    is_upgradeable: bool = False
    is_abstract: bool = False
    is_interface: bool = False
    imports: List[str] = field(default_factory=list)
    inherits: List[str] = field(default_factory=list)
    libraries_used: List[str] = field(default_factory=list)
    lines_of_code: int = 0
    function_count: int = 0
    external_function_count: int = 0
    public_function_count: int = 0
    source_code: Optional[str] = None
    bytecode: Optional[str] = None
    abi: Optional[List[Dict]] = None
    _project_root: Optional[Path] = field(default=None, repr=False)
    _source_cache: Optional[str] = field(default=None, repr=False)

    def get_source_code(self) -> str:
        """lazy load source from cache or disk"""
        if self._source_cache is not None:
            return self._source_cache
        if self.source_code is not None:
            self._source_cache = self.source_code
            return self.source_code
        if self._project_root:
            file_path = self._project_root / self.file_path
        else:
            file_path = self.file_path

        try:
            self._source_cache = file_path.read_text(encoding='utf-8')
            return self._source_cache
        except Exception:
            self._source_cache = ""
            return ""

    def set_project_root(self, project_root: Path) -> None:
        """set project root for lazy loading"""
        self._project_root = project_root

    def __repr__(self) -> str:
        return f"ContractInfo({self.name}, type={self.contract_type.value})"


@dataclass
class ProjectStructure:
    """foundry project structure"""
    project_root: Path
    project_name: str
    contracts: List[ContractInfo] = field(default_factory=list)
    test_contracts: List[ContractInfo] = field(default_factory=list)
    solidity_versions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    total_contracts: int = 0
    total_lines_of_code: int = 0
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def get_contract_by_name(self, name: str) -> Optional[ContractInfo]:
        """Find contract by name"""
        for contract in self.contracts:
            if contract.name == name:
                return contract
        return None

    def get_contracts_by_type(self, contract_type: ContractType) -> List[ContractInfo]:
        """Get all contracts of a specific type"""
        return [c for c in self.contracts if c.contract_type == contract_type]

    def __repr__(self) -> str:
        return f"ProjectStructure({self.project_name}, {self.total_contracts} contracts)"


@dataclass
class ContractInterfaceSummary:
    """contract interface summary"""
    name: str
    file_path: str
    purpose: str
    external_api: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    trust_assumptions: List[str] = field(default_factory=list)

    def to_context_string(self) -> str:
        return f"""
CONTRACT: {self.name}
PURPOSE: {self.purpose}
API: {', '.join(self.external_api[:10])}{'...' if len(self.external_api) > 10 else ''}
DEPENDENCIES: {', '.join(self.dependencies)}
""".strip()


@dataclass
class FunctionSignature:
    """function signature with security metadata"""
    name: str
    selector: str
    visibility: str
    state_mutability: str
    inputs: List[Dict[str, str]] = field(default_factory=list)
    outputs: List[Dict[str, str]] = field(default_factory=list)
    has_modifiers: bool = False
    modifiers: List[str] = field(default_factory=list)
    has_external_calls: bool = False
    has_delegatecall: bool = False
    is_payable: bool = False

    def __repr__(self) -> str:
        return f"{self.name}({len(self.inputs)} params) {self.visibility} {self.state_mutability}"


@dataclass
class StateVariable:
    """state variable metadata"""
    name: str
    type: str
    visibility: str

    is_constant: bool = False
    is_immutable: bool = False
    initial_value: Optional[str] = None


@dataclass
class ExternalCall:
    """external call site"""
    function_name: str
    call_type: str
    target: str
    is_user_controlled: bool = False


@dataclass
class TokenFlow:
    """token movement path"""
    function_name: str
    token: str
    flow_type: str
    amount_expression: str
    has_balance_check: bool = False
    has_allowance_check: bool = False
    updates_before_transfer: bool = True


@dataclass
class OracleDependency:
    """price oracle usage"""
    function_name: str
    oracle_address: str
    oracle_type: str
    is_twap: bool = False
    twap_window: Optional[int] = None


@dataclass
class UpgradePattern:
    """upgradeability mechanism"""
    pattern_type: str
    admin_address: Optional[str] = None
    implementation_slot: Optional[str] = None


@dataclass
class AttackSurface:
    """contract attack surface"""
    contract_name: str
    contract_address: Optional[str] = None
    external_functions: List[FunctionSignature] = field(default_factory=list)
    privileged_functions: List[FunctionSignature] = field(default_factory=list)
    state_variables: List[StateVariable] = field(default_factory=list)
    external_calls: List[ExternalCall] = field(default_factory=list)
    token_flows: List[TokenFlow] = field(default_factory=list)
    oracle_dependencies: List[OracleDependency] = field(default_factory=list)
    upgrade_mechanism: Optional[UpgradePattern] = None
    has_flashloan: bool = False
    flashloan_functions: List[str] = field(default_factory=list)
    has_reentrancy_guard: bool = False
    reentrancy_protected_functions: List[str] = field(default_factory=list)

    def get_unprotected_external_functions(self) -> List[FunctionSignature]:
        return [f for f in self.external_functions if not f.has_modifiers]

    def has_arbitrary_external_calls(self) -> bool:
        return any(call.is_user_controlled for call in self.external_calls)

    def __repr__(self) -> str:
        return f"AttackSurface({self.contract_name}, {len(self.external_functions)} external funcs)"


@dataclass
class StaticAnalysisFinding:
    """static analysis finding"""
    detector_name: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    confidence: float
    description: str
    location: str
    affected_contract: Optional['ContractInfo'] = None
    raw_output: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"StaticAnalysisFinding({self.severity.value}, {self.vulnerability_type.value}, {self.location})"


@dataclass
class AnalysisResult:
    """combined static analysis results"""
    contract_name: str
    slither_findings: List[StaticAnalysisFinding] = field(default_factory=list)
    mythril_findings: List[StaticAnalysisFinding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    analysis_time_seconds: float = 0.0
    tools_failed: List[str] = field(default_factory=list)

    def get_all_findings(self) -> List[StaticAnalysisFinding]:
        return self.slither_findings + self.mythril_findings

    def get_critical_findings(self) -> List[StaticAnalysisFinding]:
        return [f for f in self.get_all_findings() if f.severity.lower() == "critical"]


@dataclass
class RiskAssessment:
    """risk scoring"""
    risk_score: float
    should_deep_analyze: bool
    has_critical_findings: bool = False
    has_external_calls: bool = False
    has_flashloans: bool = False
    has_oracles: bool = False
    is_complex: bool = False
    reasoning: str = ""


@dataclass
class CALOutput:
    """cal output"""
    contract_info: ContractInfo
    project_structure: ProjectStructure
    static_analysis: AnalysisResult
    attack_surface: AttackSurface
    risk_assessment: RiskAssessment
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_llm_prompt(self) -> str:
        prompt = f"""# Contract Analysis Report

## Contract Information
- Name: {self.contract_info.name}
- Type: {self.contract_info.contract_type.value}
- File: {self.contract_info.file_path}
- Lines of Code: {self.contract_info.lines_of_code}
- Functions: {self.contract_info.function_count} ({self.contract_info.external_function_count} external)

## Static Analysis Results
- Critical: {self.static_analysis.critical_count}
- High: {self.static_analysis.high_count}
- Medium: {self.static_analysis.medium_count}
- Low: {self.static_analysis.low_count}

### Key Findings:
{self._format_top_findings()}

## Attack Surface
- External Functions: {len(self.attack_surface.external_functions)}
- Privileged Functions: {len(self.attack_surface.privileged_functions)}
- External Calls: {len(self.attack_surface.external_calls)}
- Token Flows: {len(self.attack_surface.token_flows)}
- Has Flash Loans: {self.attack_surface.has_flashloan}
- Has Oracles: {len(self.attack_surface.oracle_dependencies) > 0}
- Upgradeable: {self.attack_surface.upgrade_mechanism is not None}

## Risk Assessment
- Risk Score: {self.risk_assessment.risk_score:.2f}/1.0
- Should Deep Analyze: {self.risk_assessment.should_deep_analyze}
- Reasoning: {self.risk_assessment.reasoning}

## Source Code
```solidity
{self.contract_info.source_code if self.contract_info.source_code else '[Source not available]'}
```
"""
        return prompt

    def _format_top_findings(self) -> str:
        findings = self.static_analysis.get_all_findings()[:5]
        if not findings:
            return "No findings."

        lines = []
        for i, finding in enumerate(findings, 1):
            lines.append(f"{i}. [{finding.severity.upper()}] {finding.detector_name}: {finding.description[:100]}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"CALOutput({self.contract_info.name}, risk={self.risk_assessment.risk_score:.2f})"


@dataclass
class Finding:
    """confirmed vulnerability"""
    vulnerability_type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    affected_contracts: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    line_numbers: List[int] = field(default_factory=list)
    poc_code: str = ""
    execution_result: Optional[Dict] = None
    impact_description: str = ""
    estimated_loss: Optional[str] = None
    remediation: str = ""
    confidence: float = 0.0
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    discovered_by: str = "Mortar-C Agentic Auditor"
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_contracts": self.affected_contracts,
            "affected_functions": self.affected_functions,
            "line_numbers": self.line_numbers,
            "poc_code": self.poc_code,
            "execution_result": self.execution_result,
            "impact_description": self.impact_description,
            "estimated_loss": self.estimated_loss,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at.isoformat(),
            "discovered_by": self.discovered_by,
            "verified": self.verified,
        }

    def __repr__(self) -> str:
        return f"Finding([{self.severity.value.upper()}] {self.title})"


@dataclass
class SystemFinding:
    """cross-contract vulnerability"""
    title: str
    description: str
    severity: Severity
    vulnerability_type: str = "Logic Error"
    affected_contracts: List[str] = field(default_factory=list)
    
    def __repr__(self) -> str:
        return f"SystemFinding([{self.severity.value.upper()}] {self.title})"


@dataclass
class AuditResult:
    """audit result"""
    contract_name: str
    contract_path: Path
    audit_id: Optional[str] = None
    iterations_used: int = 0
    static_findings: List[Any] = field(default_factory=list)
    attack_surface: Optional[Any] = None
    research_quality: float = 0.0
    knowledge_graph: Optional[Any] = None
    research_discoveries: List[Any] = field(default_factory=list)
    attack_hypotheses: List[Any] = field(default_factory=list)
    validated_vulnerabilities: List[Any] = field(default_factory=list)
    generated_pocs: List[Any] = field(default_factory=list)
    executed_pocs: List[Any] = field(default_factory=list)
    total_cost: float = 0.0
    total_time: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    run_profile: Optional[Dict[str, Any]] = None
    success: bool = False
    error_message: Optional[str] = None
    budget_degraded: bool = False
    dedup_saved: bool = False
    findings: List[Finding] = field(default_factory=list)

    def get_critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def get_high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def _count_by_severity(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def _poc_success_rate(self) -> float:
        if not self.generated_pocs:
            return 0.0
        return len(self.executed_pocs) / len(self.generated_pocs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_name": self.contract_name,
            "contract_path": str(self.contract_path),
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "validated_vulnerabilities": [
                {
                    "hypothesis": {
                        "attack_type": vuln['hypothesis'].attack_type,
                        "description": vuln['hypothesis'].description,
                        "confidence": vuln['hypothesis'].confidence,
                    },
                    "impact": {
                        "severity": vuln['impact'].severity.value if vuln.get('impact') else None,
                        "economic_impact_usd": vuln['impact'].economic_impact_usd if vuln.get('impact') else 0.0,
                    } if vuln.get('impact') else None,
                    "resolution": {
                        "fix_complexity": vuln['resolution'].fix_complexity.value if vuln.get('resolution') else None,
                        "remediation_steps": vuln['resolution'].remediation_steps if vuln.get('resolution') else [],
                    } if vuln.get('resolution') else None,
                    "poc_path": str(vuln['poc'].file_path) if vuln.get('poc') else None,
                    "gas_used": vuln['execution'].gas_used if vuln.get('execution') else None,
                }
                for vuln in self.validated_vulnerabilities
            ],
            "stats": {
                "total_findings": len(self.findings),
                "by_severity": self._count_by_severity(),
                "validated_count": len(self.validated_vulnerabilities),
                "verified_count": sum(1 for f in self.findings if f.verified),
                "poc_success_rate": self._poc_success_rate(),
                "research_quality": self.research_quality,
                "attack_hypotheses": len(self.attack_hypotheses),
                "pocs_generated": len(self.generated_pocs),
                "pocs_executed": len(self.executed_pocs),
            },
            "cost_usd": self.total_cost,
            "duration_seconds": self.total_time,
            "success": self.success,
            "error_message": self.error_message,
            "budget_degraded": self.budget_degraded,
            "dedup_saved": self.dedup_saved,
            "run_profile": self.run_profile,
        }

    def to_json(self, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_sarif(self) -> Dict[str, Any]:
        from utils.output_formats import SARIFFormatter
        formatter = SARIFFormatter()
        sarif_json = formatter.format(self)
        import json
        return json.loads(sarif_json)

    def __repr__(self) -> str:
        return f"AuditResult({self.contract_name}, {len(self.findings)} findings, {self.iterations_used} iterations)"

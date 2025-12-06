"""s for Findings data models"""

import unittest
from datetime import datetime
from pathlib import Path
from src.models.findings import (
    Severity,
    VulnerabilityType,
    Finding,
    AuditResult,
    ContractInfo,
    ContractType
)

class TestFindingsModels(unittest.TestCase):
    """Test Findings data models"""

    def test_finding_creation(self):
        finding = Finding(
            title="Reentrancy vulnerability",
            description="Contract vulnerable to reentrancy attack",
            severity=Severity.CRITICAL,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            affected_contracts=["VulnerableContract"],
            affected_functions=["withdraw"],
            confidence=0.95
        )

        self.assertEqual(finding.title, "Reentrancy vulnerability")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.confidence, 0.95)
        self.assertIsInstance(finding.discovered_at, datetime)
        self.assertIn("VulnerableContract", finding.affected_contracts)

    def test_finding_severity_values(self):
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")
        self.assertEqual(Severity.INFORMATIONAL.value, "informational")

    def test_finding_confidence_validation(self):
        finding = Finding(
            title="Test",
            description="Test",
            severity=Severity.LOW,
            vulnerability_type=VulnerabilityType.LOGIC_ERROR,
            confidence=0.75
        )
        self.assertEqual(finding.confidence, 0.75)
        self.assertGreaterEqual(finding.confidence, 0.0)
        self.assertLessEqual(finding.confidence, 1.0)

    def test_audit_result_creation(self):
        audit = AuditResult(
            contract_name="TestContract",
            contract_path=Path("/test/TestContract.sol")
        )

        # add findings
        finding1 = Finding(
            title="Issue 1",
            description="Description 1",
            severity=Severity.HIGH,
            vulnerability_type=VulnerabilityType.ACCESS_CONTROL,
            confidence=0.9
        )

        finding2 = Finding(
            title="Issue 2",
            description="Description 2",
            severity=Severity.LOW,
            vulnerability_type=VulnerabilityType.LOGIC_ERROR,
            confidence=0.6
        )

        audit.findings.append(finding1)
        audit.findings.append(finding2)

        self.assertEqual(len(audit.findings), 2)
        self.assertEqual(audit.findings[0].severity, Severity.HIGH)

    def test_audit_result_severity_counts(self):
        audit = AuditResult(
            contract_name="TestContract",
            contract_path=Path("/test/TestContract.sol")
        )

        # add multiple findings
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM]:
            finding = Finding(
                title=f"Issue {severity.value}",
                description="Test",
                severity=severity,
                vulnerability_type=VulnerabilityType.LOGIC_ERROR,
                confidence=0.8
            )
            audit.findings.append(finding)
        critical_findings = audit.get_critical_findings()
        high_findings = audit.get_high_findings()

        self.assertEqual(len(critical_findings), 1)
        self.assertEqual(len(high_findings), 2)

    def test_contract_info_creation(self):
        contract = ContractInfo(
            name="TestVault",
            file_path=Path("/test/Vault.sol"),
            solidity_version="0.8.20",
            contract_type=ContractType.VAULT,
            is_upgradeable=True,
            lines_of_code=250,
            function_count=12,
            external_function_count=8
        )

        self.assertEqual(contract.name, "TestVault")
        self.assertEqual(contract.contract_type, ContractType.VAULT)
        self.assertTrue(contract.is_upgradeable)
        self.assertEqual(contract.external_function_count, 8)

    def test_finding_poc_fields(self):
        finding = Finding(
            title="Reentrancy attack",
            description="Can drain funds",
            severity=Severity.CRITICAL,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            poc_code="function exploit() external { ... }",
            execution_result={"success": True, "gas_used": 50000},
            impact_description="$1M at risk",
            remediation="Add reentrancy guard"
        )

        self.assertIn("exploit", finding.poc_code)
        self.assertIsNotNone(finding.execution_result)
        self.assertTrue(finding.execution_result["success"])
        self.assertIn("$1M", finding.impact_description)

    def test_vulnerability_type_coverage(self):
        required_types = [
            "REENTRANCY",
            "ACCESS_CONTROL",
            "LOGIC_ERROR",
            "FLASH_LOAN",
            "ORACLE_MANIPULATION",
            "FRONT_RUNNING"
        ]

        for type_name in required_types:
            self.assertTrue(
                hasattr(VulnerabilityType, type_name),
                f"Missing vulnerability type: {type_name}"
            )

if __name__ == '__main__':
    unittest.main()

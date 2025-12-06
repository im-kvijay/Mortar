""" """

import json
from pathlib import Path
from datetime import datetime, UTC

import pytest

from src.models.findings import AuditResult, Finding, Severity, VulnerabilityType
from src.utils.output_formats import (
    OutputFormat,
    get_formatter,
    TextFormatter,
    JSONFormatter,
    SARIFFormatter,
    MarkdownFormatter,
)

@pytest.fixture
def sample_audit_result():

    finding = Finding(
        vulnerability_type=VulnerabilityType.REENTRANCY,
        severity=Severity.CRITICAL,
        title="Reentrancy vulnerability in withdraw()",
        description="The withdraw function is vulnerable to reentrancy attacks",
        affected_contracts=["VulnerableContract"],
        affected_functions=["withdraw"],
        line_numbers=[42, 43],
        confidence=0.95,
        remediation="Add reentrancy guard or use CEI pattern",
        verified=True,
    )

    return AuditResult(
        contract_name="VulnerableContract",
        contract_path=Path("/path/to/VulnerableContract.sol"),
        audit_id="test-audit-001",
        findings=[finding],
        validated_vulnerabilities=[],
        total_cost=1.50,
        total_time=120.0,
        success=True,
        research_quality=0.85,
    )

def test_get_formatter():
    assert isinstance(get_formatter(OutputFormat.TEXT), TextFormatter)
    assert isinstance(get_formatter(OutputFormat.JSON), JSONFormatter)
    assert isinstance(get_formatter(OutputFormat.SARIF), SARIFFormatter)
    assert isinstance(get_formatter(OutputFormat.MARKDOWN), MarkdownFormatter)

def test_text_formatter(sample_audit_result):
    formatter = TextFormatter()
    output = formatter.format(sample_audit_result)

    assert "AUDIT SUCCESSFUL" in output
    assert "VulnerableContract" in output
    assert "Total Findings: 1" in output
    assert "Total Cost: $1.50" in output
    assert "Total Time: 120.0s" in output
    assert "Reentrancy vulnerability in withdraw()" in output

def test_text_formatter_failure():
    result = AuditResult(
        contract_name="FailedContract",
        contract_path=Path("/path/to/Failed.sol"),
        success=False,
        error_message="Analysis failed due to timeout",
    )

    formatter = TextFormatter()
    output = formatter.format(result)

    assert "AUDIT FAILED" in output
    assert "Analysis failed due to timeout" in output

def test_json_formatter(sample_audit_result):
    formatter = JSONFormatter()
    output = formatter.format(sample_audit_result)

    # parse to verify valid json
    data = json.loads(output)

    assert data["contract_name"] == "VulnerableContract"
    assert data["success"] is True
    assert data["cost_usd"] == 1.50
    assert data["duration_seconds"] == 120.0
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "critical"
    assert data["findings"][0]["vulnerability_type"] == "reentrancy"
    assert data["findings"][0]["verified"] is True

def test_sarif_formatter(sample_audit_result):
    formatter = SARIFFormatter()
    output = formatter.format(sample_audit_result)

    # parse to verify valid json
    sarif = json.loads(output)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run
    assert "artifacts" in run
    assert "invocations" in run
    tool = run["tool"]["driver"]
    assert tool["name"] == "Mortar-C"
    assert tool["version"] == "1.0.0"
    assert "rules" in tool
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "reentrancy"
    assert result["level"] == "error"  # critical/high -> error
    assert "message" in result
    assert "locations" in result

def test_sarif_severity_mapping():
    formatter = SARIFFormatter()

    assert formatter._severity_to_sarif_level(Severity.CRITICAL) == "error"
    assert formatter._severity_to_sarif_level(Severity.HIGH) == "error"
    assert formatter._severity_to_sarif_level(Severity.MEDIUM) == "warning"
    assert formatter._severity_to_sarif_level(Severity.LOW) == "note"
    assert formatter._severity_to_sarif_level(Severity.INFORMATIONAL) == "note"

def test_markdown_formatter(sample_audit_result):
    formatter = MarkdownFormatter()
    output = formatter.format(sample_audit_result)

    assert "# mortar-c audit report" in output
    assert "## audit information" in output
    assert "## summary" in output
    assert "VulnerableContract" in output
    assert "Total Findings**: 1" in output
    assert "### 1." in output  # finding number
    assert "[CRITICAL]" in output
    assert "Reentrancy vulnerability in withdraw()" in output
    assert "**Remediation**: Add reentrancy guard or use CEI pattern" in output

def test_markdown_formatter_severity_breakdown(sample_audit_result):
    formatter = MarkdownFormatter()
    output = formatter.format(sample_audit_result)

    assert "### severity breakdown" in output
    assert "Critical" in output
    assert "High" in output
    assert "Medium" in output
    assert "Low" in output

def test_audit_result_to_dict(sample_audit_result):
    data = sample_audit_result.to_dict()

    assert data["contract_name"] == "VulnerableContract"
    assert data["success"] is True
    assert data["cost_usd"] == 1.50
    assert data["duration_seconds"] == 120.0
    assert len(data["findings"]) == 1
    assert data["stats"]["total_findings"] == 1
    assert data["stats"]["verified_count"] == 1

def test_audit_result_to_json(sample_audit_result):
    json_str = sample_audit_result.to_json()
    data = json.loads(json_str)
    assert data["contract_name"] == "VulnerableContract"

def test_audit_result_to_sarif(sample_audit_result):
    sarif = sample_audit_result.to_sarif()

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

def test_finding_to_dict():
    finding = Finding(
        vulnerability_type=VulnerabilityType.FLASH_LOAN,
        severity=Severity.HIGH,
        title="Flash loan attack",
        description="Vulnerable to flash loan manipulation",
        confidence=0.88,
        verified=True,
    )

    data = finding.to_dict()

    assert data["vulnerability_type"] == "flash_loan"
    assert data["severity"] == "high"
    assert data["title"] == "Flash loan attack"
    assert data["confidence"] == 0.88
    assert data["verified"] is True
    assert "discovered_at" in data

def test_output_format_enum():
    assert OutputFormat.TEXT.value == "text"
    assert OutputFormat.JSON.value == "json"
    assert OutputFormat.SARIF.value == "sarif"
    assert OutputFormat.MARKDOWN.value == "markdown"

def test_sarif_rules_generation():
    formatter = SARIFFormatter()
    rules = formatter._build_rules()
    assert len(rules) > 0
    rule_ids = [rule["id"] for rule in rules]
    assert "reentrancy" in rule_ids
    assert "flash_loan" in rule_ids
    assert "access_control" in rule_ids
    assert "logic_error" in rule_ids

def test_formatters_handle_empty_findings():
    result = AuditResult(
        contract_name="CleanContract",
        contract_path=Path("/path/to/Clean.sol"),
        success=True,
        total_cost=0.50,
        total_time=30.0,
    )

    # text
    text_output = TextFormatter().format(result)
    assert "Total Findings: 0" in text_output

    # json
    json_output = JSONFormatter().format(result)
    data = json.loads(json_output)
    assert len(data["findings"]) == 0

    # sarif
    sarif_output = SARIFFormatter().format(result)
    sarif = json.loads(sarif_output)
    assert len(sarif["runs"][0]["results"]) == 0

    # markdown
    md_output = MarkdownFormatter().format(result)
    assert "Total Findings**: 0" in md_output

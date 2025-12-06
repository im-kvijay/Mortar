"""output formatters for audit results: text, json, sarif, markdown"""

from enum import Enum
from typing import Protocol, Dict, Any, List
import json
from pathlib import Path
from datetime import datetime

from src.models.findings import AuditResult, Finding, Severity, VulnerabilityType


class OutputFormat(Enum):
    """supported output formats"""
    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


class OutputFormatter(Protocol):
    """protocol for output formatters"""
    def format(self, result: AuditResult) -> str:
        """format an audit result"""
        ...


class TextFormatter:
    """human-readable text output (default terminal format)"""

    def format(self, result: AuditResult) -> str:
        """format audit result as human-readable text"""
        lines = []

#        # header
        lines.append("=" * 80)
        if result.success:
            lines.append("AUDIT SUCCESSFUL")
        else:
            lines.append("AUDIT FAILED")
        lines.append("=" * 80)

#        # basic info
        lines.append(f"Contract: {result.contract_name}")
        lines.append(f"Path: {result.contract_path}")
        if result.audit_id:
            lines.append(f"Audit ID: {result.audit_id}")
        lines.append(f"Timestamp: {result.timestamp.isoformat()}")

#        # error handling
        if not result.success and result.error_message:
            lines.append(f"\nError: {result.error_message}")
            lines.append("=" * 80)
            return "\n".join(lines)

#        # statistics
        lines.append(f"\nValidated Vulnerabilities: {len(result.validated_vulnerabilities)}")
        lines.append(f"Total Findings: {len(result.findings)}")
        lines.append(f"Research Quality: {result.research_quality:.2f}")

#        # vulnerabilities
        if result.validated_vulnerabilities:
            lines.append("\nVALIDATED VULNERABILITIES:")
            for i, vuln in enumerate(result.validated_vulnerabilities, 1):
                h = vuln['hypothesis']
                impact = vuln.get('impact')
                resolution = vuln.get('resolution')
                severity = impact.severity.value.upper() if impact else 'N/A'
                econ = impact.economic_impact_usd if impact else 0.0
                fix_complexity = resolution.fix_complexity.value if resolution else 'unknown'

                lines.append(f"\n{i}. [{severity}] {h.attack_type.upper()}")
                lines.append(f"   Description: {h.description}")
                lines.append(f"   Confidence: {h.confidence:.2f}")
                lines.append(f"   Economic Impact: ${econ:,.2f}")
                lines.append(f"   Fix Complexity: {fix_complexity}")
                if 'poc' in vuln:
                    lines.append(f"   PoC: {vuln['poc'].file_path}")
                if 'execution' in vuln:
                    lines.append(f"   Gas Used: {vuln['execution'].gas_used}")

#        # additional findings
        if result.findings:
            lines.append("\nADDITIONAL FINDINGS:")
            for i, finding in enumerate(result.findings, 1):
                lines.append(f"\n{i}. [{finding.severity.value.upper()}] {finding.title}")
                lines.append(f"   Type: {finding.vulnerability_type.value}")
                lines.append(f"   Confidence: {finding.confidence:.2f}")
                if finding.affected_functions:
                    lines.append(f"   Functions: {', '.join(finding.affected_functions)}")

#        # metadata
        lines.append(f"\n{'─' * 80}")
        lines.append(f"Total Cost: ${result.total_cost:.2f}")
        lines.append(f"Total Time: {result.total_time:.1f}s")
        if result.budget_degraded:
            lines.append("Budget degradation triggered")
        if result.dedup_saved:
            lines.append("Deduplication saved analysis time")
        lines.append("=" * 80)

        return "\n".join(lines)


class JSONFormatter:
    """json output for programmatic consumption"""

    def format(self, result: AuditResult) -> str:
        """format audit result as json"""
        return result.to_json()


class SARIFFormatter:
    """sarif 2.1.0 formatter for github code scanning and ide integration spec: https://docs.oasis-open...."""

    def format(self, result: AuditResult) -> str:
        """format audit result as sarif 2.1.0"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [self._build_run(result)]
        }
        return json.dumps(sarif, indent=2)

    def _build_run(self, result: AuditResult) -> Dict[str, Any]:
        """build sarif run object"""
        return {
            "tool": self._build_tool(),
            "results": self._build_results(result),
            "artifacts": self._build_artifacts(result),
            "invocations": [self._build_invocation(result)],
            "properties": {
                "auditId": result.audit_id,
                "totalCost": result.total_cost,
                "totalTime": result.total_time,
                "researchQuality": result.research_quality,
            }
        }

    def _build_tool(self) -> Dict[str, Any]:
        """build sarif tool object"""
        return {
            "driver": {
                "name": "Mortar-C",
                "version": "1.0.0",
                "informationUri": "https://github.com/im-kvijay/Mortar-C",
                "semanticVersion": "1.0.0",
                "organization": "Mortar-C Project",
                "shortDescription": {
                    "text": "Agentic Smart Contract Auditor"
                },
                "fullDescription": {
                    "text": "End-to-end agentic smart contract auditor with reproducible Foundry PoCs"
                },
                "rules": self._build_rules()
            }
        }

    def _build_rules(self) -> List[Dict[str, Any]]:
        """build sarif rules (one per vulnerability type)"""
        rules = []

#        # create rules for all vulnerability types
        vuln_descriptions = {
            VulnerabilityType.ACCESS_CONTROL: "Improper access control allows unauthorized access",
            VulnerabilityType.LOGIC_ERROR: "Business logic error enables unexpected behavior",
            VulnerabilityType.REENTRANCY: "Reentrancy vulnerability allows recursive calls",
            VulnerabilityType.FLASH_LOAN: "Flash loan manipulation vulnerability",
            VulnerabilityType.ORACLE_MANIPULATION: "Price oracle manipulation risk",
            VulnerabilityType.INPUT_VALIDATION: "Insufficient input validation",
            VulnerabilityType.UNCHECKED_CALL: "Unchecked external call return value",
            VulnerabilityType.INTEGER_OVERFLOW: "Integer overflow/underflow vulnerability",
            VulnerabilityType.FRONT_RUNNING: "Transaction front-running vulnerability",
            VulnerabilityType.DOS: "Denial of service vulnerability",
            VulnerabilityType.PRICE_MANIPULATION: "Price manipulation vulnerability",
            VulnerabilityType.READ_ONLY_REENTRANCY: "Read-only reentrancy vulnerability",
            VulnerabilityType.CROSS_FUNCTION_REENTRANCY: "Cross-function reentrancy",
            VulnerabilityType.CROSS_CONTRACT_REENTRANCY: "Cross-contract reentrancy",
        }

        for vuln_type in VulnerabilityType:
            rules.append({
                "id": vuln_type.value,
                "name": vuln_type.value.replace("_", " ").title(),
                "shortDescription": {
                    "text": vuln_descriptions.get(vuln_type, f"{vuln_type.value} vulnerability")
                },
                "fullDescription": {
                    "text": vuln_descriptions.get(vuln_type, f"{vuln_type.value} vulnerability detected by Mortar-C")
                },
                "help": {
                    "text": f"See Mortar-C documentation for {vuln_type.value} remediation guidance"
                },
                "defaultConfiguration": {
                    "level": "warning"
                },
                "properties": {
                    "tags": ["security", "smart-contract", vuln_type.value],
                    "precision": "high"
                }
            })

        return rules

    def _build_results(self, result: AuditResult) -> List[Dict[str, Any]]:
        """build sarif results array"""
        sarif_results = []

#        # add validated vulnerabilities
        for vuln in result.validated_vulnerabilities:
            h = vuln['hypothesis']
            impact = vuln.get('impact')
            resolution = vuln.get('resolution')

            sarif_result = {
                "ruleId": h.attack_type,
                "level": self._severity_to_sarif_level(impact.severity if impact else Severity.MEDIUM),
                "message": {
                    "text": h.description
                },
                "locations": self._build_locations(h, result),
                "properties": {
                    "confidence": h.confidence,
                    "economicImpact": impact.economic_impact_usd if impact else 0.0,
                    "fixComplexity": resolution.fix_complexity.value if resolution else "unknown",
                    "attackType": h.attack_type,
                }
            }

#            # add poc reference if available
            if 'poc' in vuln:
                sarif_result["properties"]["pocPath"] = str(vuln['poc'].file_path)

#            # add fix information if available
            if resolution and resolution.remediation_steps:
                sarif_result["fixes"] = [{
                    "description": {
                        "text": "\n".join(resolution.remediation_steps)
                    }
                }]

            sarif_results.append(sarif_result)

#        # add additional findings
        for finding in result.findings:
            sarif_result = {
                "ruleId": finding.vulnerability_type.value,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {
                    "text": finding.description or finding.title
                },
                "locations": self._build_finding_locations(finding, result),
                "properties": {
                    "confidence": finding.confidence,
                    "title": finding.title,
                }
            }

#            # add remediation if available
            if finding.remediation:
                sarif_result["fixes"] = [{
                    "description": {
                        "text": finding.remediation
                    }
                }]

            sarif_results.append(sarif_result)

        return sarif_results

    def _build_locations(self, hypothesis: Any, result: AuditResult) -> List[Dict[str, Any]]:
        """build sarif location objects from hypothesis"""
#        # default location pointing to contract
        return [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(result.contract_path),
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
                }
            },
            "message": {
                "text": f"Vulnerability in {result.contract_name}"
            }
        }]

    def _build_finding_locations(self, finding: Finding, result: AuditResult) -> List[Dict[str, Any]]:
        """build sarif location objects from finding"""
        locations = []

        if finding.line_numbers:
            for line_num in finding.line_numbers:
                locations.append({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(result.contract_path),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1
                        }
                    }
                })
        else:
#            # default location
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(result.contract_path),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1
                    }
                }
            })

        return locations

    def _build_artifacts(self, result: AuditResult) -> List[Dict[str, Any]]:
        """build sarif artifacts array"""
        return [{
            "location": {
                "uri": str(result.contract_path),
                "uriBaseId": "%SRCROOT%"
            },
            "length": -1,  # unknown
            "sourceLanguage": "solidity"
        }]

    def _build_invocation(self, result: AuditResult) -> Dict[str, Any]:
        """build sarif invocation object"""
        return {
            "executionSuccessful": result.success,
            "startTimeUtc": result.timestamp.isoformat(),
            "endTimeUtc": result.timestamp.isoformat(),
            "properties": {
                "totalCost": result.total_cost,
                "totalTime": result.total_time,
                "budgetDegraded": result.budget_degraded,
                "dedupSaved": result.dedup_saved,
            }
        }

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """convert mortar-c severity to sarif level"""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFORMATIONAL: "note",
        }
        return mapping.get(severity, "warning")


class MarkdownFormatter:
    """markdown report formatter"""

    def format(self, result: AuditResult) -> str:
        """format audit result as markdown"""
        lines = []

#        # header
        lines.append(f"# mortar-c audit report")
        lines.append(f"")

#        # metadata table
        lines.append(f"## audit information")
        lines.append(f"")
        lines.append(f"| Property | Value |")
        lines.append(f"|----------|-------|")
        lines.append(f"| Contract | `{result.contract_name}` |")
        lines.append(f"| Path | `{result.contract_path}` |")
        lines.append(f"| Audit ID | `{result.audit_id or 'N/A'}` |")
        lines.append(f"| Timestamp | {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
        lines.append(f"| Status | {'[OK] Success' if result.success else '[FAIL] Failed'} |")
        lines.append(f"| Total Cost | ${result.total_cost:.2f} |")
        lines.append(f"| Total Time | {result.total_time:.1f}s |")
        lines.append(f"| Research Quality | {result.research_quality:.2f} |")
        lines.append(f"")

#        # error handling
        if not result.success and result.error_message:
            lines.append(f"## error")
            lines.append(f"")
            lines.append(f"```")
            lines.append(f"{result.error_message}")
            lines.append(f"```")
            lines.append(f"")
            return "\n".join(lines)

#        # summary
        lines.append(f"## summary")
        lines.append(f"")
        lines.append(f"- **Validated Vulnerabilities**: {len(result.validated_vulnerabilities)}")
        lines.append(f"- **Total Findings**: {len(result.findings)}")
        lines.append(f"- **Attack Hypotheses**: {len(result.attack_hypotheses)}")
        lines.append(f"- **PoCs Generated**: {len(result.generated_pocs)}")
        lines.append(f"- **PoCs Executed**: {len(result.executed_pocs)}")
        lines.append(f"")

#        # severity breakdown
        if result.findings or result.validated_vulnerabilities:
            critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
            high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
            medium_count = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
            low_count = sum(1 for f in result.findings if f.severity == Severity.LOW)

            lines.append(f"### severity breakdown")
            lines.append(f"")
            lines.append(f"| Severity | Count |")
            lines.append(f"|----------|-------|")
            lines.append(f"| Critical | {critical_count} |")
            lines.append(f"| High | {high_count} |")
            lines.append(f"| Medium | {medium_count} |")
            lines.append(f"| Low | {low_count} |")
            lines.append(f"")

#        # validated vulnerabilities
        if result.validated_vulnerabilities:
            lines.append(f"## validated vulnerabilities")
            lines.append(f"")

            for i, vuln in enumerate(result.validated_vulnerabilities, 1):
                h = vuln['hypothesis']
                impact = vuln.get('impact')
                resolution = vuln.get('resolution')
                severity = impact.severity.value.upper() if impact else 'N/A'
                econ = impact.economic_impact_usd if impact else 0.0
                fix_complexity = resolution.fix_complexity.value if resolution else 'unknown'

                lines.append(f"### {i}. [{severity}] {h.attack_type.upper()}")
                lines.append(f"")
                lines.append(f"**Description**: {h.description}")
                lines.append(f"")
                lines.append(f"| Property | Value |")
                lines.append(f"|----------|-------|")
                lines.append(f"| Confidence | {h.confidence:.2f} |")
                lines.append(f"| Economic Impact | ${econ:,.2f} |")
                lines.append(f"| Fix Complexity | {fix_complexity} |")

                if 'poc' in vuln:
                    lines.append(f"| PoC Path | `{vuln['poc'].file_path}` |")
                if 'execution' in vuln:
                    lines.append(f"| Gas Used | {vuln['execution'].gas_used} |")

                lines.append(f"")

#                # remediation steps
                if resolution and resolution.remediation_steps:
                    lines.append(f"**Remediation Steps**:")
                    lines.append(f"")
                    for step in resolution.remediation_steps:
                        lines.append(f"- {step}")
                    lines.append(f"")

#        # additional findings
        if result.findings:
            lines.append(f"## additional findings")
            lines.append(f"")

            for i, finding in enumerate(result.findings, 1):
                lines.append(f"### {i}. [{finding.severity.value.upper()}] {finding.title}")
                lines.append(f"")
                lines.append(f"**Type**: {finding.vulnerability_type.value}")
                lines.append(f"")
                lines.append(f"**Description**: {finding.description}")
                lines.append(f"")

                if finding.affected_functions:
                    lines.append(f"**Affected Functions**: {', '.join(f'`{fn}`' for fn in finding.affected_functions)}")
                    lines.append(f"")

                if finding.remediation:
                    lines.append(f"**Remediation**: {finding.remediation}")
                    lines.append(f"")

                lines.append(f"**Confidence**: {finding.confidence:.2f}")
                lines.append(f"")

#        # footer
        lines.append(f"---")
        lines.append(f"")
        lines.append(f"*Generated by Mortar-C Agentic Auditor*")
        lines.append(f"")

        return "\n".join(lines)


def get_formatter(format_type: OutputFormat) -> OutputFormatter:
    """get formatter for specified output format args: format_type: output format enum returns: outputfo..."""
    formatters = {
        OutputFormat.TEXT: TextFormatter(),
        OutputFormat.JSON: JSONFormatter(),
        OutputFormat.SARIF: SARIFFormatter(),
        OutputFormat.MARKDOWN: MarkdownFormatter(),
    }
    return formatters[format_type]

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agent.logic_scanner import LogicVulnScanner  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph, NodeType  # noqa: E402

SAMPLE = """
pragma solidity ^0.8.17;
contract Exec {
    address public target;
    function execute(bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok, "fail");
    }
    function bump(uint256 a) external { target = address(uint160(a)); }
}
"""

SAMPLE_UPGRADE = """
pragma solidity ^0.8.17;
contract Up {
    address public impl;
    address public oracle;
    function upgradeTo(address newImpl) external {
        impl = newImpl;
        (bool ok,) = newImpl.delegatecall("");
        require(ok);
    }
    function setOracle(address o) external {
        oracle = o;
    }
    function initialize() external {
        impl = address(0xbeef);
    }
}
"""

def test_logic_scanner_detects_unprotected_call():
    scanner = LogicVulnScanner()
    kg = KnowledgeGraph("Exec")
    ci = {"name": "Exec", "state_vars": ["target"]}
    findings = scanner.scan(SAMPLE, ci, knowledge_graph=kg)
    assert findings, "logic scanner should produce findings"
    vuln_nodes = [n for n, data in kg.graph.nodes(data=True) if data.get("node_type") == NodeType.VULNERABILITY.value]
    assert vuln_nodes, "vulnerability node added to knowledge graph"

def test_logic_scanner_upgrade_oracle_setter():
    scanner = LogicVulnScanner(max_findings=10)
    kg = KnowledgeGraph("Up")
    ci = {"name": "Up", "state_vars": ["impl", "oracle"]}
    findings = scanner.scan(SAMPLE_UPGRADE, ci, knowledge_graph=kg)
    kinds = [f.attack_type for f in findings]
    assert "upgradeability" in kinds
    vuln_nodes = [n for n, data in kg.graph.nodes(data=True) if data.get("node_type") == NodeType.VULNERABILITY.value]
    assert any("upgrade" in n or "delegatecall" in n for n in vuln_nodes)


import unittest
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.cal.project_scanner import ProjectScanner
from src.agent.deployment_gen import SystemDeploymentGenerator
from src.research.system_invariant import SystemInvariantAnalyst
from src.agent.poc_generator import PoCGenerator
from src.agent.base_attacker import AttackHypothesis
from src.models.findings import Severity, ContractInterfaceSummary

class TestDVDBenchmark(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path("/tmp/dvd_benchmark")
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
        self.test_dir.mkdir(parents=True)
        
        # create mock dvd structure
        (self.test_dir / "src").mkdir()
        (self.test_dir / "test").mkdir()
        
        # create foundry.toml
        (self.test_dir / "foundry.toml").write_text("""
[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
""")

        # create puppetv3pool.sol
        self.pool_path = self.test_dir / "src/PuppetV3Pool.sol"
        self.pool_path.write_text("""
            contract PuppetV3Pool {
                function borrow(uint256 amount) external {
                    // Vulnerable logic
                }
            }
        """)
        
        # create token.sol
        self.token_path = self.test_dir / "src/Token.sol"
        self.token_path.write_text("""
            contract Token {
                function transfer(address to, uint256 amount) external returns (bool) {}
            }
        """)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_full_pipeline_simulation(self):
        # 1. Scan Project
        # we need to mock create_backend inside projectscanner or pass it if possible.
        # projectscanner uses create_backend internally for summarization.
        # we'll patch create_backend.
        with patch("src.cal.project_scanner.create_backend") as mock_create_backend, \
             patch("src.agent.poc_generator.PoCGenerator._compile_solidity", return_value=(True, "")) as mock_compile:
            mock_backend = MagicMock()
            mock_create_backend.return_value = mock_backend
            mock_backend.generate.return_value.text = '{"purpose": "Token contract", "external_api": [], "state_variables": [], "dependencies": [], "trust_assumptions": []}'
            
            scanner = ProjectScanner(self.test_dir)
            execution_order, summaries, pkg = scanner.scan()
            
            self.assertIn("PuppetV3Pool", summaries)
            self.assertIn("Token", summaries)
            
            # 2. Generate Deployment Script
            deploy_gen = SystemDeploymentGenerator(self.test_dir, execution_order, summaries)
            script = deploy_gen.generate_script()
            
            self.assertIn("contract SystemDeploy", script)
            self.assertIn("new Token()", script)
            self.assertIn("new PuppetV3Pool()", script)
            
            # 3. System Invariant Analysis
            mock_backend.generate.return_value.text = "NO_ISSUES" # simplify for now
            
            analyst = SystemInvariantAnalyst(pkg, backend=mock_backend)
            findings = analyst.analyze_system()
            # we expect 0 findings if we mock "no_issues", or we can mock a finding.
            
            # 4. PoC Generation (Integration Mode)
            poc_gen = PoCGenerator(backend=mock_backend, logger=MagicMock(), cost_manager=MagicMock(), output_dir=str(self.test_dir / "test"))
            
            hypothesis = AttackHypothesis(
                hypothesis_id="hyp_1",
                attack_type="Oracle Manipulation",
                description="Manipulate Uniswap oracle to drain pool",
                target_function="borrow",
                preconditions=["Pool has funds"],
                steps=["Swap large amount", "Borrow cheap"],
                expected_impact="Drain pool",
                confidence=0.9,
                requires_research=[],
                evidence=[]
            )
            mock_backend.generate.return_value.text = """
TEST_CODE:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {ExploitTestBase} from "src/poc/ExploitTestBase.sol";
import {PuppetV3Pool} from "src/PuppetV3Pool.sol";

contract ExploitTest is ExploitTestBase {
    PuppetV3Pool target;
    function setUp() public override {
        super.setUp();
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"));
        target = PuppetV3Pool(makeAddr("target"));
    }
    function testExploit() public {
        target.borrow(100);
    }
}
```
EXPLOIT_CONTRACT:
```solidity
N/A
```
EXPLANATION:
Exploit
"""
            
            poc = poc_gen.generate(
                hypothesis, 
                contract_source=self.pool_path.read_text(), 
                contract_info={"name": "PuppetV3Pool", "file_path": str(self.pool_path)},
                integration_mode=True
            )
            
            self.assertIsNotNone(poc)
            self.assertIn("vm.createSelectFork", poc.test_code)

if __name__ == '__main__':
    unittest.main()

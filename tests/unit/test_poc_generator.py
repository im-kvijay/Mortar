import re
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from utils.logging import ResearchLogger  # noqa: E402
from utils.cost_manager import CostManager  # noqa: E402
from utils.llm_backend.base import LLMBackend, LLMResponse  # noqa: E402
from agent.poc_generator import PoCGenerator  # noqa: E402

class DummyBackend(LLMBackend):
    def __init__(self):
        super().__init__("dummy-model")

    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        return LLMResponse(text="TEST_CODE:\n```solidity\n```\nEXPLOIT_CONTRACT:\n```solidity\nN/A\n```\nEXPLANATION:\nN/A")

    def is_available(self) -> bool:
        return True

class TestPoCGeneratorImpactSignal(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.logger = ResearchLogger(project_root=str(PROJECT_ROOT))
        self.generator = PoCGenerator(
            backend=DummyBackend(),
            logger=self.logger,
            cost_manager=CostManager(),
            output_dir=self.tempdir.name,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_injects_impact_inside_test_function(self) -> None:
        baseline = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {ExploitTestBase} from "src/poc/ExploitTestBase.sol";
contract Example is ExploitTestBase {
    function setUp() public override {
        super.setUp();
    }

    function test_manifest_strategy() public {
        revert("FALLBACK_POC_UNAVAILABLE");
    }
}
""".strip()

        result = self.generator._ensure_impact_signal(baseline)
        self.assertRegex(
            result,
            r'revert\("FALLBACK_POC_UNAVAILABLE"\);\s*\n\s*markImpact\("MARKET_CORRUPTION"\);\s*\n\s*\}',
        )
        self.assertEqual(result.count('markImpact("MARKET_CORRUPTION");'), 1)

    def test_specialized_template_detects_puppet_v3(self) -> None:
        contract_info = {"path": "/tmp/training/damn-vulnerable-defi/src/puppet-v3/PuppetV3Pool.sol"}
        template = self.generator._maybe_specialized_template(contract_info)
        self.assertIsNotNone(template)
        assert template is not None
        self.assertIn("PuppetV3PriceManipulationTest", template)
        self.assertIn("V3OracleMock", template)

if __name__ == "__main__":
    unittest.main()

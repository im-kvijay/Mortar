"""s for PoC Sandbox"""

import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agent.poc_sandbox import (  # noqa: E402
    make_sandbox,
    write_test,
    run_forge,
    cleanup_sandbox,
    _ensure_symlink,
)

class TestPoCandbox(unittest.TestCase):
    """Test PoC sandbox functionality"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_sandbox_"))
        self.repo_root = self.temp_dir / "repo"
        self.repo_root.mkdir(parents=True)

    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_make_sandbox_creates_directories(self):
        # create minimal repo structure
        (self.repo_root / "lib" / "forge-std").mkdir(parents=True)
        (self.repo_root / "src" / "poc").mkdir(parents=True)

        with patch('src.agent.poc_sandbox.config') as mock_config:
            mock_config.DVD_DIR = self.temp_dir / "dvd"
            mock_config.TRAINING_DIR = self.temp_dir / "training"
            mock_config.DVD_DIR.mkdir(parents=True)
            mock_config.TRAINING_DIR.mkdir(parents=True)

            sandbox_root, test_dir = make_sandbox(self.repo_root)
            self.assertTrue(sandbox_root.exists())
            self.assertTrue(test_dir.exists())
            self.assertTrue((sandbox_root / "test" / ".generated").exists())
            self.assertTrue((sandbox_root / "src").exists())
            self.assertTrue((sandbox_root / "lib").exists())
            self.assertTrue((sandbox_root / "foundry.toml").exists())
            foundry_content = (sandbox_root / "foundry.toml").read_text()
            self.assertIn('src = "src"', foundry_content)
            self.assertIn('test = "test"', foundry_content)
            self.assertIn('evm_version = "cancun"', foundry_content)
            self.assertIn("remappings", foundry_content)

            # cleanup
            cleanup_sandbox(sandbox_root)

    def test_make_sandbox_copies_harness(self):
        # create harness structure
        harness_src = self.repo_root / "src" / "poc"
        harness_src.mkdir(parents=True)
        (harness_src / "ExploitTestBase.sol").write_text("// Base harness")

        # create critical subdirectories
        (harness_src / "uniswap").mkdir(parents=True)
        (harness_src / "uniswap" / "UniswapV2Flash.sol").write_text("// Uniswap")
        (harness_src / "modules").mkdir(parents=True)
        (harness_src / "modules" / "Module.sol").write_text("// Module")

        (self.repo_root / "lib" / "forge-std").mkdir(parents=True)

        with patch('src.agent.poc_sandbox.config') as mock_config:
            mock_config.DVD_DIR = self.temp_dir / "dvd"
            mock_config.TRAINING_DIR = self.temp_dir / "training"
            mock_config.DVD_DIR.mkdir(parents=True)
            mock_config.TRAINING_DIR.mkdir(parents=True)

            sandbox_root, _ = make_sandbox(self.repo_root)
            self.assertTrue((sandbox_root / "src" / "poc" / "ExploitTestBase.sol").exists())
            self.assertTrue((sandbox_root / "src" / "poc" / "uniswap" / "UniswapV2Flash.sol").exists())
            self.assertTrue((sandbox_root / "src" / "poc" / "modules" / "Module.sol").exists())

            cleanup_sandbox(sandbox_root)

    def test_write_test_creates_file(self):
        sandbox_root = self.temp_dir / "sandbox"
        (sandbox_root / "test" / ".generated").mkdir(parents=True)

        solidity_code = """
        // SPDX-License-Identifier: MIT
        contract TestContract {
            function test() public {}
        }
        """

        test_path = write_test(sandbox_root, "TestPoC.sol", solidity_code)

        self.assertTrue(test_path.exists())
        self.assertEqual(test_path.name, "TestPoC.sol")
        self.assertEqual(test_path.parent.name, ".generated")
        self.assertIn("TestContract", test_path.read_text())

    def test_write_test_adds_sol_extension(self):
        sandbox_root = self.temp_dir / "sandbox"
        (sandbox_root / "test" / ".generated").mkdir(parents=True)

        test_path = write_test(sandbox_root, "TestPoC", "contract Test {}")

        self.assertEqual(test_path.name, "TestPoC.sol")
        self.assertTrue(test_path.exists())

    def test_write_test_sanitizes_filename(self):
        sandbox_root = self.temp_dir / "sandbox"
        (sandbox_root / "test" / ".generated").mkdir(parents=True)

        # try path traversal - should raise valueerror (security fix)
        with self.assertRaises(ValueError) as ctx:
            write_test(
                sandbox_root,
                "../../malicious/Test.sol",
                "contract Test {}"
            )
        self.assertIn("Invalid", str(ctx.exception))

    def test_write_test_prevents_path_traversal(self):
        sandbox_root = self.temp_dir / "sandbox"
        (sandbox_root / "test" / ".generated").mkdir(parents=True)

        # create a file outside sandbox
        outside_dir = self.temp_dir / "outside"
        outside_dir.mkdir()

        # try to write outside sandbox - should raise valueerror
        # security fix: path traversal attempts are now rejected
        with self.assertRaises(ValueError) as ctx:
            write_test(
                sandbox_root,
                "../../../outside/evil.sol",
                "contract Evil {}"
            )
        self.assertIn("Invalid", str(ctx.exception))
        self.assertFalse((outside_dir / "evil.sol").exists())

    def test_cleanup_sandbox_removes_directory(self):
        sandbox_root = self.temp_dir / "test_cleanup"
        sandbox_root.mkdir(parents=True)
        (sandbox_root / "test.txt").write_text("test")

        self.assertTrue(sandbox_root.exists())

        cleanup_sandbox(sandbox_root)

        self.assertFalse(sandbox_root.exists())

    def test_cleanup_sandbox_ignores_errors(self):
        # cleanup non-existent directory should not raise
        cleanup_sandbox(Path("/tmp/nonexistent_sandbox_12345"))

    def test_run_forge_sets_offline_mode(self):
        sandbox_root = self.temp_dir / "sandbox"
        sandbox_root.mkdir()

        with patch('subprocess.run') as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = "Success"
            mock_process.stderr = ""
            mock_run.return_value = mock_process

            run_forge(sandbox_root, timeout_sec=10)
            call_kwargs = mock_run.call_args[1]
            env = call_kwargs['env']
            self.assertEqual(env.get('FOUNDRY_OFFLINE'), 'true')
            self.assertEqual(env.get('NO_PROXY'), '*')
            self.assertEqual(env.get('HTTP_PROXY'), '')
            self.assertEqual(env.get('HTTPS_PROXY'), '')

    def test_run_forge_passes_arguments(self):
        sandbox_root = self.temp_dir / "sandbox"
        sandbox_root.mkdir()

        with patch('subprocess.run') as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = ""
            mock_process.stderr = ""
            mock_run.return_value = mock_process

            run_forge(
                sandbox_root,
                timeout_sec=10,
                args=["--match-test", "test_exploit"]
            )
            call_args = mock_run.call_args[0][0]
            self.assertIn("--match-test", call_args)
            self.assertIn("test_exploit", call_args)

    def test_ensure_symlink_creates_link(self):
        src = self.temp_dir / "source"
        src.mkdir()
        dst = self.temp_dir / "dest"

        _ensure_symlink(src, dst)

        self.assertTrue(dst.exists())
        self.assertTrue(dst.is_symlink())
        self.assertEqual(dst.resolve(), src.resolve())

    def test_ensure_symlink_skips_nonexistent_source(self):
        src = self.temp_dir / "nonexistent"
        dst = self.temp_dir / "dest"

        _ensure_symlink(src, dst)

        self.assertFalse(dst.exists())

    def test_ensure_symlink_skips_existing_destination(self):
        src = self.temp_dir / "source"
        src.mkdir()
        dst = self.temp_dir / "dest"
        dst.mkdir()

        _ensure_symlink(src, dst)
        self.assertTrue(dst.exists())
        self.assertFalse(dst.is_symlink())

if __name__ == '__main__':
    unittest.main()

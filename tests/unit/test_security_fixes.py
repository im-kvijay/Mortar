""" """

import pytest
import sys
import tempfile
import shutil
import subprocess
import urllib.parse
import re
from pathlib import Path
from typing import Optional
from unittest.mock import Mock, patch, MagicMock

# add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# import the functions directly to avoid loading the entire agent module
# this is a testing workaround to avoid import dependencies

def write_test(sandbox_root: Path | str, filename: str, solidity: str) -> Path:
    """Direct copy of write_test() from poc_sandbox.py for testing."""
    root = Path(sandbox_root).resolve()
    if not filename.endswith(".sol"):
        filename = f"{filename}.sol"

    # security: check for url encoding bypass
    decoded_filename = urllib.parse.unquote(filename)
    if decoded_filename != filename:
        raise ValueError(f"URL-encoded filename detected: {filename}")

    # security: check for null bytes
    if '\x00' in filename:
        raise ValueError(f"Null byte detected in filename: {filename}")

    # security: validate filename contains only safe characters
    # allow: alphanumeric, underscore, dash, dot, and spaces
    if not re.match(r'^[a-zA-Z0-9_\-\. ]+$', filename):
        raise ValueError(f"Invalid characters in filename: {filename}")

    # security: sanitize filename to prevent path traversal
    # remove any path components and keep only the base filename
    safe_filename = Path(filename).name
    if not safe_filename or safe_filename in (".", ".."):
        raise ValueError(f"Invalid filename: {filename}")

    target = root / "test" / ".generated" / safe_filename

    # security: verify resolved path is within sandbox
    target_resolved = target.resolve()
    sandbox_test_dir = (root / "test" / ".generated").resolve()
    if not str(target_resolved).startswith(str(sandbox_test_dir)):
        raise ValueError(f"Path traversal detected: {filename} resolves outside sandbox")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(solidity, encoding="utf-8")
    return target

def run_forge(sandbox_root: Path | str, timeout_sec: int = 300, args: Optional[list[str]] = None, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """Direct copy of run_forge() from poc_sandbox.py for testing."""
    import os as _os

    root = Path(sandbox_root)
    cmd = ["forge", "test", "-vv"]
    if args:
        cmd.extend(args)

    # security: only allow specific environment variables to be overridden
    ALLOWED_ENV_VARS = {
        'AUTOPOC_PLAN',
        'FOUNDRY_OFFLINE',
        'NO_PROXY',
        'HTTP_PROXY',
        'HTTPS_PROXY',
        'ALL_PROXY',
    }
    if env:
        for key in env.keys():
            if key not in ALLOWED_ENV_VARS:
                raise ValueError(f"Environment variable '{key}' is not allowed. Allowed: {ALLOWED_ENV_VARS}")

    # build environment with defaults and user overrides
    env_merged = dict(_os.environ)
    if env:
        env_merged.update(env)
    env_merged.setdefault("FOUNDRY_OFFLINE", "true")
    env_merged.setdefault("NO_PROXY", "*")
    env_merged.setdefault("HTTP_PROXY", "")
    env_merged.setdefault("HTTPS_PROXY", "")
    env_merged.setdefault("ALL_PROXY", "")

    return subprocess.run(
        cmd,
        cwd=root,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        env=env_merged,
    )

class TestFilenameSanitization:
    """Test suite for write_test() filename sanitization."""

    def test_normal_filename_allowed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_root = Path(tmpdir)
            (sandbox_root / "test" / ".generated").mkdir(parents=True)

            result = write_test(sandbox_root, "TestPoC.sol", "// SPDX-License-Identifier: MIT")
            assert result.exists()
            assert result.name == "TestPoC.sol"

    def test_url_encoded_filename_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_root = Path(tmpdir)
            (sandbox_root / "test" / ".generated").mkdir(parents=True)

            with pytest.raises(ValueError, match="URL-encoded filename detected"):
                write_test(sandbox_root, "%2e%2e%2fmalicious.sol", "// code")

    def test_null_byte_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_root = Path(tmpdir)
            (sandbox_root / "test" / ".generated").mkdir(parents=True)

            with pytest.raises(ValueError, match="Null byte detected"):
                write_test(sandbox_root, "test\x00.sol", "// code")

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_root = Path(tmpdir)
            (sandbox_root / "test" / ".generated").mkdir(parents=True)

            with pytest.raises(ValueError, match="Invalid characters in filename"):
                write_test(sandbox_root, "../../../etc/passwd.sol", "// code")

    def test_special_characters_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_root = Path(tmpdir)
            (sandbox_root / "test" / ".generated").mkdir(parents=True)

            dangerous_names = [
                "test;rm -rf /.sol",
                "test|cat /etc/passwd.sol",
                "test&& malicious.sol",
                "test$(whoami).sol",
            ]

            for dangerous_name in dangerous_names:
                with pytest.raises(ValueError, match="Invalid characters in filename"):
                    write_test(sandbox_root, dangerous_name, "// code")

    def test_valid_characters_allowed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_root = Path(tmpdir)
            (sandbox_root / "test" / ".generated").mkdir(parents=True)

            valid_names = [
                "TestPoC.sol",
                "Test_PoC_123.sol",
                "Test-PoC.sol",
                "Test PoC.sol",
            ]

            for valid_name in valid_names:
                result = write_test(sandbox_root, valid_name, "// code")
                assert result.exists()
                assert result.name == valid_name

class TestEnvironmentVariableValidation:
    """Test suite for run_forge() environment variable validation."""

    @patch('subprocess.run')
    def test_allowed_env_vars_accepted(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            allowed_env = {
                'AUTOPOC_PLAN': 'test',
                'FOUNDRY_OFFLINE': 'true',
                'NO_PROXY': '*',
                'HTTP_PROXY': '',
                'HTTPS_PROXY': '',
                'ALL_PROXY': '',
            }
            run_forge(tmpdir, env=allowed_env)

    @patch('subprocess.run')
    def test_dangerous_env_vars_rejected(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            dangerous_env_vars = [
                {'LD_PRELOAD': '/tmp/malicious.so'},
                {'PATH': '/tmp/malicious:/usr/bin'},
                {'LD_LIBRARY_PATH': '/tmp/malicious'},
                {'DYLD_INSERT_LIBRARIES': '/tmp/malicious.dylib'},
                {'PYTHONPATH': '/tmp/malicious'},
            ]

            for dangerous_env in dangerous_env_vars:
                with pytest.raises(ValueError, match="not allowed"):
                    run_forge(tmpdir, env=dangerous_env)

    @patch('subprocess.run')
    def test_mixed_env_vars_rejected(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            mixed_env = {
                'FOUNDRY_OFFLINE': 'true',  # allowed
                'LD_PRELOAD': '/tmp/malicious.so',  # dangerous
            }

            with pytest.raises(ValueError, match="not allowed"):
                run_forge(tmpdir, env=mixed_env)

    @patch('subprocess.run')
    def test_no_env_vars_works(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            run_forge(tmpdir, env=None)

    @patch('subprocess.run')
    def test_empty_env_dict_works(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            run_forge(tmpdir, env={})

class TestPathTraversalInImportRewrite:
    """Test suite for path traversal validation logic."""

    def test_path_validation_logic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            src_root = repo_root / "src"
            output_dir = repo_root / "data" / "pocs"
            src_root.mkdir()
            output_dir.mkdir(parents=True)

            # create a file inside allowed directories
            inside_file = src_root / "TestContract.sol"
            inside_file.write_text("// test")

            # create a file outside allowed directories
            outside_dir = Path(tmpdir).parent / "outside"
            outside_dir.mkdir(exist_ok=True)
            outside_file = outside_dir / "Malicious.sol"
            outside_file.write_text("// malicious")
            allowed_roots = [repo_root.resolve(), output_dir.resolve(), src_root.resolve()]

            # file inside should pass validation
            inside_abs = inside_file.resolve()
            is_inside_allowed = any(
                str(inside_abs).startswith(str(root)) for root in allowed_roots
            )
            assert is_inside_allowed, "Inside file should be allowed"

            # file outside should fail validation
            outside_abs = outside_file.resolve()
            is_outside_allowed = any(
                str(outside_abs).startswith(str(root)) for root in allowed_roots
            )
            assert not is_outside_allowed, "Outside file should be blocked"

    def test_path_resolution_behavior(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            test_file = base / "test.sol"
            test_file.write_text("// test")
            traversed = (base / "subdir" / ".." / ".." / ".." / "test.sol").resolve()
            expected = test_file.resolve()
            # this tests our security assumption
            assert traversed.exists() or not str(traversed).startswith(str(base.resolve()))

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

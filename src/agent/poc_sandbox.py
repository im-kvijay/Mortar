# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Set

from config import config

logger = logging.getLogger(__name__)

# global tracking of active sandboxes for cleanup
_active_sandboxes: Set[Path] = set()
_sandbox_lock = threading.Lock()
_cleanup_registered = False


def _ensure_symlink(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    if dst.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(src, dst, target_is_directory=True)


def _cleanup_all_sandboxes():
    """Clean up all active sandboxes (called on shutdown)"""
    global _active_sandboxes
    with _sandbox_lock:
        if _active_sandboxes:
            logger.info(f"Cleaning up {len(_active_sandboxes)} active sandboxes...")
            for sandbox_path in list(_active_sandboxes):
                try:
                    cleanup_sandbox(sandbox_path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup sandbox {sandbox_path}: {e}")
            _active_sandboxes.clear()
            logger.debug("All sandboxes cleaned up")


def make_sandbox(repo_root: str | Path) -> Tuple[Path, Path]:
    global _cleanup_registered
    repo = Path(repo_root).resolve()
    sandbox = Path(tempfile.mkdtemp(prefix="poc_sbx_"))

    # track this sandbox for cleanup
    with _sandbox_lock:
        _active_sandboxes.add(sandbox)

        # register cleanup on first sandbox creation
        if not _cleanup_registered:
            try:
                from utils.shutdown import register_cleanup
                register_cleanup(_cleanup_all_sandboxes, "sandbox_cleanup")
                _cleanup_registered = True
                logger.debug("Sandbox cleanup handler registered")
            except ImportError:
                logger.warning("Shutdown module not available - sandboxes may not cleanup on exit")

    logger.debug(f"Created sandbox: {sandbox}")

    test_dir = sandbox / "test" / ".generated"
    test_dir.mkdir(parents=True, exist_ok=True)
    # also host static tests under sandbox/test
    (sandbox / "test").mkdir(parents=True, exist_ok=True)

    src_dir = sandbox / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    harness_src = repo / "src" / "poc"
    if harness_src.exists():
        # copy all subdirectories recursively to ensure complete harness availability
        shutil.copytree(harness_src, src_dir / "poc", dirs_exist_ok=True)
        # explicitly verify critical subdirectories are present
        for critical_dir in ["uniswap", "modules"]:
            src_subdir = harness_src / critical_dir
            dst_subdir = src_dir / "poc" / critical_dir
            if src_subdir.exists() and not dst_subdir.exists():
                shutil.copytree(src_subdir, dst_subdir, dirs_exist_ok=True)
    vm_src = repo / "src" / "pocvm"
    if vm_src.exists():
        shutil.copytree(vm_src, src_dir / "pocvm", dirs_exist_ok=True)

    # static runner tests (optional)
    runner_test = repo / "test" / "AutoPoCRunner.t.sol"
    if runner_test.exists():
        shutil.copy2(runner_test, sandbox / "test" / "AutoPoCRunner.t.sol")

    lib_dir = sandbox / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    _ensure_symlink(repo / "lib" / "forge-std", lib_dir / "forge-std")

    dvd_root = config.DVD_DIR.resolve()
    training_root = config.TRAINING_DIR.resolve()
    lido_core_contracts = (repo / "external" / "lido-core" / "contracts").resolve()

    dvd_path = dvd_root.as_posix().rstrip("/")
    training_path = training_root.as_posix().rstrip("/")
    lido_core_path = lido_core_contracts.as_posix().rstrip("/")

    remappings: List[str] = [
        "forge-std/=lib/forge-std/src/",
        f"openzeppelin/={dvd_path}/lib/openzeppelin-contracts/contracts/",
        f"openzeppelin-contracts/={dvd_path}/lib/openzeppelin-contracts/contracts/",
        f"@openzeppelin/contracts/={dvd_path}/lib/openzeppelin-contracts/contracts/",
        f"@openzeppelin/contracts-upgradeable/={dvd_path}/lib/openzeppelin-contracts-upgradeable/contracts/",
        f"openzeppelin-contracts-upgradeable/={dvd_path}/lib/openzeppelin-contracts-upgradeable/",
        f"@uniswap/v3-core/={dvd_path}/lib/v3-core/",
        f"@uniswap/v3-periphery/={dvd_path}/lib/v3-periphery/",
        f"@uniswap/v2-core/={dvd_path}/lib/v2-core/",
        f"solmate/={dvd_path}/lib/solmate/src/",
        f"solmate/src/={dvd_path}/lib/solmate/src/",
        f"solady/={dvd_path}/lib/solady/src/",
        f"solady/src/={dvd_path}/lib/solady/src/",
        f"murky/={dvd_path}/lib/murky/src/",
        f"permit2/={dvd_path}/lib/permit2/src/",
        f"safe-smart-account/={dvd_path}/lib/safe-smart-account/",
        f"@safe-global/safe-smart-account/={dvd_path}/lib/safe-smart-account/",
        f"dvd/={dvd_path}/",
        f"training/={training_path}/",
        f"lido/={lido_core_path}/",
        f"lido-core/={lido_core_path}/",
        "poc/=src/poc/",
        "pocmods/=src/poc/modules/",
        "src/=src/",
    ]

    allow_paths = {
        str(repo),
        dvd_path,
        f"{dvd_path}/lib",
        training_path,
        lido_core_path,
    }

    remap_block = ",\n".join(f'  "{entry}"' for entry in remappings)
    allow_block = ",\n".join(f'  "{path}"' for path in sorted(allow_paths))

    foundry_toml = (
        "[profile.default]\n"
        'src = "src"\n'
        'test = "test"\n'
        'libs = ["lib"]\n'
        "optimizer = true\n"
        "optimizer_runs = 2000\n"
        'evm_version = "cancun"\n'
        "auto_detect_solc = true\n"
        "remappings = [\n"
        f"{remap_block}\n"
        "]\n"
        "allow_paths = [\n"
        f"{allow_block}\n"
        "]\n"
    )
    (sandbox / "foundry.toml").write_text(foundry_toml, encoding="utf-8")

    return sandbox, test_dir


def write_test(sandbox_root: Path | str, filename: str, solidity: str) -> Path:
    import urllib.parse
    import re

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
    root = Path(sandbox_root)
    # use -vv to reduce trace identification that can trigger remote signature fetches
    cmd = ["forge", "test", "-vv"]
    if args:
        cmd.extend(args)
    import os as _os

    # security: only allow specific environment variables to be overridden
    ALLOWED_ENV_VARS = {
        'AUTOPOC_PLAN',
        'FOUNDRY_OFFLINE',
        'NO_PROXY',
        'HTTP_PROXY',
        'HTTPS_PROXY',
        'ALL_PROXY',
    }

    # validate user-provided environment variables
    if env:
        for key in env.keys():
            if key not in ALLOWED_ENV_VARS:
                raise ValueError(f"Environment variable '{key}' is not allowed. Allowed: {ALLOWED_ENV_VARS}")

    # build environment with defaults and user overrides
    env_merged = dict(_os.environ)
    if env:
        env_merged.update(env)
    env_merged.setdefault("FOUNDRY_OFFLINE", "true")
    # prevent proxy lookups that can trigger reqwest/system proxy crashes on macos
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


def cleanup_sandbox(sandbox_root: Path | str) -> None:
    """
    Clean up a sandbox directory.

    Args:
        sandbox_root: Path to sandbox directory to remove

    Note: Also removes from active sandboxes tracking.
    """
    sandbox_path = Path(sandbox_root)
    with _sandbox_lock:
        _active_sandboxes.discard(sandbox_path)
    shutil.rmtree(sandbox_path, ignore_errors=True)
    logger.debug(f"Cleaned up sandbox: {sandbox_path}")

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from verification.fuzzing_gen import FuzzingGenerator  # noqa: E402

def test_fuzzing_handler_generation(tmp_path: Path):
    # write a minimal target contract to import
    target = tmp_path / "Vault.sol"
    target.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.25;\ncontract Vault {bool public paused; uint256 public totalAssets; uint256 public totalDebt;}\n",
        encoding="utf-8",
    )
    gen = FuzzingGenerator(project_root=tmp_path)
    invariants = ["totalAssets >= totalDebt", "paused == false"]
    out = gen.generate_handler("Vault", invariants, prefix="InvGen", source_import=str(target))
    assert out.exists()
    content = out.read_text()
    assert "contract InvGen_Vault" in content
    assert "invariant_0" in content and "invariant_1" in content

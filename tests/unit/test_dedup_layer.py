import textwrap
from pathlib import Path

from cal.deduplication import DeduplicationLayer

def _make_kb(source_text: str, functions=None) -> object:
    """Create a lightweight KB stub."""
    if functions is None:
        functions = []

    class _KB:
        contract_knowledge = {
            "Original": {
                "source": textwrap.dedent(source_text).strip(),
                "contract_info": {"path": "Original.sol", "functions": functions},
                "discoveries": [{"type": "logic"}],
                "quality_score": 0.9,
            }
        }

    return _KB()

def test_dedup_off_returns_no_match(tmp_path):
    layer = DeduplicationLayer(kb=None, mode="off", cache_dir=tmp_path / "off-cache")
    match = layer.check_duplicate(
        contract_source="contract Foo { function ping() public {} }",
        contract_info={"name": "Foo"},
        contract_name="Foo",
    )
    assert not match.is_duplicate
    assert match.match_type == "disabled"

def test_dedup_exact_mode_only_uses_hash(tmp_path):
    layer = DeduplicationLayer(kb=None, mode="exact", cache_dir=tmp_path / "exact-cache")
    source = "contract A { function ping() public {} }"
    layer.register_contract("Original", source, {"path": "Original.sol"})
    identical = layer.check_duplicate(
        contract_source=source,
        contract_info={"name": "Clone"},
        contract_name="Clone",
    )
    assert identical.is_duplicate
    assert identical.transfer_strategy == "copy_all"
    different = layer.check_duplicate(
        contract_source=source.replace("ping", "pong"),
        contract_info={"name": "Variant"},
        contract_name="Variant",
    )
    assert not different.is_duplicate
    assert different.match_type == "hash_only_miss"

def test_dedup_hints_mode_surfaces_similarity(tmp_path):
    shared_body = """
    contract Base {
        function ping() public {}
        function pong(uint256 amount) public returns (uint256) {
            return amount;
        }
        function onlyOwner() external {}
    }
    """
    kb = _make_kb(
        shared_body,
        functions=[
            {"name": "ping"},
            {"name": "pong"},
            {"name": "onlyOwner"},
        ],
    )
    layer = DeduplicationLayer(kb=kb, mode="hints", cache_dir=tmp_path / "hints-cache")
    match = layer.check_duplicate(
        contract_source=shared_body.replace("Base", "Clone", 1),
        contract_info={"name": "Clone"},
        contract_name="Clone",
    )
    assert match.is_duplicate
    assert match.transfer_strategy in {"transfer_with_adjustment", "transfer_patterns_only"}

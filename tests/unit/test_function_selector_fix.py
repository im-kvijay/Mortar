""" """
import pytest
from src.cal.attack_surface import _compute_function_selector

def test_function_selector_correctness():
    # these are verified against ethereum's canonical function selectors
    test_cases = [
        # erc20 standard functions
        ("transfer(address,uint256)", "0xa9059cbb"),
        ("transferFrom(address,address,uint256)", "0x23b872dd"),
        ("approve(address,uint256)", "0x095ea7b3"),
        ("balanceOf(address)", "0x70a08231"),
        ("allowance(address,address)", "0xdd62ed3e"),

        # common defi functions
        ("deposit(uint256)", "0xb6b55f25"),
        ("withdraw(uint256)", "0x2e1a7d4d"),
        ("flashLoan(address,address,uint256,bytes)", "0x5cffe9de"),

        # access control
        ("renounceOwnership()", "0x715018a6"),
        ("transferOwnership(address)", "0xf2fde38b"),
    ]

    for signature, expected in test_cases:
        computed = _compute_function_selector(signature)
        assert computed == expected, (
            f"Selector mismatch for {signature}\n"
            f"Expected: {expected}\n"
            f"Got:      {computed}\n"
            f"This indicates SHA3-256 is being used instead of Keccak-256!"
        )

def test_function_selector_not_sha3():
    import hashlib

    signature = "transfer(address,uint256)"

    # what we get (should be keccak-256)
    computed = _compute_function_selector(signature)

    # what sha3-256 would produce (wrong)
    sha3_hash = hashlib.sha3_256(signature.encode()).digest()
    wrong_selector = "0x" + sha3_hash[:4].hex()
    assert computed != wrong_selector, (
        f"Function selector matches SHA3-256 output!\n"
        f"This means we're still using the wrong hash function.\n"
        f"Computed:  {computed}\n"
        f"SHA3-256:  {wrong_selector}\n"
        f"Expected:  0xa9059cbb (Keccak-256)"
    )

    # and the computed one should be correct
    assert computed == "0xa9059cbb", (
        f"Selector should be 0xa9059cbb, got {computed}"
    )

def test_function_selector_edge_cases():

    # function with no parameters
    assert _compute_function_selector("name()") == "0x06fdde03"
    assert _compute_function_selector("symbol()") == "0x95d89b41"
    assert _compute_function_selector("decimals()") == "0x313ce567"

    # function with complex types
    assert _compute_function_selector("multicall(bytes[])") == "0xac9650d8"

    # function with tuple types
    selector = _compute_function_selector("swap((address,uint256),uint256)")
    assert selector.startswith("0x"), "Selector should start with 0x"
    assert len(selector) == 10, "Selector should be 10 chars (0x + 8 hex digits)"

def test_library_availability():

    has_pycryptodome = False
    has_web3 = False

    try:
        from Crypto.Hash import keccak
        has_pycryptodome = True
    except ImportError:
        pass

    try:
        from web3 import Web3
        has_web3 = True
    except ImportError:
        pass

    assert has_pycryptodome or has_web3, (
        "Neither pycryptodome nor web3.py is available!\n"
        "Install with: pip install pycryptodome\n"
        "Function selectors will be INCORRECT without these libraries."
    )

if __name__ == "__main__":
    # run tests with verbose output
    pytest.main([__file__, "-v", "-s"])

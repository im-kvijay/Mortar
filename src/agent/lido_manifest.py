# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

from eth_utils import to_checksum_address


@lru_cache(maxsize=1)
def _load_manifest() -> Dict[str, Dict[str, str]]:
    repo_root = Path(__file__).resolve().parents[2]
    manifest_path = repo_root / "external" / "lido-core" / "deployed-mainnet.json"
    mapping: Dict[str, Dict[str, str]] = {}
    if not manifest_path.exists():
        return mapping
    try:
        data = json.loads(manifest_path.read_text())
    except Exception:
        return mapping

    for val in data.values():
        if not isinstance(val, dict):
            continue
        contract = val.get("contract")
        impl_addr = val.get("implementation", {}).get("address") if isinstance(val.get("implementation"), dict) else None

        if isinstance(val.get("proxy"), dict):
            pa = val["proxy"].get("address")
            if pa:
                # store full proxy info for proper handling
                proxy_info = {
                    "address": pa,
                    "implementation": impl_addr or "0x0000000000000000000000000000000000000000",
                    "admin": val["proxy"].get("admin") or "0x0000000000000000000000000000000000000000",
                }
                mapping[to_checksum_address(pa)] = {
                    "contract": contract or val.get("implementation", {}).get("contract"),
                    "implementation": impl_addr or "0x0000000000000000000000000000000000000000",
                    "proxy": proxy_info,
                }
        if impl_addr:
            mapping[to_checksum_address(impl_addr)] = {
                "contract": contract or "",
                "implementation": impl_addr,
            }
        if val.get("address"):
            mapping[to_checksum_address(val["address"])] = {
                "contract": contract or "",
                "implementation": impl_addr or val.get("address"),
            }
    return mapping


def resolve_lido_entry(address: str) -> Optional[Dict[str, str]]:
    try:
        addr = to_checksum_address(address)
    except Exception:
        return None
    return _load_manifest().get(addr)

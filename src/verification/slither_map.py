"""slither detector alignment map per exploit class"""

from __future__ import annotations

SLITHER_MAP: dict[str, list[str]] = {
    "reentrancy": [
        "reentrancy-no-eth",
        "reentrancy-unlimited-gas",
        "reentrancy-benign",
    ],
    "authz_bypass": [
        "incorrect-visibility",
        "arbitrary-send-erc20",
        "tx-origin",
    ],
    "funds_frozen": [
        "locked-ether",
        "uninitialized-storage-pointer",
    ],
    "market_corruption": [
        "controlled-delegatecall",
        "assembly-usage",
        "unprotected-upgrade",
    ],
    "config_capture": [
        "initializer-not-disabled",
        "unprotected-upgrade",
        "proxy-implementation-slot",
    ],
}

#!/usr/bin/env bash
set -euo pipefail

echo "[ci] forge --version"
forge --version

echo "[ci] forge fmt --check"
forge fmt --check

echo "[ci] forge build --sizes"
forge build --sizes

if grep -R --line-number -E 'TODO|FIXME' src tests; then
  echo "[ci] found todo/fixme markers"
  exit 1
fi

if grep -q 'auto_detect_remappings = true' foundry.toml; then
  echo "[ci] auto_detect_remappings must be false"
  exit 1
fi

if grep -R --line-number -E 'startPrank|stopPrank' data/pocs; then
  echo "[ci] raw prank helpers in pocs"
  exit 1
fi

if grep -R --line-number -E 't\\.vm' src/poc; then
  echo "[ci] legacy t.vm references"
  exit 1
fi

if ! grep -R --line-number 'HEVM_ADDRESS' src/poc/support/Hevm.sol >/dev/null; then
  echo "[ci] hevm binder missing constant"
  exit 1
fi

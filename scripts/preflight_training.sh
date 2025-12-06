#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DVD_DIR="$PROJECT_ROOT/training/damn-vulnerable-defi"

if [[ ! -d "$DVD_DIR" ]]; then
  echo "[preflight] missing dvd at $DVD_DIR" >&2
  exit 1
fi

if [[ ! -f "$DVD_DIR/foundry.toml" ]]; then
  echo "[preflight] foundry.toml not found" >&2
  exit 1
fi

echo "[preflight] dvd workspace ready: $DVD_DIR"

if [[ "${POC_SKIP_PREFLIGHT_BUILD:-0}" != "1" ]]; then
  NEED_BUILD=0
  if [[ ! -d "$DVD_DIR/out" ]]; then
    NEED_BUILD=1
  else
    if [[ $(find "$DVD_DIR/src" -type f -newer "$DVD_DIR/out" -print -quit) ]]; then
      NEED_BUILD=1
    fi
  fi

  if [[ "$NEED_BUILD" -eq 1 ]]; then
    echo "[preflight] forge build dvd"
    pushd "$DVD_DIR" >/dev/null
    forge build >/dev/null
    popd >/dev/null
  fi
fi

exit 0

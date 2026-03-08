#!/usr/bin/env bash
set -euo pipefail

SAFE_TARGET="${SAFE_TARGET:-/tmp/kestrel_lab_fake_shadow}"
REAL_TARGET="${REAL_TARGET:-/etc/shadow}"
EXECUTE="${KESTREL_LAB_EXECUTE:-0}"
ALLOW_REAL="${KESTREL_LAB_ALLOW_REAL_TARGETS:-0}"

echo "[battle-lab] credential_access scenario"

echo "fake-user:fake-hash" > "$SAFE_TARGET"

echo "[battle-lab] default target: $SAFE_TARGET"
if [[ "$ALLOW_REAL" == "1" ]]; then
  echo "[battle-lab] real target enabled: $REAL_TARGET"
fi

if [[ "$EXECUTE" != "1" ]]; then
  echo "[battle-lab] dry-run only; set KESTREL_LAB_EXECUTE=1 to execute"
  exit 0
fi

cat "$SAFE_TARGET" >/dev/null || true

if [[ "$ALLOW_REAL" == "1" ]]; then
  cat "$REAL_TARGET" >/dev/null || true
fi

echo "[battle-lab] active simulation complete"

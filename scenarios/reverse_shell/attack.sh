#!/usr/bin/env bash
set -euo pipefail

HOST="${DEFAULT_HOST:-127.0.0.1}"
PORT="${DEFAULT_PORT:-4444}"
EXECUTE="${KESTREL_LAB_EXECUTE:-0}"

echo "[battle-lab] reverse_shell scenario"
echo "[battle-lab] target=${HOST}:${PORT}"

action_preview() {
  cat <<PREVIEW
[battle-lab] preview command chain:
  /bin/sh -c 'echo test | nc ${HOST} ${PORT}'
PREVIEW
}

action_preview

if [[ "$EXECUTE" != "1" ]]; then
  echo "[battle-lab] dry-run only; set KESTREL_LAB_EXECUTE=1 to execute"
  exit 0
fi

if ! command -v nc >/dev/null 2>&1; then
  echo "[battle-lab] nc not found; cannot execute active reverse-shell simulation" >&2
  exit 1
fi

/bin/sh -c "echo kestrel-lab-test | nc ${HOST} ${PORT} || true"
echo "[battle-lab] active simulation complete"

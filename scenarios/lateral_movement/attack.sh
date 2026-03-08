#!/usr/bin/env bash
set -euo pipefail

HOST="${DEFAULT_HOST:-127.0.0.1}"
PORT="${DEFAULT_PORT:-2222}"
EXECUTE="${KESTREL_LAB_EXECUTE:-0}"

echo "[battle-lab] lateral_movement scenario"
echo "[battle-lab] loopback target=${HOST}:${PORT}"

cat <<PREVIEW
[battle-lab] preview command chain:
  /bin/sh -c 'echo kestrel-lab-lateral | nc ${HOST} ${PORT}'
  ssh -p ${PORT} user@${HOST} 'id'
PREVIEW

if [[ "$EXECUTE" != "1" ]]; then
  echo "[battle-lab] dry-run only; set KESTREL_LAB_EXECUTE=1 to execute"
  exit 0
fi

if command -v nc >/dev/null 2>&1; then
  /bin/sh -c "echo kestrel-lab-lateral | nc ${HOST} ${PORT} || true"
else
  echo "[battle-lab] nc not found; skipping active loopback connect" >&2
fi

echo "[battle-lab] simulated remote command: ssh -p ${PORT} user@${HOST} 'id'"
echo "[battle-lab] active simulation complete"

#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/kestrel_lab_ransomware}"
FILE_COUNT="${FILE_COUNT:-5}"
EXECUTE="${KESTREL_LAB_EXECUTE:-0}"

echo "[battle-lab] ransomware_early_stage scenario"
echo "[battle-lab] workdir=${WORKDIR} file_count=${FILE_COUNT}"

mkdir -p "$WORKDIR"
for i in $(seq 1 "$FILE_COUNT"); do
  printf 'kestrel-lab-file-%s\n' "$i" > "$WORKDIR/document_${i}.txt"
done

echo "[battle-lab] preview rename plan:"
for i in $(seq 1 "$FILE_COUNT"); do
  echo "  mv $WORKDIR/document_${i}.txt $WORKDIR/document_${i}.txt.locked"
done

if [[ "$EXECUTE" != "1" ]]; then
  echo "[battle-lab] dry-run only; set KESTREL_LAB_EXECUTE=1 to execute"
  exit 0
fi

for i in $(seq 1 "$FILE_COUNT"); do
  cat "$WORKDIR/document_${i}.txt" >/dev/null || true
  mv "$WORKDIR/document_${i}.txt" "$WORKDIR/document_${i}.txt.locked"
done

echo "[battle-lab] active simulation complete"

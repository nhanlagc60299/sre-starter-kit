#!/usr/bin/env bash
# Render core/**/*.tpl with values from .env into build/, copy everything else as-is.
set -euo pipefail
ROOT="$(pwd)"
[ -f "$ROOT/.env" ] || { echo "ERROR: .env not found. Run 'make init' first." >&2; exit 1; }
set -a; . "$ROOT/.env"; set +a
rm -rf "$ROOT/build"; mkdir -p "$ROOT/build"
# Only substitute variables that are defined in .env, so Prometheus/Alloy $labels etc. survive.
VARS=$(grep -oE '^[A-Z_][A-Z0-9_]*=' "$ROOT/.env" | sed 's/=$//' | sed 's/^/\$/' | tr '\n' ' ')
while IFS= read -r -d '' f; do
  rel="${f#$ROOT/core/}"
  out="$ROOT/build/$rel"
  mkdir -p "$(dirname "$out")"
  if [[ "$f" == *.tpl ]]; then
    envsubst "$VARS" < "$f" > "${out%.tpl}"
  else
    cp "$f" "$out"
  fi
done < <(find "$ROOT/core" -type f -print0)
echo "rendered to build/"

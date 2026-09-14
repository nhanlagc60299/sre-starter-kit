#!/usr/bin/env bash
# `cp .env.example .env` must not produce a config that crash-loops Alertmanager.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r core scripts .env.example "$tmp/"
cp .env.example "$tmp/.env"          # unmodified, exactly what a copy-paste install gives you

out=$( cd "$tmp" && bash scripts/render.sh 2>&1 ) && { echo "FAIL: render succeeded with an empty SLACK_WEBHOOK_URL"; exit 1; }
case "$out" in
  *"ERROR: SLACK_WEBHOOK_URL is empty. Set it in .env (or run 'make init')."*) ;;
  *) echo "FAIL: wrong error message: $out"; exit 1 ;;
esac

sed -i.bak 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' "$tmp/.env" && rm -f "$tmp/.env.bak"
( cd "$tmp" && bash scripts/render.sh >/dev/null ) || { echo "FAIL: render failed with a webhook set"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml
echo "test_env_example OK"

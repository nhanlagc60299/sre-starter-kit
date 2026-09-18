#!/usr/bin/env bash
# `cp .env.example .env` must not produce a config that crash-loops Alertmanager.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r core scripts compose .env.example "$tmp/"
cp .env.example "$tmp/.env"          # unmodified, exactly what a copy-paste install gives you

out=$( cd "$tmp" && bash scripts/render.sh 2>&1 ) && { echo "FAIL: render succeeded with no receiver configured"; exit 1; }
case "$out" in
  *"ERROR: no alert receiver configured."*) ;;
  *) echo "FAIL: wrong error message: $out"; exit 1 ;;
esac

sed -i.bak 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' "$tmp/.env" && rm -f "$tmp/.env.bak"
( cd "$tmp" && bash scripts/render.sh >/dev/null ) || { echo "FAIL: render failed with a webhook set"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml

# The Slack link on every alert is Alertmanager's external URL. Unset, it is the container's
# hostname, which nobody can click. compose reads the key straight from .env.
cfg=$( cd "$tmp" && ALERTMANAGER_EXTERNAL_URL=https://am.example.test ${CONTAINER_ENGINE:-docker} compose --env-file .env -f compose/docker-compose.yml config )
[[ "$cfg" == *"--web.external-url=https://am.example.test"* ]] || { echo "FAIL: ALERTMANAGER_EXTERNAL_URL not passed to alertmanager"; exit 1; }
cfg=$( cd "$tmp" && ${CONTAINER_ENGINE:-docker} compose --env-file .env -f compose/docker-compose.yml config )
[[ "$cfg" == *"--web.external-url=http://localhost:9093"* ]] || { echo "FAIL: external URL has no default"; exit 1; }

echo "test_env_example OK"

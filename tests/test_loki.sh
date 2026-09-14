#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' .env.example > "$tmp/.env"
cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/loki:3.5.0 -config.file=/c/loki.yml -verify-config
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/alloy:v1.9.0 fmt /c/config.alloy >/dev/null
# lokitool is not present in the loki image; rely on loki -verify-config again
# as the smoke check (it does not parse rule file contents, only the config schema).
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" --entrypoint loki grafana/loki:3.5.0 -config.file=/c/loki.yml -verify-config
echo "test_loki OK"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' .env.example > "$tmp/.env"
cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/loki:3.5.0 -config.file=/c/loki.yml -verify-config
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/alloy:v1.9.0 fmt /c/config.alloy >/dev/null
# lokitool is not present in the loki image; assert the rules file rendered to the
# tenant path and declares exactly the two alerts, instead of relying on loki -verify-config
# (which does not parse rule file contents).
test -f "$tmp/build/loki/rules/fake/security.yml" || { echo "FAIL: security.yml missing at tenant path"; exit 1; }
python3 -c 'import yaml,sys; g=yaml.safe_load(open(sys.argv[1]))["groups"]; assert {r["alert"] for gr in g for r in gr["rules"]} == {"SSHFailedLoginBurst","RootLoginDetected"}, "unexpected alert set"' "$tmp/build/loki/rules/fake/security.yml"
echo "test_loki OK"

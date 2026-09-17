#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' .env.example > "$tmp/.env"
cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/loki:3.5.0 -config.file=/c/loki.yml -verify-config
# -verify-config accepts the un-substituted template too, so check the value actually landed
grep -q 'retention_period: 168h' "$tmp/build/loki/loki.yml" || { echo "FAIL: LOKI_RETENTION_PERIOD not substituted"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/alloy:v1.9.0 fmt /c/config.alloy >/dev/null
# lokitool is not present in the loki image; assert the rules file rendered to the
# tenant path and declares exactly the two alerts, instead of relying on loki -verify-config
# (which does not parse rule file contents).
test -f "$tmp/build/loki/rules/fake/security.yml" || { echo "FAIL: security.yml missing at tenant path"; exit 1; }
python3 -c 'import yaml,sys; g=yaml.safe_load(open(sys.argv[1]))["groups"]; assert {r["alert"] for gr in g for r in gr["rules"]} == {"SSHFailedLoginBurst","RootLoginDetected"}, "unexpected alert set"' "$tmp/build/loki/rules/fake/security.yml"
test -f "$tmp/build/loki/rules/fake/logs.yml" || { echo "FAIL: logs.yml missing at tenant path"; exit 1; }
python3 -c 'import yaml,sys; g=yaml.safe_load(open(sys.argv[1]))["groups"]; assert {r["alert"] for gr in g for r in gr["rules"]} == {"LogErrorBurst","Http5xxInLogs"}, "unexpected alert set"' "$tmp/build/loki/rules/fake/logs.yml"
# The log alerts must not include the kit's own containers, or Grafana's startup chatter pages the customer.
grep -q 'service!~"prometheus|alertmanager|grafana|loki|alloy|blackbox|cadvisor|node-exporter' "$tmp/build/loki/rules/fake/logs.yml" || { echo "FAIL: log alerts do not exclude the kit's own services"; exit 1; }
echo "test_loki OK"

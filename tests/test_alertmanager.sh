#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#; s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' .env.example > "$tmp/.env"
cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml
grep -q 'severity="critical"' "$tmp/build/alertmanager/alertmanager.yml"  # sanity: routing present
! grep -q '^ *http_config:' "$tmp/build/alertmanager/alertmanager.yml" || { echo "FAIL: empty TRIAGE_WEBHOOK_TOKEN still renders an http_config"; exit 1; }
# A token set: webhook-triage sends it as a Bearer credential. The quote proves the single-quoted YAML
# escaping; amtool proves Alertmanager itself accepts the block.
printf '%s\n' "TRIAGE_WEBHOOK_TOKEN=\"ab'cd\"" >> "$tmp/.env"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml
python3 - "$tmp/build/alertmanager/alertmanager.yml" <<'PYTOK' || { echo "FAIL: webhook-triage does not send TRIAGE_WEBHOOK_TOKEN"; exit 1; }
import sys,yaml
by={r["name"]: r for r in yaml.safe_load(open(sys.argv[1]))["receivers"]}
wc=by["webhook-triage"]["webhook_configs"][0]
assert wc.get("http_config",{}).get("authorization")=={"type": "Bearer", "credentials": "ab'cd"}, wc
assert all("http_config" not in c for n,r in by.items() if n!="webhook-triage" for c in r.get("webhook_configs",[])), "token leaked to another webhook"
PYTOK
# The agent compares the header as bytes of a latin-1 decode against UTF-8 bytes of the token, so a
# non-ASCII token can never match: every alert would get a 401. Refuse to render it instead.
printf 'TRIAGE_WEBHOOK_TOKEN=t\303\266k\n' >> "$tmp/.env"   # "tök", UTF-8
if out=$( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" 2>&1 ); then echo "FAIL: render accepted a non-ASCII TRIAGE_WEBHOOK_TOKEN"; exit 1; fi
[[ "$out" == *"TRIAGE_WEBHOOK_TOKEN"* ]] || { echo "FAIL: non-ASCII token refused without naming the key: $out"; exit 1; }
echo "test_alertmanager OK"

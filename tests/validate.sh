#!/usr/bin/env bash
# Fast static checks. No stack needed.
set -euo pipefail
cd "$(dirname "$0")/.."
PROM_IMG=prom/prometheus:v3.4.0
fail=0
# 1. rule syntax
${CONTAINER_ENGINE:-docker} run --rm -v "$PWD/core/prometheus/rules:/r" --entrypoint promtool $PROM_IMG check rules /r/infra.yml /r/app.yml || fail=1
# 2. every alert has severity, module, runbook_url
python3 - <<'PY' || fail=1
import yaml,glob,sys
bad=[]
files=glob.glob("core/prometheus/rules/*.yml")+glob.glob("core/loki/rules/fake/*.yml")
assert files, "no rule files found"
for f in files:
    for g in yaml.safe_load(open(f))["groups"]:
        for r in g["rules"]:
            if "alert" not in r: continue
            l=r.get("labels",{}); a=r.get("annotations",{})
            if l.get("severity") not in ("critical","warning") or "module" not in l or "runbook_url" not in a:
                bad.append(f"{f}:{r['alert']}")
if bad: print("alerts missing severity/module/runbook_url:", *bad, sep="\n  "); sys.exit(1)
PY
# 3. dashboards parse and have uid
for d in core/grafana/dashboards/*.json; do python3 -c "import json,sys; j=json.load(open('$d')); assert j.get('uid'), 'no uid'" || { echo "bad dashboard $d"; fail=1; }; done
# 4. rendered configs pass amtool / loki verify (uses .env.example)
bash tests/test_alertmanager.sh >/dev/null || fail=1
bash tests/test_loki.sh >/dev/null || fail=1
# 5. routing: a critical alert must reach both critical and webhook-triage
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' .env.example > "$tmp/.env"; cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 config routes test --config.file=/c/alertmanager.yml --verify.receivers=critical,webhook-triage severity=critical alertname=X >/dev/null || { echo "routing: critical does not reach critical+webhook-triage"; fail=1; }
[ $fail -eq 0 ] && echo "validate OK" || { echo "validate FAILED"; exit 1; }

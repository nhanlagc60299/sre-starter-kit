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
import yaml,glob,sys,json
bad=[]
# every dashboard is tagged sre-kit and carries the SRE Kit dropdown; every alert names one of them
dash={}
for d in glob.glob("core/grafana/dashboards/*.json"):
    with open(d) as fh: j=json.load(fh)
    if not j.get("uid"): bad.append(f"{d}: dashboard has no uid"); continue
    dash[j["uid"]]=j
    if "sre-kit" not in (j.get("tags") or []): bad.append(f"{d}: missing tag sre-kit (the SRE Kit dropdown lists by tag)")
    if not any(l.get("type")=="dashboards" and "sre-kit" in (l.get("tags") or []) for l in (j.get("links") or [])): bad.append(f"{d}: missing the SRE Kit dashboards link")
assert dash, "no dashboards"
files=glob.glob("core/prometheus/rules/*.yml")+glob.glob("core/loki/rules/fake/*.yml")
assert files, "no rule files found"
for f in files:
    for g in yaml.safe_load(open(f))["groups"]:
        for r in g["rules"]:
            if "alert" not in r: continue
            l=r.get("labels",{}); a=r.get("annotations",{})
            if l.get("severity") not in ("critical","warning") or "module" not in l or "runbook_url" not in a:
                bad.append(f"{f}:{r['alert']}")
            if a.get("dashboard") not in dash: bad.append(f"{f}:{r['alert']}: annotations.dashboard must name a shipped dashboard uid, got {a.get('dashboard')!r}")
if bad: print("alerts missing severity/module/runbook_url/dashboard, or a dashboard without tag/link:", *bad, sep="\n  "); sys.exit(1)
PY
# 2b. every runbook_url resolves to a heading in docs/ALERTS.md
python3 - <<'EOPY' || fail=1
import yaml,glob,re,sys
anchors={re.sub(r"[^a-z0-9]+","-",h.lower()).strip("-")
         for h in re.findall(r"^#+\s+(.*)$", open("docs/ALERTS.md").read(), re.M)}
missing=[]
for f in glob.glob("core/prometheus/rules/*.yml")+glob.glob("core/loki/rules/fake/*.yml"):
    for g in yaml.safe_load(open(f))["groups"]:
        for r in g["rules"]:
            if "alert" not in r: continue
            url=r.get("annotations",{}).get("runbook_url","")
            frag=url.split("#",1)[1] if "#" in url else ""
            if frag not in anchors: missing.append(f"{r['alert']}: {url}")
if missing: print("runbook_url with no matching heading in docs/ALERTS.md:", *missing, sep="\n  "); sys.exit(1)
EOPY
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
# 6. the two sample runbooks are real files with the Pro runbook shape, and ALERTS.md links to them
for rb in ServiceDown DiskWillFillIn24h; do
  f="docs/runbooks/$rb.md"
  [ -f "$f" ] && [ "$(head -1 "$f")" = "# $rb" ] && [ "$(wc -l < "$f")" -le 60 ] || { echo "sample runbook $f missing or malformed"; fail=1; }
  grep -qF "](runbooks/$rb.md)" docs/ALERTS.md || { echo "docs/ALERTS.md does not link $f"; fail=1; }
done
[ $fail -eq 0 ] && echo "validate OK" || { echo "validate FAILED"; exit 1; }

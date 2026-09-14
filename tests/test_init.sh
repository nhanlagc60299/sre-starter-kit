#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r core scripts .env.example "$tmp/"
# answers: project, slack, telegram token, chat id, teams, services (2 then blank), disk warn, disk crit, prom ret, loki ret, grafana pw, security y
printf 'acme\nhttp://localhost:9/\n123:abc\n-100\n\napi=http://api:8080/health\nweb=http://web/\n\n20\n8\n15d\n168h\ns3cret\ny\n' \
  | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -q '^PROJECT_NAME=acme$' "$tmp/.env"
grep -q '^TELEGRAM_BOT_TOKEN=123:abc$' "$tmp/.env"
grep -q '^DISK_WARN_PCT=20$' "$tmp/.env"
grep -q '^SERVICES=api=http://api:8080/health,web=http://web/$' "$tmp/.env"
( cd "$tmp" && bash scripts/render.sh >/dev/null )
python3 - "$tmp" <<'PY'
import json,sys,os
t=json.load(open(sys.argv[1]+"/build/prometheus/targets/services.json"))
assert t==[{"targets":["http://api:8080/health"],"labels":{"service":"api"}},{"targets":["http://web/"],"labels":{"service":"web"}}], t
am=open(sys.argv[1]+"/build/alertmanager/alertmanager.yml").read()
assert "telegram_configs" in am and "bot_token: 123:abc" in am, "telegram receiver missing"
assert "msteamsv2_configs" not in am, "teams should be absent when blank"
rules=open(sys.argv[1]+"/build/prometheus/rules/infra.yml").read()
assert "* 100 < 8\n" in rules and "* 100 < 20\n" in rules, "disk thresholds not applied"
PY

# --- re-run 2: disk warn 30 / crit 15 must not collide, security answered "n" ---
printf '\n\n\n\n\n\n30\n15\n\n\n\nn\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -q '^DISK_WARN_PCT=30$' "$tmp/.env"
grep -q '^DISK_CRIT_PCT=15$' "$tmp/.env"
grep -q '^MODULE_SECURITY=false$' "$tmp/.env"
grep -q '^PROJECT_NAME=acme$' "$tmp/.env"   # blank answers keep the previous value
( cd "$tmp" && bash scripts/render.sh >/dev/null )
python3 - "$tmp" <<'PY'
import re,sys
rules=open(sys.argv[1]+"/build/prometheus/rules/infra.yml").read()
exprs=dict(re.findall(r'- alert: (\w+)\n\s*expr: (.*)', rules))
assert exprs["DiskFull"].endswith("* 100 < 15"), exprs["DiskFull"]
assert exprs["DiskLow"].endswith("* 100 < 30"), exprs["DiskLow"]
PY
[ -e "$tmp/build/loki/rules" ] && { echo "FAIL: security rules kept when module off"; exit 1; }

# --- re-run 3: blank security answer keeps it off ---
printf '\n\n\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -q '^MODULE_SECURITY=false$' "$tmp/.env"
echo "test_init OK"

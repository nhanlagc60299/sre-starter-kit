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
echo "test_init OK"

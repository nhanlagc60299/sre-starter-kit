#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r core scripts .env.example "$tmp/"
# answers: project, slack, telegram token, chat id, teams, services (2 then blank), disk warn, disk crit,
# prom ret, loki ret, grafana pw, security y, container sock, cadvisor y, auth log path
printf 'acme\nhttp://localhost:9/\n123:abc\n-100\n\napi=http://api:8080/health\nweb=http://web/\n\n20\n8\n15d\n168h\ns3cret\ny\n\ny\n/var/log/secure\n' \
  | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "PROJECT_NAME='acme'" "$tmp/.env"
grep -qxF "CONTAINER_SOCK='/var/run/docker.sock'" "$tmp/.env"
grep -qxF "COMPOSE_PROFILES='cadvisor'" "$tmp/.env"
grep -qxF "AUTH_LOG_PATH='/var/log/secure'" "$tmp/.env"
[ "$(stat -f '%Lp' "$tmp/.env" 2>/dev/null || stat -c '%a' "$tmp/.env")" = 600 ] || { echo "FAIL: .env is not 0600"; exit 1; }
grep -qxF "TELEGRAM_BOT_TOKEN='123:abc'" "$tmp/.env"
grep -qxF "DISK_WARN_PCT='20'" "$tmp/.env"
grep -qxF "SERVICES='api=http://api:8080/health,web=http://web/'" "$tmp/.env"
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
# Podman-style: security off (so no auth-log question), custom socket, cAdvisor off.
printf '\n\n\n\n\n\n30\n15\n\n\n\nn\n/run/user/1000/podman/podman.sock\nn\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "CONTAINER_SOCK='/run/user/1000/podman/podman.sock'" "$tmp/.env"
grep -qxF "COMPOSE_PROFILES=''" "$tmp/.env"
grep -qxF "AUTH_LOG_PATH='/var/log/secure'" "$tmp/.env"   # not asked, previous value kept
grep -qxF "DISK_WARN_PCT='30'" "$tmp/.env"
grep -qxF "DISK_CRIT_PCT='15'" "$tmp/.env"
grep -qxF "MODULE_SECURITY='false'" "$tmp/.env"
grep -qxF "PROJECT_NAME='acme'" "$tmp/.env"   # blank answers keep the previous value
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
printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "MODULE_SECURITY='false'" "$tmp/.env"
grep -qxF "COMPOSE_PROFILES=''" "$tmp/.env"   # blank answer keeps cAdvisor off
# --- re-run 4: values with spaces and shell metacharacters survive the .env round-trip ---
printf 'Acme Corp\n\n\n\n\n\n\n\n\n\np@ss word$1\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "PROJECT_NAME='Acme Corp'" "$tmp/.env"
grep -qxF "GRAFANA_ADMIN_PASSWORD='p@ss word\$1'" "$tmp/.env"
( cd "$tmp" && bash scripts/render.sh >/dev/null )    # would die with "Corp: command not found" if unquoted
grep -q '^    project: Acme Corp$' "$tmp/build/prometheus/prometheus.yml"

# --- re-run 5: bad answers are rejected and re-asked ---
# services: the comma line is dropped, then a valid one; disk warn: "20%" is re-asked, then 20
printf '\n\n\n\n\nbad=http://x/a,b\nok=http://ok/\n\n20%%\n20\n8\n\n\n\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "SERVICES='ok=http://ok/'" "$tmp/.env"
grep -qxF "DISK_WARN_PCT='20'" "$tmp/.env"
grep -qxF "DISK_CRIT_PCT='8'" "$tmp/.env"
echo "test_init OK"

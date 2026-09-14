#!/usr/bin/env bash
# Bring the stack up with a throwaway .env, assert every Prometheus target is UP, tear down.
set -euo pipefail
cd "$(dirname "$0")/.."
CE=${CONTAINER_ENGINE:-docker}
COMPOSE="$CE compose -p sre-kit-smoke --env-file .env -f compose/docker-compose.yml"
H=${SMOKE_HOST:-localhost}   # CI with docker-in-docker: SMOKE_HOST=docker
cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; [ -n "${BACKUP:-}" ] && mv "$BACKUP" .env || rm -f .env; }
trap cleanup EXIT
if [ -f .env ]; then BACKUP=$(mktemp); mv .env "$BACKUP"; fi
sed 's/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=smoke/; s#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' .env.example > .env
case ",${SMOKE_SKIP_JOBS:-}," in *,cadvisor,*) sed -i.bak 's/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=/' .env && rm -f .env.bak ;; esac
[ -n "${CONTAINER_SOCK:-}" ] && sed -i.bak "s#^CONTAINER_SOCK=.*#CONTAINER_SOCK=${CONTAINER_SOCK}#" .env && rm -f .env.bak
bash scripts/render.sh
echo '[{"targets":["http://prometheus:9090/-/healthy"],"labels":{"service":"prometheus-self"}}]' > build/prometheus/targets/services.json
$COMPOSE up -d
for i in $(seq 1 30); do
  sleep 4
  down=$(curl -sf $H:9090/api/v1/targets | SKIP="${SMOKE_SKIP_JOBS:-}" python3 -c 'import sys,json,os; skip=set(os.environ["SKIP"].split(",")); t=json.load(sys.stdin)["data"]["activeTargets"]; print(" ".join(x["labels"]["job"] for x in t if x["health"]!="up" and x["labels"]["job"] not in skip))' 2>/dev/null || echo "api-not-ready")
  [ -z "$down" ] && break
done
[ -z "$down" ] || { echo "FAIL: targets not up: $down"; $COMPOSE ps; exit 1; }
curl -sf $H:3000/api/health | grep -q '"database": "ok"' || { echo "FAIL: grafana unhealthy"; exit 1; }
for i in $(seq 1 15); do curl -sf $H:3100/ready | grep -q ready && break; sleep 4; done
curl -sf $H:3100/ready | grep -q ready || { echo "FAIL: loki not ready after 60s"; exit 1; }
rules=$(curl -sf $H:3100/loki/api/v1/rules 2>/dev/null || true)
echo "$rules" | grep -q SSHFailedLoginBurst && echo "$rules" | grep -q RootLoginDetected || { echo "FAIL: loki ruler did not load security rules"; exit 1; }
echo "smoke OK: all targets up"

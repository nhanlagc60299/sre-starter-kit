#!/usr/bin/env bash
# Bring the stack up with a throwaway .env, assert every Prometheus target is UP, tear down.
set -euo pipefail
cd "$(dirname "$0")/.."
CE=${CONTAINER_ENGINE:-docker}
COMPOSE="$CE compose -p sre-kit-smoke --env-file .env -f compose/docker-compose.yml"
H=${SMOKE_HOST:-localhost}   # CI with docker-in-docker: SMOKE_HOST=docker
cleanup() {
  $COMPOSE down -v >/dev/null 2>&1 || true
  # render.sh wiped build/ for the throwaway .env; put the real config back.
  if [ -n "${BACKUP:-}" ]; then mv "$BACKUP" .env; bash scripts/render.sh >/dev/null || true
  else rm -f .env; rm -rf build; fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT   # Ctrl-C must not report success
if [ -f .env ]; then BACKUP=$(mktemp); mv .env "$BACKUP"; fi
sed 's/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=smoke/; s#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' .env.example > .env
sed -i.bak "s/^BIND_ADDR=.*/BIND_ADDR=${SMOKE_BIND_ADDR:-127.0.0.1}/" .env && rm -f .env.bak
case ",${SMOKE_SKIP_JOBS:-}," in *,cadvisor,*) sed -i.bak 's/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=/' .env && rm -f .env.bak ;; esac
[ -n "${CONTAINER_SOCK:-}" ] && sed -i.bak "s#^CONTAINER_SOCK=.*#CONTAINER_SOCK=${CONTAINER_SOCK}#" .env && rm -f .env.bak
bash scripts/render.sh
echo '[{"targets":["http://prometheus:9090/-/healthy"],"labels":{"service":"prometheus-self"}}]' > build/prometheus/targets/services.json
$COMPOSE up -d
for i in $(seq 1 30); do
  sleep 4
  down=$(curl -sf $H:9090/api/v1/targets | SKIP="${SMOKE_SKIP_JOBS:-}" python3 -c 'import sys,json,os; skip=set(os.environ["SKIP"].split(",")); t=json.load(sys.stdin)["data"]["activeTargets"]; print("no-targets-yet" if not t else " ".join(x["labels"]["job"] for x in t if x["health"]!="up" and x["labels"]["job"] not in skip))' 2>/dev/null || echo "api-not-ready")
  [ -z "$down" ] && break
done
[ -z "$down" ] || { echo "FAIL: targets not up: $down"; $COMPOSE ps; exit 1; }
# A cAdvisor that scrapes UP is not a cAdvisor that sees containers. Given a Docker whose storage
# driver it cannot read, it registers no container at all and publishes only host cgroups -- the
# target stays UP, series keep flowing, and every container alert goes quiet with nothing looking
# broken. Assert it names at least one real container, which is what "UP" failed to mean.
case ",${SMOKE_SKIP_JOBS:-}," in *,cadvisor,*) ;; *)
  named=0
  for i in $(seq 1 15); do
    named=$(curl -sf $H:9090/api/v1/query --data-urlencode 'query=count(container_memory_working_set_bytes{name!=""})' \
      | python3 -c 'import sys,json; r=json.load(sys.stdin)["data"]["result"]; print(int(float(r[0]["value"][1])) if r else 0)' 2>/dev/null || echo 0)
    [ "$named" -gt 0 ] && break
    sleep 4
  done
  [ "$named" -gt 0 ] || { echo "FAIL: cAdvisor target is UP but names no containers; every container alert is blind"; exit 1; }
  echo "smoke: cAdvisor names $named containers"
;; esac

# BlackboxExporterDown reads up{job="blackbox"}. The "no target is down" loop above passes happily
# when a job is absent entirely, so a renamed or dropped job would take the alert down in silence --
# which is exactly how this alert spent its whole life pointed at blackbox-http, a job with no
# series at all unless SERVICES is set.
for i in $(seq 1 15); do
  bb=$(curl -sf $H:9090/api/v1/query --data-urlencode 'query=count(up{job="blackbox"})' \
    | python3 -c 'import sys,json; r=json.load(sys.stdin)["data"]["result"]; print(int(float(r[0]["value"][1])) if r else 0)' 2>/dev/null || echo 0)
  [ "$bb" -gt 0 ] && break
  sleep 4
done
[ "$bb" -gt 0 ] || { echo "FAIL: no up{job=\"blackbox\"} series; BlackboxExporterDown cannot fire"; exit 1; }
echo "smoke: blackbox exporter self-scrape present ($bb series)"
for i in $(seq 1 15); do curl -sf $H:3000/api/health | grep -q '"database": *"ok"' && break; sleep 4; done
curl -sf $H:3000/api/health | grep -q '"database": *"ok"' || { echo "FAIL: grafana unhealthy after 60s"; exit 1; }
for i in $(seq 1 15); do curl -sf $H:3100/ready | grep -q ready && break; sleep 4; done
curl -sf $H:3100/ready | grep -q ready || { echo "FAIL: loki not ready after 60s"; exit 1; }
rules=$(curl -sf $H:3100/loki/api/v1/rules 2>/dev/null || true)
echo "$rules" | grep -q SSHFailedLoginBurst && echo "$rules" | grep -q RootLoginDetected || { echo "FAIL: loki ruler did not load security rules"; exit 1; }
echo "$rules" | grep -q LogErrorBurst && echo "$rules" | grep -q Http5xxInLogs || { echo "FAIL: loki ruler did not load the log alerts"; exit 1; }
# Prove the LogQL the alerts use actually counts lines: push 60 error lines for a fake service and evaluate
# the LogErrorBurst selector against them. A rule the ruler *loads* can still be one that never matches.
python3 - "$H" <<'PY'
import json,sys,time,urllib.request
now=time.time_ns()
lines=[[str(now+i), "2026-09-17T00:00:00Z ERROR boom %d" % i] for i in range(60)]
body=json.dumps({"streams":[{"stream":{"service":"smoke-app","container":"smoke-app"},"values":lines}]}).encode()
req=urllib.request.Request("http://%s:3100/loki/api/v1/push" % sys.argv[1], data=body, headers={"Content-Type":"application/json"})
urllib.request.urlopen(req).read()
PY
q='sum by (service) (count_over_time({service=~".+", service!~"prometheus|alertmanager|grafana|loki|alloy|blackbox|cadvisor|node-exporter"} |~ `(?i)\b(error|exception|fatal|panic|traceback)\b` [5m]))'
n=0
for i in $(seq 1 15); do
  n=$(curl -sf "$H:3100/loki/api/v1/query" --data-urlencode "query=$q" \
    | python3 -c 'import sys,json; r=json.load(sys.stdin)["data"]["result"]; print(int(float(r[0]["value"][1])) if r else 0)' 2>/dev/null || echo 0)
  [ "$n" -ge 60 ] && break; sleep 4
done
[ "$n" -ge 60 ] || { echo "FAIL: LogErrorBurst selector counted $n of 60 pushed error lines"; exit 1; }
echo "smoke: log alert selector counts pushed lines ($n)"
echo "smoke OK: all targets up"

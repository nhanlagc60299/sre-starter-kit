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
# The triage agent runs in every smoke: dry run, so nothing leaves the machine, and it is the one
# place the pack's fixture shapes (tests/test_triage_agent.py) meet the real services. Rewrite with
# python rather than sed: .env's COMPOSE_PROFILES value can itself hold whatever SMOKE_SKIP_JOBS
# left behind, and feeding that text into a sed s/// pattern is exactly how a stray "/" breaks it.
sed -i.bak 's#^TRIAGE_WEBHOOK_URL=.*#TRIAGE_WEBHOOK_URL=http://triage-agent:9096/alert#' .env && rm -f .env.bak
python3 - <<'PY'
import re
with open(".env") as f:
    text = f.read()
def add_triage(m):
    # .env.example's own COMPOSE_PROFILES line carries a long inline comment (only stripped above
    # when SMOKE_SKIP_JOBS includes cadvisor); split on the first whitespace-then-# so the comment
    # text itself is never mistaken for part of the profiles list.
    p = re.split(r"\s+#", m.group(1), maxsplit=1)[0].strip()
    return "COMPOSE_PROFILES=" + (p + ",triage" if p else "triage")
text = re.sub(r"^COMPOSE_PROFILES=(.*)$", add_triage, text, flags=re.M)
with open(".env", "w") as f:
    f.write(text)
PY
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
# The selector stays verbatim (it is the alert's own, exclusion list included), so it also matches any
# other service Alloy happens to be tailing, not just smoke-app. The count below therefore picks the
# smoke-app stream by name rather than the first row of the result, which is in no defined order.
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
    | python3 -c 'import sys,json
r=[x for x in json.load(sys.stdin)["data"]["result"] if x["metric"].get("service")=="smoke-app"]
print(int(float(r[0]["value"][1])) if r else 0)' 2>/dev/null || echo 0)
  [ "$n" -ge 60 ] && break; sleep 4
done
[ "$n" -ge 60 ] || { echo "FAIL: LogErrorBurst selector counted $n of 60 pushed error lines"; exit 1; }
echo "smoke: log alert selector counts pushed lines ($n)"

# Fire one synthetic critical alert straight into Alertmanager; the critical route copies it to
# webhook-triage; the agent must log a dry-run pack whose sources are all reachable. Written outside
# build/ (SMOKE_PACK_OUT), because cleanup() above deletes build/ on every exit, including success.
PACK_OUT="${SMOKE_PACK_OUT:-${TMPDIR:-/tmp}/triage-sample-pack.json}"
curl -sf -XPOST $H:9093/api/v2/alerts -H 'Content-Type: application/json' -d '[{"labels":{"alertname":"ServiceDown","severity":"critical","module":"app","service":"prometheus-self","instance":"http://prometheus:9090/-/healthy","job":"blackbox-http"},"annotations":{"summary":"smoke: synthetic ServiceDown","runbook_url":"https://github.com/nhanlagc60299/sre-starter-kit/blob/main/docs/ALERTS.md#servicedown"}}]'
pack=""
for i in $(seq 1 20); do
  pack=$($COMPOSE logs --no-log-prefix triage-agent 2>/dev/null | grep '^{' | tail -1 || true)
  [ -n "$pack" ] && break; sleep 4
done
[ -n "$pack" ] || { echo "FAIL: triage agent logged no pack within 80s"; $COMPOSE logs triage-agent | tail -20; exit 1; }
printf '%s\n' "$pack" > "$PACK_OUT"
python3 - "$PACK_OUT" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))
assert p["schema_version"]==1, p.get("schema_version")
assert p["alerts"][0]["labels"]["alertname"]=="ServiceDown", p["alerts"][0]
for s in ("rules", "query", "alertmanager", "runbook"):
    assert p["sources"][s]=="ok", (s, p["sources"])
# no service logs for prometheus-self is fine (no Loki stream to match); unreachable is not
assert p["sources"]["loki"] in ("ok","empty"), p["sources"]
# a fresh Grafana has no deploy annotations yet; empty is fine, unreachable is not
assert p["sources"]["grafana"] in ("ok","empty"), p["sources"]
# the synthetic alert CLAIMS ServiceDown, but the probed target (Prometheus's own /-/healthy) is
# actually healthy, so the real rule expression (probe_success{job="blackbox-http"} == 0) matches no
# series over the last 30m; empty is the honest answer here, not a broken source. "query" above stays
# "ok" only because the separate up{instance=...} query folded into the same source does return one.
assert p["sources"]["query_range"] in ("ok","empty"), p["sources"]
assert p["rule"] and "probe_success" in p["rule"]["query"], p["rule"]   # the real ServiceDown rule was found
assert p["runbook"]["text"].strip(), "ALERTS.md section for ServiceDown is empty"
assert any(a["labels"]["alertname"]=="ServiceDown" for a in p["firing"]), "firing list misses the synthetic alert"
# up{instance=<probed url>} is Prometheus's own per-target series (job=blackbox-http relabels
# instance to the probed URL), independent of the rule's own probe_success reading - report what
# the real stack actually returns for it rather than assume.
print("smoke: up{instance=<probe url>} = %r" % (p["up"],))
print("smoke: triage pack ok, %d bytes, sources %s" % (len(open(sys.argv[1]).read()), p["sources"]))
PY
echo "smoke OK: all targets up"

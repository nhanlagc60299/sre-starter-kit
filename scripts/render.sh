#!/usr/bin/env bash
# Render core/**/*.tpl with values from .env into build/, copy everything else as-is.
set -euo pipefail
ROOT="$(pwd)"
[ -f "$ROOT/.env" ] || { echo "ERROR: .env not found. Run 'make init' first." >&2; exit 1; }
set -a; . "$ROOT/.env"; set +a
rm -rf "$ROOT/build"; mkdir -p "$ROOT/build"
# Only substitute variables that are defined in .env, so Prometheus/Alloy $labels etc. survive.
VARS=$(grep -oE '^[A-Z_][A-Z0-9_]*=' "$ROOT/.env" | sed 's/=$//' | sed 's/^/\$/' | tr '\n' ' ')
while IFS= read -r -d '' f; do
  rel="${f#$ROOT/core/}"
  out="$ROOT/build/$rel"
  mkdir -p "$(dirname "$out")"
  if [[ "$f" == *.tpl ]]; then
    envsubst "$VARS" < "$f" > "${out%.tpl}"
  else
    cp "$f" "$out"
  fi
done < <(find "$ROOT/core" -type f -print0)

# --- post-render: customer-specific generation from .env ---
# 1. blackbox targets
[ -d "$ROOT/build/prometheus/targets" ] && python3 - "$ROOT" <<'PY'
import json,os,sys
root=sys.argv[1]; svcs=os.environ.get("SERVICES","")
out=[{"targets":[u],"labels":{"service":n}} for n,u in (x.split("=",1) for x in svcs.split(",") if "=" in x)]
json.dump(out, open(f"{root}/build/prometheus/targets/services.json","w"))
PY
# 2. disk thresholds into rendered infra rules (core/ stays untouched)
# Two phase: tag both lines first, then fill in the values, so a chosen threshold
# can never be re-matched by the other expression (e.g. crit=15 vs the "< 15" anchor).
[ -f "$ROOT/build/prometheus/rules/infra.yml" ] && sed -i.bak -e "s/\* 100 < 5$/* 100 < __CRIT__/" -e "s/\* 100 < 15$/* 100 < __WARN__/" "$ROOT/build/prometheus/rules/infra.yml" && sed -i.bak -e "s/__CRIT__/${DISK_CRIT_PCT:-5}/" -e "s/__WARN__/${DISK_WARN_PCT:-15}/" "$ROOT/build/prometheus/rules/infra.yml" && rm -f "$ROOT/build/prometheus/rules/infra.yml.bak"
# 3. optional receivers
AM="$ROOT/build/alertmanager/alertmanager.yml"
add() { # marker block
  python3 - "$AM" "$1" "$2" <<'PY'
import sys; p,marker,block=sys.argv[1:]; s=open(p).read(); open(p,"w").write(s.replace("    # "+marker, block+"\n    # "+marker))
PY
}
if [ -f "$AM" ] && [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
  for m in RECEIVERS_CRITICAL_EXTRA RECEIVERS_WARNING_EXTRA; do
    add "$m" "    telegram_configs:
      - bot_token: ${TELEGRAM_BOT_TOKEN:-}
        chat_id: ${TELEGRAM_CHAT_ID:-}
        parse_mode: ''
        send_resolved: true
        message: '[${PROJECT_NAME:-}] {{ .CommonLabels.alertname }}: {{ range .Alerts }}{{ .Annotations.summary }} {{ end }}'"
  done
fi
if [ -f "$AM" ] && [ -n "${TEAMS_WEBHOOK_URL:-}" ]; then
  for m in RECEIVERS_CRITICAL_EXTRA RECEIVERS_WARNING_EXTRA; do
    add "$m" "    msteamsv2_configs:
      - webhook_url: ${TEAMS_WEBHOOK_URL:-}
        send_resolved: true
        title: '[${PROJECT_NAME:-}] {{ .CommonLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.summary }} {{ end }}'"
  done
fi
# 4. security module off -> drop the loki rules
[ "${MODULE_SECURITY:-true}" = true ] || rm -rf "$ROOT/build/loki/rules"

echo "rendered to build/"

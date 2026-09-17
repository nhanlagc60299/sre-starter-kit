#!/usr/bin/env bash
# Render core/**/*.tpl with values from .env into build/, copy everything else as-is.
set -euo pipefail
ROOT="$(pwd)"
[ -f "$ROOT/.env" ] || { echo "ERROR: .env not found. Run 'make init' first." >&2; exit 1; }
set -a; . "$ROOT/.env"; set +a
# Alertmanager crash-loops on an empty slack api_url. Slack is optional now: with no URL the slack_configs
# blocks are stripped below, but SOME receiver has to exist or every alert is dropped on the floor.
# Guarded on the template so the minimal render fixture in tests/ is unaffected.
if [ -f "$ROOT/core/alertmanager/alertmanager.yml.tpl" ]; then
  if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
    echo "ERROR: TELEGRAM_BOT_TOKEN is set but TELEGRAM_CHAT_ID is empty." >&2
    exit 1
  fi
  # Telegram needs both the bot token and the chat id to actually notify anyone; the token alone
  # is not a usable receiver, so it does not count towards "at least one" below.
  tg=""; [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] && tg=1
  if [ -z "${SLACK_WEBHOOK_URL:-}${DISCORD_WEBHOOK_URL:-}${ALERT_EMAIL_TO:-}${tg}${TEAMS_WEBHOOK_URL:-}" ]; then
    echo "ERROR: no alert receiver configured. Set at least one of SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, ALERT_EMAIL_TO, TELEGRAM_BOT_TOKEN or TEAMS_WEBHOOK_URL in .env (or run 'make init')." >&2
    exit 1
  fi
  if [ -n "${ALERT_EMAIL_TO:-}" ] && { [ -z "${SMTP_HOST:-}" ] || [ -z "${SMTP_FROM:-}" ]; }; then
    echo "ERROR: ALERT_EMAIL_TO is set but SMTP_HOST or SMTP_FROM is empty." >&2
    exit 1
  fi
fi
# node-exporter runs in the host netns (see compose/docker-compose.yml), so the address Prometheus
# reaches it on depends on the container engine. This must default here rather than rely on .env: a
# .env written before this key existed has no such line, and because only keys found in .env are
# substituted, an unsubstituted ${NODE_EXPORTER_TARGET} would survive into prometheus.yml as a
# literal and break the scrape.
: "${NODE_EXPORTER_TARGET:=node-exporter:9100}"
export NODE_EXPORTER_TARGET
rm -rf "$ROOT/build"; mkdir -p "$ROOT/build"
# Only substitute variables that are defined in .env, so Prometheus/Alloy $labels etc. survive.
VARS="$(grep -oE '^[A-Z_][A-Z0-9_]*=' "$ROOT/.env" | sed 's/=$//' | sed 's/^/\$/' | tr '\n' ' ') \$NODE_EXPORTER_TARGET"
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
INFRA="$ROOT/build/prometheus/rules/infra.yml"
if [ -f "$INFRA" ]; then
  sed -i.bak -e "s/\* 100 < 5$/* 100 < __CRIT__/" -e "s/\* 100 < 15$/* 100 < __WARN__/" "$INFRA"
  sed -i.bak -e "s/__CRIT__/${DISK_CRIT_PCT:-5}/" -e "s/__WARN__/${DISK_WARN_PCT:-15}/" "$INFRA"
  rm -f "$INFRA.bak"
  # A rules edit that renames or reflows these two expressions would silently ship the defaults.
  grep -q "\* 100 < ${DISK_CRIT_PCT:-5}\$" "$INFRA" && grep -q "\* 100 < ${DISK_WARN_PCT:-15}\$" "$INFRA" || {
    echo "ERROR: disk thresholds were not applied to $INFRA (expected crit ${DISK_CRIT_PCT:-5}%, warn ${DISK_WARN_PCT:-15}%)." >&2
    echo "       core/prometheus/rules/infra.yml must keep the '* 100 < 5' / '* 100 < 15' expressions." >&2
    exit 1; }
fi
# 3. optional receivers
AM="$ROOT/build/alertmanager/alertmanager.yml"
add() { # marker block
  python3 - "$AM" "$1" "$2" <<'PY'
import sys
p,marker,block=sys.argv[1:]; s=open(p).read()
if "    # "+marker not in s:
    sys.exit("ERROR: receiver marker '%s' not found in %s - core/alertmanager/alertmanager.yml.tpl must keep it." % (marker,p))
open(p,"w").write(s.replace("    # "+marker, block+"\n    # "+marker))
PY
}
# Slack optional: drop the slack_configs block from both receivers when the URL is empty. Runs BEFORE the
# optional blocks are added, since it removes every line indented deeper than 4 spaces after slack_configs.
if [ -f "$AM" ] && [ -z "${SLACK_WEBHOOK_URL:-}" ]; then
  python3 - "$AM" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p).read()
s2=re.sub(r"^    slack_configs:\n(?:^ {5,}.*\n)*", "", s, flags=re.M)
if s2.count("slack_configs") or s2==s:
    sys.exit("ERROR: could not strip slack_configs from %s - core/alertmanager/alertmanager.yml.tpl changed shape" % p)
open(p,"w").write(s2)
PY
fi
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
if [ -f "$AM" ] && [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
  for m in RECEIVERS_CRITICAL_EXTRA RECEIVERS_WARNING_EXTRA; do
    add "$m" "    discord_configs:
      - webhook_url: ${DISCORD_WEBHOOK_URL:-}
        send_resolved: true
        title: '[${PROJECT_NAME:-}] {{ .CommonLabels.alertname }}'
        message: '{{ range .Alerts }}{{ .Annotations.summary }} {{ .Annotations.runbook_url }} {{ end }}'"
  done
fi
if [ -f "$AM" ] && [ -n "${ALERT_EMAIL_TO:-}" ]; then
  auth=""
  # YAML single-quoted scalars escape ' by doubling it ('' ); backslash is not special there, so it
  # needs no escaping. Without this a password containing a quote breaks the YAML parse (amtool/Alertmanager).
  pw_esc=$(printf '%s' "${SMTP_PASSWORD:-}" | sed "s/'/''/g")
  [ -n "${SMTP_USER:-}" ] && auth="
        auth_username: ${SMTP_USER}
        auth_password: '${pw_esc}'"
  for m in RECEIVERS_CRITICAL_EXTRA RECEIVERS_WARNING_EXTRA; do
    add "$m" "    email_configs:
      - to: ${ALERT_EMAIL_TO}
        from: ${SMTP_FROM:-}
        smarthost: ${SMTP_HOST:-}${auth}
        send_resolved: true
        headers: { Subject: '[${PROJECT_NAME:-}] {{ .CommonLabels.alertname }} ({{ .Status }})' }"
  done
fi
# 4. security module off -> drop only its rules; the log alerts in logs.yml are not part of the module
[ "${MODULE_SECURITY:-true}" = true ] || rm -f "$ROOT/build/loki/rules/fake/security.yml"

echo "rendered to build/"

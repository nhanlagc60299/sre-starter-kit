#!/usr/bin/env bash
# Interactive wizard. Writes .env. Re-run to change answers (previous values become defaults).
set -euo pipefail
ROOT="$(pwd)"
[ -f "$ROOT/.env" ] && { set -a; . "$ROOT/.env"; set +a; }
ask() { # var prompt default
  local v="$1" p="$2" d="${!1:-$3}"
  read -r -p "$p [${d}]: " a
  printf -v "$v" '%s' "${a:-$d}"
}
echo "== SRE Starter Kit setup =="
ask PROJECT_NAME "Project name" "myproject"
ask SLACK_WEBHOOK_URL "Slack webhook URL (required)" ""
ask TELEGRAM_BOT_TOKEN "Telegram bot token (optional)" ""
ask TELEGRAM_CHAT_ID "Telegram chat id (optional)" ""
ask TEAMS_WEBHOOK_URL "MS Teams Workflows webhook URL (optional)" ""
echo "Services to probe, one per line as name=http://host:port/health. Empty line to finish."
svcs=()
while true; do
  read -r -p "  service: " line
  [ -z "$line" ] && break
  [[ "$line" == *=http* ]] || { echo "  format: name=http://..."; continue; }
  svcs+=("$line")
done
[ ${#svcs[@]} -gt 0 ] && SERVICES=$(IFS=,; echo "${svcs[*]}")
ask DISK_WARN_PCT "Disk free % warning threshold" "15"
ask DISK_CRIT_PCT "Disk free % critical threshold" "5"
ask PROM_RETENTION_TIME "Prometheus retention" "15d"
ask LOKI_RETENTION_PERIOD "Loki retention" "168h"
ask GRAFANA_ADMIN_PASSWORD "Grafana admin password" "change-me"
# Keep the current setting as the default so a re-run does not silently re-enable it.
case "${MODULE_SECURITY:-true}" in true) sec_default=y ;; *) sec_default=n ;; esac
ask MODULE_SECURITY_ANS "Enable SSH early-warning alerts? (y/n)" "$sec_default"
case "$MODULE_SECURITY_ANS" in y|Y|yes|YES) MODULE_SECURITY=true ;; *) MODULE_SECURITY=false ;; esac
[ -z "$SLACK_WEBHOOK_URL" ] && { echo "ERROR: Slack webhook is required in the free tier." >&2; exit 1; }

cat > "$ROOT/.env" <<ENV
PROJECT_NAME=$PROJECT_NAME
SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL
TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID
TEAMS_WEBHOOK_URL=$TEAMS_WEBHOOK_URL
TRIAGE_WEBHOOK_URL=${TRIAGE_WEBHOOK_URL:-http://localhost:9/}
SERVICES=${SERVICES:-}
DISK_WARN_PCT=$DISK_WARN_PCT
DISK_CRIT_PCT=$DISK_CRIT_PCT
PROM_RETENTION_TIME=$PROM_RETENTION_TIME
PROM_RETENTION_SIZE=${PROM_RETENTION_SIZE:-20GB}
LOKI_RETENTION_PERIOD=$LOKI_RETENTION_PERIOD
GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD
MODULE_SECURITY=$MODULE_SECURITY
AUTH_LOG_PATH=${AUTH_LOG_PATH:-/var/log/auth.log}
CONTAINER_SOCK=${CONTAINER_SOCK:-/var/run/docker.sock}
COMPOSE_PROFILES=${COMPOSE_PROFILES:-cadvisor}
ENV
echo "wrote .env"

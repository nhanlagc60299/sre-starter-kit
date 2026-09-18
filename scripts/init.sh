#!/usr/bin/env bash
# Interactive wizard. Writes .env. Re-run to change answers (previous values become defaults).
set -euo pipefail
umask 077   # .env holds the Grafana password and every webhook token
ROOT="$(pwd)"
[ -f "$ROOT/.env" ] && { set -a; . "$ROOT/.env"; set +a; }
ask() { # var prompt default
  local v="$1" p="$2" d="${!1:-$3}"
  read -r -p "$p [${d}]: " a || a=
  printf -v "$v" '%s' "${a:-$d}"
}
ask_secret() { # var prompt -- input hidden; empty answer keeps the current value
  local v="$1" p="$2" cur="${!1:-}" shown
  [ -n "$cur" ] && shown="[unchanged]" || shown="[empty]"
  read -rs -p "$p $shown: " a || a=
  echo
  printf -v "$v" '%s' "${a:-$cur}"
}
ask_pct() { # var prompt default -- integer 1-99
  while true; do
    ask "$1" "$2" "$3"
    case "${!1}" in [1-9]|[1-9][0-9]) return 0 ;; esac
    echo "  enter a number 1-99"
  done
}
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }  # shell-quote a value for .env
echo "== SRE Starter Kit setup =="
ask PROJECT_NAME "Project name" "myproject"
ask SLACK_WEBHOOK_URL "Slack webhook URL (optional if you set another receiver below)" ""
ask TELEGRAM_BOT_TOKEN "Telegram bot token (optional)" ""
ask TELEGRAM_CHAT_ID "Telegram chat id (optional)" ""
ask TEAMS_WEBHOOK_URL "MS Teams Workflows webhook URL (optional)" ""
echo "Services to probe, one per line as name=http://host:port/health. Empty line to finish."
echo "Name each probe after its compose service name so its logs and metrics line up in the dashboards."
svcs=()
while true; do
  read -r -p "  service: " line
  [ -z "$line" ] && break
  case "$line" in *,*) echo "  commas are not allowed in a service line"; continue ;; esac
  [[ "$line" == *=http* ]] || { echo "  format: name=http://..."; continue; }
  svcs+=("$line")
done
[ ${#svcs[@]} -gt 0 ] && SERVICES=$(IFS=,; echo "${svcs[*]}")
ask_pct DISK_WARN_PCT "Disk free % warning threshold" "15"
ask_pct DISK_CRIT_PCT "Disk free % critical threshold" "5"
ask PROM_RETENTION_TIME "Prometheus retention" "15d"
ask LOKI_RETENTION_PERIOD "Loki retention" "168h"
ask GRAFANA_ADMIN_PASSWORD "Grafana admin password" "change-me"
# Keep the current setting as the default so a re-run does not silently re-enable it.
case "${MODULE_SECURITY:-true}" in true) sec_default=y ;; *) sec_default=n ;; esac
ask MODULE_SECURITY_ANS "Enable SSH early-warning alerts? (y/n)" "$sec_default"
case "$MODULE_SECURITY_ANS" in y|Y|yes|YES) MODULE_SECURITY=true ;; *) MODULE_SECURITY=false ;; esac
ask CONTAINER_SOCK "Container socket" "/var/run/docker.sock"
# cAdvisor needs Docker's /var/lib/docker, so it is a profile rather than a plain service.
case "${COMPOSE_PROFILES-cadvisor}" in *cadvisor*) cad_default=y ;; *) cad_default=n ;; esac  # unset (first run) -> on; empty -> off
ask CADVISOR_ANS "Enable cAdvisor container metrics? (y/n; answer n on Podman)" "$cad_default"
case "$CADVISOR_ANS" in y|Y|yes|YES) COMPOSE_PROFILES=cadvisor ;; *) COMPOSE_PROFILES= ;; esac
if [ "$MODULE_SECURITY" = true ]; then
  ask AUTH_LOG_PATH "Auth log path (RHEL/Amazon Linux: /var/log/secure)" "/var/log/auth.log"
fi
ask DISCORD_WEBHOOK_URL "Discord webhook URL (optional)" ""
ask ALERT_EMAIL_TO "Email address(es) for alerts, comma-separated (optional)" ""
if [ -n "$ALERT_EMAIL_TO" ]; then
  ask SMTP_HOST "SMTP host:port (STARTTLS)" "smtp.gmail.com:587"
  ask SMTP_FROM "From address" "${ALERT_EMAIL_TO%%,*}"
  ask SMTP_USER "SMTP username (empty = no auth)" "$SMTP_FROM"
  [ -n "$SMTP_USER" ] && ask_secret SMTP_PASSWORD "SMTP password"
fi
# AI triage: a copy of every critical alert goes to the triage agent (profile "triage"), which
# gathers context from this stack and, with a licence key, asks the triage service for a note.
# Without a key it only prints the context pack to its own log (dry run) so you can see what
# would leave your network before you decide.
# The re-run default is probed from TRIAGE_WEBHOOK_URL, not COMPOSE_PROFILES: the cAdvisor
# question above already overwrote COMPOSE_PROFILES by the time we get here.
case "${TRIAGE_WEBHOOK_URL:-}" in http://triage-agent:9096/alert) tri_default=y ;; *) tri_default=n ;; esac
ask TRIAGE_ANS "Enable AI triage notes for critical alerts? (y/n)" "$tri_default"
case "$TRIAGE_ANS" in y|Y|yes|YES)
  COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}triage"
  TRIAGE_WEBHOOK_URL=http://triage-agent:9096/alert
  ask_secret TRIAGE_LICENSE_KEY "Triage licence key (empty = dry run: the pack is only printed to the agent's log)"
  [ -n "${TRIAGE_LICENSE_KEY:-}" ] && TRIAGE_DRY_RUN=false || TRIAGE_DRY_RUN=true ;;
*) TRIAGE_WEBHOOK_URL=http://localhost:9/; TRIAGE_DRY_RUN=true ;;
esac
# Telegram needs both the bot token and the chat id to actually notify anyone; the token alone
# is not a usable receiver, so it does not count towards "at least one" below.
tg=""; [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] && tg=1
[ -z "${SLACK_WEBHOOK_URL}${DISCORD_WEBHOOK_URL}${ALERT_EMAIL_TO}${tg}${TEAMS_WEBHOOK_URL}" ] && { echo "ERROR: configure at least one receiver (Slack, Discord, email, Telegram or Teams)." >&2; exit 1; }

cat > "$ROOT/.env" <<ENV
PROJECT_NAME=$(q "$PROJECT_NAME")
BIND_ADDR=$(q "${BIND_ADDR:-127.0.0.1}")
ALERTMANAGER_EXTERNAL_URL=$(q "${ALERTMANAGER_EXTERNAL_URL:-http://localhost:9093}")
SLACK_WEBHOOK_URL=$(q "$SLACK_WEBHOOK_URL")
TELEGRAM_BOT_TOKEN=$(q "$TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID=$(q "$TELEGRAM_CHAT_ID")
TEAMS_WEBHOOK_URL=$(q "$TEAMS_WEBHOOK_URL")
DISCORD_WEBHOOK_URL=$(q "${DISCORD_WEBHOOK_URL:-}")
ALERT_EMAIL_TO=$(q "${ALERT_EMAIL_TO:-}")
SMTP_HOST=$(q "${SMTP_HOST:-}")
SMTP_FROM=$(q "${SMTP_FROM:-}")
SMTP_USER=$(q "${SMTP_USER:-}")
SMTP_PASSWORD=$(q "${SMTP_PASSWORD:-}")
TRIAGE_WEBHOOK_URL=$(q "${TRIAGE_WEBHOOK_URL:-http://localhost:9/}")
TRIAGE_DRY_RUN=$(q "${TRIAGE_DRY_RUN:-true}")
TRIAGE_LICENSE_KEY=$(q "${TRIAGE_LICENSE_KEY:-}")
TRIAGE_API_URL=$(q "${TRIAGE_API_URL:-}")
TRIAGE_REDACT=$(q "${TRIAGE_REDACT:-}")
SERVICES=$(q "${SERVICES:-}")
DISK_WARN_PCT=$(q "$DISK_WARN_PCT")
DISK_CRIT_PCT=$(q "$DISK_CRIT_PCT")
PROM_RETENTION_TIME=$(q "$PROM_RETENTION_TIME")
PROM_RETENTION_SIZE=$(q "${PROM_RETENTION_SIZE:-20GB}")
LOKI_RETENTION_PERIOD=$(q "$LOKI_RETENTION_PERIOD")
GRAFANA_ADMIN_PASSWORD=$(q "$GRAFANA_ADMIN_PASSWORD")
MODULE_SECURITY=$(q "$MODULE_SECURITY")
AUTH_LOG_PATH=$(q "${AUTH_LOG_PATH:-/var/log/auth.log}")
CONTAINER_SOCK=$(q "${CONTAINER_SOCK:-/var/run/docker.sock}")
COMPOSE_PROFILES=$(q "${COMPOSE_PROFILES:-}")
ENV
echo "wrote .env"

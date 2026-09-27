#!/usr/bin/env bash
# Keep Grafana's persisted admin password in sync with .env after `make up`. Grafana only applies
# GF_SECURITY_ADMIN_PASSWORD when it creates the admin user in an empty database (its own sqlite
# file, on the grafana-data volume); a later .env change alone never reaches an already-provisioned
# grafana.db. This runs `grafana cli admin reset-admin-password --password-from-stdin` INSIDE the
# grafana container, reading GF_SECURITY_ADMIN_PASSWORD from the container's own environment - the
# password is never on this script's argv, or the host's.
#
# Best-effort: this never fails `make up`. A rotation that cannot complete leaves the previous
# password in place, which is at worst what shipped before this script existed.
set -uo pipefail
cd "$(dirname "$0")/.."
CE=${CONTAINER_ENGINE:-docker}
COMPOSE="$CE compose --env-file .env -f compose/docker-compose.yml"
for f in compose/docker-compose.*.yml; do [ -e "$f" ] && COMPOSE="$COMPOSE -f $f"; done

cid=$($COMPOSE ps -q grafana 2>/dev/null)
if [ -z "$cid" ]; then
  exit 0   # grafana is not part of this run (e.g. it failed to start); nothing to rotate
fi

# Never run the CLI while Grafana's own process might still be migrating that same sqlite file: a
# concurrent write while the server's own migration is in flight corrupted grafana.db irrecoverably
# in testing (task-11-report.md). Wait for the server's own readiness signal before touching it a
# second way, rather than retrying the CLI itself on failure.
ready=false
for _ in $(seq 1 30); do
  $COMPOSE exec -T grafana wget -q -O /dev/null http://localhost:3000/api/health >/dev/null 2>&1 && { ready=true; break; }
  sleep 2
done
if [ "$ready" != true ]; then
  echo "WARN: grafana did not become ready within 60s; the admin password was not rotated (best-effort, 'make up' still succeeded)." >&2
  exit 0
fi

out=$($COMPOSE exec -T grafana sh -c 'echo "$GF_SECURITY_ADMIN_PASSWORD" | grafana cli admin reset-admin-password --password-from-stdin' 2>&1)
if printf '%s' "$out" | grep -q "changed successfully"; then
  exit 0
fi
echo "WARN: could not rotate the Grafana admin password; it may still be the previous value (best-effort, 'make up' still succeeded)." >&2
printf '%s\n' "$out" | tail -5 >&2
exit 0

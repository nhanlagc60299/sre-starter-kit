#!/usr/bin/env bash
# `cp .env.example .env` must not produce a config that crash-loops Alertmanager.
set -euo pipefail
cd "$(dirname "$0")/.."

# I6: compose's dotenv reader strips an inline comment only when a value precedes it; with an empty
# value it takes the comment text as the value instead. The TRIAGE_* keys are consumed only through
# compose's `environment:` block for the triage-agent service (unlike the older receiver keys, whose
# broken-looking `KEY=   # comment` shape is harmless because render.sh shell-sources .env, where a
# comment after whitespace is a real comment) -- so a `TRIAGE_KEY=  # ...` line ships genuinely
# broken with nothing to catch it, which is exactly what shipped before this fix.
bad=$(grep -nE '^TRIAGE_[A-Za-z0-9_]*=[[:space:]]*#' .env.example || true)
[ -z "$bad" ] || { echo "FAIL: .env.example has a TRIAGE_* key with an empty value and an inline comment:"; echo "$bad"; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r core scripts compose .env.example "$tmp/"
cp .env.example "$tmp/.env"          # unmodified, exactly what a copy-paste install gives you

out=$( cd "$tmp" && bash scripts/render.sh 2>&1 ) && { echo "FAIL: render succeeded with no receiver configured"; exit 1; }
case "$out" in
  *"ERROR: no alert receiver configured."*) ;;
  *) echo "FAIL: wrong error message: $out"; exit 1 ;;
esac

sed -i.bak 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' "$tmp/.env" && rm -f "$tmp/.env.bak"
( cd "$tmp" && bash scripts/render.sh >/dev/null ) || { echo "FAIL: render failed with a webhook set"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml

# I6 live check: the triage-agent's own `environment:` block reads these three straight from .env
# (compose/docker-compose.yml), so this is the actual parser that mattered -- confirm each is really
# an empty string, not the comment text, under `--profile triage config`.
cfg=$( cd "$tmp" && ${CONTAINER_ENGINE:-docker} compose --profile triage --env-file .env -f compose/docker-compose.yml config )
for k in TRIAGE_LICENSE_KEY TRIAGE_API_URL TRIAGE_REDACT; do
  [[ "$cfg" == *"$k: \"\""* ]] || { echo "FAIL: $k is not an empty string under --profile triage config"; exit 1; }
done

# The Slack link on every alert is Alertmanager's external URL. Unset, it is the container's
# hostname, which nobody can click. compose reads the key straight from .env.
cfg=$( cd "$tmp" && ALERTMANAGER_EXTERNAL_URL=https://am.example.test ${CONTAINER_ENGINE:-docker} compose --env-file .env -f compose/docker-compose.yml config )
[[ "$cfg" == *"--web.external-url=https://am.example.test"* ]] || { echo "FAIL: ALERTMANAGER_EXTERNAL_URL not passed to alertmanager"; exit 1; }
cfg=$( cd "$tmp" && ${CONTAINER_ENGINE:-docker} compose --env-file .env -f compose/docker-compose.yml config )
[[ "$cfg" == *"--web.external-url=http://localhost:9093"* ]] || { echo "FAIL: .env.example's ALERTMANAGER_EXTERNAL_URL not passed to alertmanager"; exit 1; }

# .env.example already sets ALERTMANAGER_EXTERNAL_URL, so the check above can't tell that value
# apart from compose/docker-compose.yml's own default. Strip the key and confirm the
# ${ALERTMANAGER_EXTERNAL_URL:-http://localhost:9093} fallback still renders it.
grep -v '^ALERTMANAGER_EXTERNAL_URL=' "$tmp/.env" > "$tmp/.env.no-external-url" || true
cfg=$( cd "$tmp" && ${CONTAINER_ENGINE:-docker} compose --env-file .env.no-external-url -f compose/docker-compose.yml config )
[[ "$cfg" == *"--web.external-url=http://localhost:9093"* ]] || { echo "FAIL: external URL has no default"; exit 1; }

echo "test_env_example OK"

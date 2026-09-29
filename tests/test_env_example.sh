#!/usr/bin/env bash
# `cp .env.example .env` must not produce a config that crash-loops Alertmanager.
set -euo pipefail
cd "$(dirname "$0")/.."

# I6: compose's dotenv reader strips an inline comment only when a value precedes it; with an empty
# value it takes the comment text as the value instead. The TRIAGE_* keys are consumed only through
# compose's `environment:` block for the triage-agent service (unlike the older receiver keys, whose
# broken-looking `KEY=   # comment` shape was "fine to ship" only because render.sh shell-sources
# .env, where a comment after whitespace is a real comment) -- so a `TRIAGE_KEY=  # ...` line ships
# genuinely broken with nothing to catch it, which is exactly what shipped before this fix. M4
# (synced from Pro) widens this from TRIAGE_* to every key: the render.sh escape hatch bounded the
# blast radius, it didn't make the shape correct, and the guard should not depend on which parser
# happens to read a given key today.
bad=$(grep -nE '^[A-Za-z_][A-Za-z0-9_]*=[[:space:]]*#' .env.example || true)
[ -z "$bad" ] || { echo "FAIL: .env.example has a key with an empty value and an inline comment:"; echo "$bad"; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r core scripts compose .env.example "$tmp/"
cp .env.example "$tmp/.env"          # unmodified, exactly what a copy-paste install gives you
# .env.example ships GRAFANA_ADMIN_PASSWORD empty on purpose (render.sh refuses it, checked below);
# set a real one here so the receiver checks that follow fail for the reason they say they do.
sed -i.bak 's/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' "$tmp/.env" && rm -f "$tmp/.env.bak"

out=$( cd "$tmp" && bash scripts/render.sh 2>&1 ) && { echo "FAIL: render succeeded with no receiver configured"; exit 1; }
case "$out" in
  *"ERROR: no alert receiver configured."*) ;;
  *) echo "FAIL: wrong error message: $out"; exit 1 ;;
esac

sed -i.bak 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#' "$tmp/.env" && rm -f "$tmp/.env.bak"
( cd "$tmp" && bash scripts/render.sh >/dev/null ) || { echo "FAIL: render failed with a webhook set"; exit 1; }

# GRAFANA_ADMIN_PASSWORD must never be empty, nor .env.example's own published default. Checked here
# because a plain `cp .env.example .env` is exactly the shape that used to ship 'change-me' silently.
for bad_pw in change-me "" abc admin; do
  sed -i.bak "s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=$bad_pw/" "$tmp/.env" && rm -f "$tmp/.env.bak"
  out=$( cd "$tmp" && bash scripts/render.sh 2>&1 ) && { echo "FAIL: render accepted GRAFANA_ADMIN_PASSWORD='$bad_pw'"; exit 1; }
  case "$out" in
    *"GRAFANA_ADMIN_PASSWORD"*) ;;
    *) echo "FAIL: wrong error message for GRAFANA_ADMIN_PASSWORD='$bad_pw': $out"; exit 1 ;;
  esac
done
# A line break inside the (quoted, so bash accepts it) value: refused like the rest, by name.
grep -v '^GRAFANA_ADMIN_PASSWORD=' "$tmp/.env" > "$tmp/.env.nopw"
for nl in '\n' '\r'; do
  { cat "$tmp/.env.nopw"; printf "GRAFANA_ADMIN_PASSWORD='line-one${nl}line-two'\n"; } > "$tmp/.env"
  out=$( cd "$tmp" && bash scripts/render.sh 2>&1 ) && { echo "FAIL: render accepted a GRAFANA_ADMIN_PASSWORD with a line break ($nl)"; exit 1; }
  case "$out" in
    *"GRAFANA_ADMIN_PASSWORD"*"line break"*) ;;
    *) echo "FAIL: wrong error message for a GRAFANA_ADMIN_PASSWORD with a line break ($nl): $out"; exit 1 ;;
  esac
done
{ cat "$tmp/.env.nopw"; echo "GRAFANA_ADMIN_PASSWORD=fixture-pw"; } > "$tmp/.env"
sed -i.bak 's/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' "$tmp/.env" && rm -f "$tmp/.env.bak"   # restore for the checks below
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml

# I6 live check: the triage-agent's own `environment:` block reads this straight from .env
# (compose/docker-compose.yml), so this is the actual parser that mattered -- confirm it is really
# an empty string, not the comment text, under `--profile triage config`.
cfg=$( cd "$tmp" && ${CONTAINER_ENGINE:-docker} compose --profile triage --env-file .env -f compose/docker-compose.yml config )
for k in TRIAGE_REDACT TRIAGE_WEBHOOK_TOKEN TRIAGE_MAX_RUNS_PER_HOUR; do
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

# A copy of .env (.env.bak, .env.prod, .env.local) holds the same secrets: git ignores every one of
# them, but still tracks the example.
for f in .env .env.bak .env.prod .env.local; do
  git check-ignore -q --no-index "$f" || { echo "FAIL: git does not ignore $f"; exit 1; }
done
if git check-ignore -q --no-index .env.example; then echo "FAIL: .env.example is ignored"; exit 1; fi

echo "test_env_example OK"

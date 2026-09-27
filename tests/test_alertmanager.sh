#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#; s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' .env.example > "$tmp/.env"
cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml
grep -q 'severity="critical"' "$tmp/build/alertmanager/alertmanager.yml"  # sanity: routing present
! grep -q '^ *http_config:' "$tmp/build/alertmanager/alertmanager.yml" || { echo "FAIL: empty TRIAGE_WEBHOOK_TOKEN still renders an http_config"; exit 1; }
# A token set: webhook-triage sends it as a Bearer credential. The quote proves the single-quoted YAML
# escaping; amtool proves Alertmanager itself accepts the block.
printf '%s\n' "TRIAGE_WEBHOOK_TOKEN=\"ab'cd\"" >> "$tmp/.env"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml
python3 - "$tmp/build/alertmanager/alertmanager.yml" <<'PYTOK' || { echo "FAIL: webhook-triage does not send TRIAGE_WEBHOOK_TOKEN"; exit 1; }
import sys,yaml
by={r["name"]: r for r in yaml.safe_load(open(sys.argv[1]))["receivers"]}
wc=by["webhook-triage"]["webhook_configs"][0]
assert wc.get("http_config",{}).get("authorization")=={"type": "Bearer", "credentials": "ab'cd"}, wc
assert all("http_config" not in c for n,r in by.items() if n!="webhook-triage" for c in r.get("webhook_configs",[])), "token leaked to another webhook"
PYTOK
# The agent compares the header as bytes of a latin-1 decode against UTF-8 bytes of the token, so a
# non-ASCII token can never match: every alert would get a 401. Refuse to render it instead.
printf 'TRIAGE_WEBHOOK_TOKEN=t\303\266k\n' >> "$tmp/.env"   # "tök", UTF-8
if out=$( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" 2>&1 ); then echo "FAIL: render accepted a non-ASCII TRIAGE_WEBHOOK_TOKEN"; exit 1; fi
[[ "$out" == *"TRIAGE_WEBHOOK_TOKEN"* ]] || { echo "FAIL: non-ASCII token refused without naming the key: $out"; exit 1; }

# Task 13: AWS Name tags, Pushgateway/StatsD/postgres_exporter labels reach these same annotation
# fields unescaped from lower-trust producers. Every notification title/text/message action that
# interpolates CommonLabels/Labels/GroupLabels/Annotations/CommonAnnotations must be piped through
# Alertmanager's reReplaceAll sanitizer, for every receiver this kit renders. Fresh fixture,
# independent of the .env accumulated above (which ends deliberately poisoned by the non-ASCII-token
# negative test just above).
tmp2=$(mktemp -d); trap 'rm -rf "$tmp" "$tmp2"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#; s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' .env.example > "$tmp2/.env"
cat >> "$tmp2/.env" <<'ENV'
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1/x
TEAMS_WEBHOOK_URL=https://example.webhook.office.com/webhookb2/xxx
TELEGRAM_BOT_TOKEN=123:abc
TELEGRAM_CHAT_ID=-1001
ALERT_EMAIL_TO=a@example.invalid
SMTP_HOST=smtp.example.invalid:587
SMTP_FROM=b@example.invalid
ENV
cp -r core "$tmp2/core"
( cd "$tmp2" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp2/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml
python3 - "$tmp2/build/alertmanager/alertmanager.yml" <<'PYSAN' || { echo "FAIL: an unsanitized label/annotation action reaches a notification field"; exit 1; }
import re, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
ACTION = re.compile(r"\{\{.*?\}\}", re.S)
SENSITIVE = re.compile(r"\.(CommonLabels|Labels|GroupLabels|Annotations|CommonAnnotations)\b")
bad = []
by = {r["name"]: r for r in cfg["receivers"]}
for r in cfg["receivers"]:
    for kind in ("slack_configs", "discord_configs", "msteamsv2_configs", "telegram_configs", "email_configs"):
        for c in r.get(kind, []):
            fields = [(f, c[f]) for f in ("title", "text", "message") if f in c]
            subj = c.get("headers", {}).get("Subject")
            if subj:
                fields.append(("headers.Subject", subj))
            for fname, text in fields:
                for action in ACTION.findall(text):
                    if SENSITIVE.search(action) and "reReplaceAll" not in action:
                        bad.append((r["name"], kind, fname, action))
if bad:
    for b in bad:
        print("UNSANITIZED:", b)
    sys.exit(1)
for rname in ("critical", "warning"):
    assert by[rname]["slack_configs"][0].get("link_names") is False, (rname, "link_names not explicitly disabled")
assert by["critical"].get("discord_configs") and by["critical"].get("msteamsv2_configs") and by["critical"].get("telegram_configs") and by["critical"].get("email_configs"), "fixture did not render every optional receiver"
print("all label/annotation actions sanitized")
PYSAN
# Runtime proof, not just a source-level shape check: render the ACTUAL critical-Slack text field
# through amtool with a hostile annotation value (an AWS Name tag / Pushgateway job / StatsD dag_id /
# postgres relname could all put this in .Annotations.summary) and show the output is inert.
crit_text=$(python3 - "$tmp2/build/alertmanager/alertmanager.yml" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
by = {r["name"]: r for r in cfg["receivers"]}
print(by["critical"]["slack_configs"][0]["text"], end="")
PY
)
cat > "$tmp2/hostile.json" <<'JSON'
{"Alerts":[{"Status":"firing","Labels":{},"Annotations":{"summary":"<!channel> [click](https://evil.test) @everyone","runbook_url":"https://github.com/nhanlagc60299/sre-starter-kit-pro/blob/main/runbooks/Test.md","dashboard":"abc"}}],"GroupLabels":{},"CommonLabels":{"alertname":"Test"},"CommonAnnotations":{},"ExternalURL":""}
JSON
out=$(${CONTAINER_ENGINE:-docker} run --rm -v "$tmp2:/c" --entrypoint amtool prom/alertmanager:v0.28.1 template render --template.glob="/c/*.nonexistent" --template.data=/c/hostile.json --template.text="$crit_text")
echo "$out" | grep -q '<!channel>' && { echo "FAIL: <!channel> survived unescaped in the rendered Slack text: $out"; exit 1; }
echo "$out" | grep -qE '\[click\]\(' && { echo "FAIL: a masked link survived in the rendered Slack text: $out"; exit 1; }
echo "$out" | grep -q '@everyone' && { echo "FAIL: @everyone survived unescaped in the rendered Slack text: $out"; exit 1; }
echo "amtool template render: hostile label/annotation text is inert -> $out"

echo "test_alertmanager OK"

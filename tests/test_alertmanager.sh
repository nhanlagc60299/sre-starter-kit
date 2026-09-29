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
python3 - "$tmp/build/alertmanager/alertmanager.yml" <<'PYTOK' || { echo "FAIL: webhook-triage does not send TRIAGE_WEBHOOK_TOKEN, or has no max_alerts: 20"; exit 1; }
import sys,yaml
by={r["name"]: r for r in yaml.safe_load(open(sys.argv[1]))["receivers"]}
wc=by["webhook-triage"]["webhook_configs"][0]
assert wc.get("http_config",{}).get("authorization")=={"type": "Bearer", "credentials": "ab'cd"}, wc
# a group of thousands of alerts (anyone who reaches Alertmanager's API can post them) reaches the
# agent as at most 20, the rest counted in truncatedAlerts
assert wc.get("max_alerts")==20, ("webhook-triage max_alerts", wc.get("max_alerts"))
assert all("http_config" not in c for n,r in by.items() if n!="webhook-triage" for c in r.get("webhook_configs",[])), "token leaked to another webhook"
PYTOK
# The agent compares the header as bytes of a latin-1 decode against UTF-8 bytes of the token, so a
# non-ASCII token can never match: every alert would get a 401. Refuse to render it instead.
printf 'TRIAGE_WEBHOOK_TOKEN=t\303\266k\n' >> "$tmp/.env"   # "tök", UTF-8
if out=$( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" 2>&1 ); then echo "FAIL: render accepted a non-ASCII TRIAGE_WEBHOOK_TOKEN"; exit 1; fi
[[ "$out" == *"TRIAGE_WEBHOOK_TOKEN"* ]] || { echo "FAIL: non-ASCII token refused without naming the key: $out"; exit 1; }

# AWS Name tags, Pushgateway/StatsD/postgres_exporter labels reach these same annotation
# fields unescaped from lower-trust producers. Every notification title/text/message/fallback action
# that interpolates CommonLabels/Labels/GroupLabels/Annotations.summary/CommonAnnotations must be
# piped through the right reReplaceAll sanitizer, for every receiver this kit renders. Fresh fixture,
# independent of the .env accumulated above (which ends deliberately poisoned by the non-ASCII-token
# negative test just above).
tmp2=$(mktemp -d); trap 'rm -rf "$tmp" "$tmp2"' EXIT
# The amtool render steps below mount $tmp2 itself, and amtool runs as nobody: mktemp's 0700 makes
# every file in it unreadable there on Linux (CI), though podman on macOS hides that.
chmod 755 "$tmp2"
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

# Three rules, each from a defect found in review: (1) the Slack &/</> entity chain must never reach Discord/Teams/Telegram/email
# (it showed up literally as "&gt;"); (2) .Annotations.runbook_url/.dashboard are operator-authored
# and must go through NEITHER chain, in ANY receiver, or a query string in a dashboard link breaks;
# (3) Slack's fallback (used by clients that can't render the full message) must be explicitly
# sanitized too, since Alertmanager's own default fallback prints raw GroupLabels/CommonLabels.
python3 - "$tmp2/build/alertmanager/alertmanager.yml" "$tmp2/combined.txt" <<'PYSAN' || { echo "FAIL: sanitizer shape is wrong"; exit 1; }
import re, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
ACTION = re.compile(r"\{\{.*?\}\}", re.S)
ALWAYS_SENSITIVE = re.compile(r"\.(CommonLabels|Labels|GroupLabels|CommonAnnotations)\b")
ANNOT = re.compile(r"\.Annotations\.(\w+)")
EXEMPT_ANNOT = {"runbook_url", "dashboard"}
# anyone who can POST to Alertmanager's API sets runbook_url/dashboard, so they carry a link
# chain that strips only what breaks out of a link ([<>| everywhere, ) too on markdown receivers),
# never the text chain -- a query string's & must survive.
LINK = 'reReplaceAll "[[<>|]" ""'
MD_LINK = 'reReplaceAll "[[<>|)]" ""'
MD_KINDS = {"discord_configs", "msteamsv2_configs", "telegram_configs"}
by = {r["name"]: r for r in cfg["receivers"]}
bad = []
fields = {}  # key -> raw (pre-amtool) field text, for the runtime render step below
for r in cfg["receivers"]:
    for kind in ("slack_configs", "discord_configs", "msteamsv2_configs", "telegram_configs", "email_configs"):
        for c in r.get(kind, []):
            flds = [(f, c[f]) for f in ("title", "text", "message", "fallback") if f in c]
            subj = c.get("headers", {}).get("Subject")
            if subj:
                flds.append(("headers.Subject", subj))
            for fname, text in flds:
                key = "%s.%s.%s" % (r["name"], kind, fname)
                fields[key] = text
                for action in ACTION.findall(text):
                    annot = ANNOT.findall(action)
                    needs_sanitizer = bool(ALWAYS_SENSITIVE.search(action)) or any(a not in EXEMPT_ANNOT for a in annot)
                    exempt_only = annot and all(a in EXEMPT_ANNOT for a in annot) and not ALWAYS_SENSITIVE.search(action)
                    if needs_sanitizer:
                        if "reReplaceAll" not in action:
                            bad.append((key, "missing sanitizer", action))
                        elif kind == "slack_configs":
                            if "&amp;" not in action:
                                bad.append((key, "Slack field is missing the entity chain", action))
                        else:
                            if "&amp;" in action or "&lt;" in action or "&gt;" in action:
                                bad.append((key, "non-Slack field carries the Slack entity chain (garbles outside Slack)", action))
                    elif exempt_only:
                        want = MD_LINK if kind in MD_KINDS else LINK
                        if want not in action or "＠" in action or "&amp;" in action:
                            bad.append((key, "runbook_url/dashboard must carry only the link chain", action))
if bad:
    for b in bad:
        print("BAD SANITIZER SHAPE:", b)
    sys.exit(1)
for rname in ("critical", "warning"):
    sc = by[rname]["slack_configs"][0]
    assert sc.get("link_names") is False, (rname, "link_names not explicitly disabled")
    assert sc.get("fallback"), (rname, "Slack fallback not set")
assert by["critical"].get("discord_configs") and by["critical"].get("msteamsv2_configs") and by["critical"].get("telegram_configs") and by["critical"].get("email_configs"), "fixture did not render every optional receiver"
# Combined template text for the runtime render step: every field once, delimited so the rendered
# output can be split back apart per field.
with open(sys.argv[2], "w") as f:
    for key, text in fields.items():
        f.write("===%s===\n%s\n" % (key, text))
print("sanitizer shape OK: two text chains, link chains on runbook_url/dashboard, fallback set, link_names disabled")
PYSAN

# Runtime proof over EVERY notification field of every receiver, not just a source-level shape
# check: one hostile case (must render inert everywhere) and one ordinary case (an AWS Name tag /
# Pushgateway job / StatsD dag_id / postgres relname could carry either into .Annotations.summary,
# .CommonLabels.alertname or .GroupLabels.alertname). Batched into one amtool call per case via
# "===key===" delimiters, split back apart below -- one container start per case, not one per field.
# runbook_url uses this repo's own public URL shape (docs/ALERTS.md#<anchor>), not the private Pro
# repo's runbooks/<Name>.md.
cat > "$tmp2/hostile.json" <<'JSON'
{"Status":"firing","Receiver":"critical","Alerts":[{"Status":"firing","Labels":{},"Annotations":{"summary":"<!channel> <@U123> <https://evil.invalid|runbook> [click](https://evil.invalid) @everyone `x` &lt;!here&gt;\r\n# heading\n\u000b# vt\u000c# ff\u0085# nel\u2028# ls\u2029# ps","runbook_url":"https://github.com/nhanlagc60299/sre-starter-kit/blob/main/docs/ALERTS.md#test","dashboard":"abc"}}],"GroupLabels":{"alertname":"<!channel>"},"CommonLabels":{"alertname":"<!channel> [x](https://evil.invalid) @here\n# heading\u2028# ls\u0085# nel\u000b# vt"},"CommonAnnotations":{},"ExternalURL":"http://am.invalid"}
JSON
cat > "$tmp2/ordinary.json" <<'JSON'
{"Status":"firing","Receiver":"critical","Alerts":[{"Status":"firing","Labels":{"alertname":"ServiceDown"},"Annotations":{"summary":"Container web restarted >3 times in 15m; Service api is DOWN (https://api.example.invalid/health?a=1&b=2)","runbook_url":"https://github.com/nhanlagc60299/sre-starter-kit/blob/main/docs/ALERTS.md#servicedown","dashboard":"sre-app?a=1&b=2"}}],"GroupLabels":{"alertname":"ServiceDown"},"CommonLabels":{"alertname":"ServiceDown"},"CommonAnnotations":{},"ExternalURL":"http://am.invalid"}
JSON
chmod 644 "$tmp2/hostile.json" "$tmp2/ordinary.json"   # read by amtool as nobody, whatever the caller's umask
combined=$(cat "$tmp2/combined.txt")
hostile_out=$(${CONTAINER_ENGINE:-docker} run --rm -v "$tmp2:/c" --entrypoint amtool prom/alertmanager:v0.28.1 template render --template.glob="/c/*.nonexistent" --template.data=/c/hostile.json --template.text="$combined")
ordinary_out=$(${CONTAINER_ENGINE:-docker} run --rm -v "$tmp2:/c" --entrypoint amtool prom/alertmanager:v0.28.1 template render --template.glob="/c/*.nonexistent" --template.data=/c/ordinary.json --template.text="$combined")
printf '%s' "$hostile_out" > "$tmp2/hostile.out"
printf '%s' "$ordinary_out" > "$tmp2/ordinary.out"
# a link-annotation value that tries to leave its link -- "|" relabels and ">" closes a Slack
# link, "<!channel>" pings, ")" closes a markdown link and "[b](...)" opens a new one.
cat > "$tmp2/links.json" <<'JSON'
{"Status":"firing","Receiver":"critical","Alerts":[{"Status":"firing","Labels":{"alertname":"Test"},"Annotations":{"summary":"ok","runbook_url":"x|y> <!channel> <z","dashboard":"a)[b](https://evil.invalid)"}}],"GroupLabels":{"alertname":"Test"},"CommonLabels":{"alertname":"Test"},"CommonAnnotations":{},"ExternalURL":"http://am.invalid"}
JSON
chmod 644 "$tmp2/links.json"
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp2:/c" --entrypoint amtool prom/alertmanager:v0.28.1 template render --template.glob="/c/*.nonexistent" --template.data=/c/links.json --template.text="$combined" > "$tmp2/links.out"
python3 - "$tmp2/combined.txt" "$tmp2/hostile.out" "$tmp2/ordinary.out" "$tmp2/links.out" <<'PYRENDER' || { echo "FAIL: a rendered notification field failed the hostile or ordinary check"; exit 1; }
import re, sys

def split_by_key(path):
    text = open(path).read()
    parts = re.split(r"===([^=]+)===\n", text)[1:]  # drop leading empty chunk before first marker
    return {parts[i]: parts[i + 1] for i in range(0, len(parts), 2)}

fields = split_by_key(sys.argv[1])          # key -> raw (pre-render) template text
hostile = split_by_key(sys.argv[2])         # key -> hostile-case rendered text
ordinary = split_by_key(sys.argv[3])        # key -> ordinary-case rendered text
links = split_by_key(sys.argv[4])           # key -> hostile runbook_url/dashboard rendered text
RUNBOOK_URL = "https://github.com/nhanlagc60299/sre-starter-kit/blob/main/docs/ALERTS.md#servicedown"
DASHBOARD = "sre-app?a=1&b=2"
bad = []
for key, text in fields.items():
    is_slack = ".slack_configs." in key
    h, o = hostile[key], ordinary[key]
    if ".Annotations.summary" in text or ".CommonLabels.alertname" in text or ".GroupLabels.alertname" in text:
        # Each check targets ONE rule independently (an attacker-chosen token like "click"/"x" that
        # never appears in our own [runbook](...)/[dashboard](...) markup), so deleting any single
        # rule -- not just both bracket rules together -- fails a check.
        if "[click" in h or "[x](" in h: bad.append((key, "'[' survived (masked-link open bracket)", h))
        if "click]" in h or "x](" in h: bad.append((key, "']' survived (masked-link close bracket)", h))
        if "@everyone" in h: bad.append((key, "'@' survived (mention)", h))
        if "@here" in h: bad.append((key, "'@' survived (mention)", h))
        # a CR/LF would start a new line - a markdown heading on Discord/Teams/Telegram, a second email header line
        if re.search(r"(?m)^# heading", h): bad.append((key, "a line break survived", h))
        # ... and so would VT, FF, NEL and the Unicode line/paragraph separators on some receivers
        if re.search("[\x0b\x0c\x85\u2028\u2029]", h): bad.append((key, "a line separator survived", h))
        if "`x`" in h: bad.append((key, "'`' survived (code fence)", h))
        if is_slack:
            if "<!channel" in h or "<@U123" in h: bad.append((key, "'<' survived on Slack", h))
            if "U123>" in h: bad.append((key, "'>' survived on Slack", h))
    if ".Annotations.summary" in text and not is_slack:
        if ">3 times" not in o: bad.append((key, "ordinary '>3 times' was garbled outside Slack", o))
    if ".Annotations.dashboard" in text:
        if DASHBOARD not in o: bad.append((key, "dashboard query string was corrupted", o))
    if ".Annotations.runbook_url" in text:
        if RUNBOOK_URL not in o: bad.append((key, "runbook_url was corrupted", o))
    if ".Annotations.runbook_url" in text or ".Annotations.dashboard" in text:
        # one check per stripped character, so deleting any single one from a chain fails
        l = links[key]
        if "[b" in l: bad.append((key, "'[' survived in a link annotation", l))
        if "x|y" in l: bad.append((key, "'|' survived in a link annotation", l))
        if "y>" in l: bad.append((key, "'>' survived in a link annotation", l))
        if "<!channel" in l or "<z" in l: bad.append((key, "'<' survived in a link annotation", l))
        if not is_slack and "a)" in l: bad.append((key, "')' survived in a markdown link annotation", l))
if bad:
    for b in bad:
        print("FIELD CHECK FAILED:", b)
    sys.exit(1)
print("amtool template render: every field is inert on the hostile case and intact on the ordinary case")
PYRENDER

# Secrets never ride on a helper process's argv (security audit run-4, C1): /proc/<pid>/cmdline is
# world-readable on Linux, so a receiver block or the triage token passed as an argument reaches
# every local user while build/ at 0700 keeps the same values from them. A stub python3 first on
# PATH records every argv render.sh gives it; no dummy secret may appear there, and every one must
# still reach the rendered config (or the check proves nothing).
tmp3=$(mktemp -d); trap 'rm -rf "$tmp" "$tmp2" "$tmp3"' EXIT
mkdir "$tmp3/bin"
real_py=$(command -v python3)
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/argv.log"\nexec "%s" "$@"\n' "$tmp3" "$real_py" > "$tmp3/bin/python3"
chmod 755 "$tmp3/bin/python3"
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/DUMMYSLACKSECRET#; s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' .env.example > "$tmp3/.env"
cat >> "$tmp3/.env" <<'ENV'
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1/DUMMYDISCORDSECRET
TEAMS_WEBHOOK_URL=https://example.webhook.office.com/webhookb2/DUMMYTEAMSSECRET
TELEGRAM_BOT_TOKEN=123:DUMMYTELEGRAMSECRET
TELEGRAM_CHAT_ID=-1001
ALERT_EMAIL_TO=a@example.invalid
SMTP_HOST=smtp.example.invalid:587
SMTP_FROM=b@example.invalid
SMTP_USER=b@example.invalid
SMTP_PASSWORD=DUMMYSMTPSECRET
TRIAGE_WEBHOOK_TOKEN=DUMMYTRIAGESECRET
ENV
cp -r core "$tmp3/core"
( cd "$tmp3" && PATH="$tmp3/bin:$PATH" bash "$OLDPWD/scripts/render.sh" >/dev/null )
[ -s "$tmp3/argv.log" ] || { echo "FAIL: the python3 stub never ran, so the argv check proves nothing"; exit 1; }
for s in DUMMYSLACKSECRET DUMMYDISCORDSECRET DUMMYTEAMSSECRET DUMMYTELEGRAMSECRET DUMMYSMTPSECRET DUMMYTRIAGESECRET; do
  grep -q "$s" "$tmp3/build/alertmanager/alertmanager.yml" || { echo "FAIL: $s did not reach the rendered config"; exit 1; }
  if grep -q "$s" "$tmp3/argv.log"; then echo "FAIL: $s was passed to python3 on its command line"; exit 1; fi
done
echo "no receiver secret or triage token on a helper's argv"

echo "test_alertmanager OK"

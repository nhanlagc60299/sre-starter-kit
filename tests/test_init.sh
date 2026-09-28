#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# One trap for every temp dir in this file, installed before the first can leak: ${tmpN:-} is empty
# until that section runs, and rm -rf "" is a no-op.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp" "${tmp7:-}" "${tmp8:-}" "${tmp8b:-}" "${tmp9:-}" "${tmp10:-}" "${tmp11:-}" "${tmp12:-}" "${tmp13:-}" "${tmp14:-}"' EXIT
cp -r core scripts .env.example "$tmp/"
# answers: project, slack, telegram token, chat id, teams, services (2 then blank), disk warn, disk crit,
# prom ret, loki ret, grafana pw, security y, container sock, cadvisor y, auth log path, discord blank,
# email blank, triage y
printf 'acme\nhttp://localhost:9/\n123:abc\n-100\n\napi=http://api:8080/health\nweb=http://web/\n\n20\n8\n15d\n168h\ns3cret\ny\n\ny\n/var/log/secure\n\n\ny\n' \
  | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "PROJECT_NAME='acme'" "$tmp/.env"
grep -qxF "CONTAINER_SOCK='/var/run/docker.sock'" "$tmp/.env"
grep -qxF "COMPOSE_PROFILES='cadvisor,triage'" "$tmp/.env"
grep -qxF "AUTH_LOG_PATH='/var/log/secure'" "$tmp/.env"
case "$(ls -ld "$tmp/.env")" in -rw-------*) ;; *) echo "FAIL: .env is not 0600: $(ls -ld "$tmp/.env")"; exit 1 ;; esac
grep -qxF "TELEGRAM_BOT_TOKEN='123:abc'" "$tmp/.env"
grep -qxF "DISK_WARN_PCT='20'" "$tmp/.env"
grep -qxF "SERVICES='api=http://api:8080/health,web=http://web/'" "$tmp/.env"
grep -qxF "TRIAGE_WEBHOOK_URL='http://triage-agent:9096/alert'" "$tmp/.env"
grep -qxF "TRIAGE_DRY_RUN='true'" "$tmp/.env"          # free tier: always dry run, even after y
( cd "$tmp" && bash scripts/render.sh >/dev/null )
python3 - "$tmp" <<'PY'
import json,sys,os
t=json.load(open(sys.argv[1]+"/build/prometheus/targets/services.json"))
assert t==[{"targets":["http://api:8080/health"],"labels":{"service":"api"}},{"targets":["http://web/"],"labels":{"service":"web"}}], t
am=open(sys.argv[1]+"/build/alertmanager/alertmanager.yml").read()
assert "telegram_configs" in am and "bot_token: 123:abc" in am, "telegram receiver missing"
assert "msteamsv2_configs" not in am, "teams should be absent when blank"
rules=open(sys.argv[1]+"/build/prometheus/rules/infra.yml").read()
assert "* 100 < 8\n" in rules and "* 100 < 20\n" in rules, "disk thresholds not applied"
PY

# --- re-run 2: disk warn 30 / crit 15 must not collide, security answered "n" ---
# Podman-style: security off (so no auth-log question), custom socket, cAdvisor off, and triage
# answered "n" explicitly (a blank/EOF answer here would remember run 1's "y" and re-enable it).
# ALERTMANAGER_EXTERNAL_URL is never asked either; set a custom value by hand first to prove a
# re-run keeps it instead of resetting it to the .env.example default.
sed -i.bak "s#^ALERTMANAGER_EXTERNAL_URL=.*#ALERTMANAGER_EXTERNAL_URL='https://am.example.test'#" "$tmp/.env" && rm -f "$tmp/.env.bak"
printf '\n\n\n\n\n\n30\n15\n\n\n\nn\n/run/user/1000/podman/podman.sock\nn\n\n\nn\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "CONTAINER_SOCK='/run/user/1000/podman/podman.sock'" "$tmp/.env"
grep -qxF "COMPOSE_PROFILES=''" "$tmp/.env"
grep -qxF "AUTH_LOG_PATH='/var/log/secure'" "$tmp/.env"   # not asked, previous value kept
grep -qxF "ALERTMANAGER_EXTERNAL_URL='https://am.example.test'" "$tmp/.env"   # not asked, previous value kept
grep -qxF "DISK_WARN_PCT='30'" "$tmp/.env"
grep -qxF "DISK_CRIT_PCT='15'" "$tmp/.env"
grep -qxF "MODULE_SECURITY='false'" "$tmp/.env"
grep -qxF "PROJECT_NAME='acme'" "$tmp/.env"   # blank answers keep the previous value
grep -qxF "TRIAGE_WEBHOOK_URL='http://localhost:9/'" "$tmp/.env"   # answered n -> back to the sink
( cd "$tmp" && bash scripts/render.sh >/dev/null )
python3 - "$tmp" <<'PY'
import re,sys
rules=open(sys.argv[1]+"/build/prometheus/rules/infra.yml").read()
exprs=dict(re.findall(r'- alert: (\w+)\n\s*expr: (.*)', rules))
assert exprs["DiskFull"].endswith("* 100 < 15"), exprs["DiskFull"]
assert exprs["DiskLow"].endswith("* 100 < 30"), exprs["DiskLow"]
PY
[ -e "$tmp/build/loki/rules/fake/security.yml" ] && { echo "FAIL: security rules kept when module off"; exit 1; }
[ -e "$tmp/build/loki/rules/fake/logs.yml" ] || { echo "FAIL: log alerts dropped when the security module is off"; exit 1; }

# --- re-run 3: blank security answer keeps it off ---
printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "MODULE_SECURITY='false'" "$tmp/.env"
grep -qxF "COMPOSE_PROFILES=''" "$tmp/.env"   # blank answer keeps cAdvisor off
# --- re-run 4: values with spaces and shell metacharacters survive the .env round-trip ---
printf 'Acme Corp\n\n\n\n\n\n\n\n\n\np@ss word$1\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "PROJECT_NAME='Acme Corp'" "$tmp/.env"
grep -qxF "GRAFANA_ADMIN_PASSWORD='p@ss word\$1'" "$tmp/.env"
( cd "$tmp" && bash scripts/render.sh >/dev/null )    # would die with "Corp: command not found" if unquoted
grep -q '^    project: Acme Corp$' "$tmp/build/prometheus/prometheus.yml"

# --- re-run 5: bad answers are rejected and re-asked ---
# services: the comma line is dropped, then a valid one; disk warn: "20%" is re-asked, then 20
printf '\n\n\n\n\nbad=http://x/a,b\nok=http://ok/\n\n20%%\n20\n8\n\n\n\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "SERVICES='ok=http://ok/'" "$tmp/.env"
grep -qxF "DISK_WARN_PCT='20'" "$tmp/.env"
grep -qxF "DISK_CRIT_PCT='8'" "$tmp/.env"

# --- re-run 6: a Teams webhook reaches both receivers and the result is still valid ---
printf '\n\n\n\nhttps://example.invalid/hook\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp" && bash scripts/init.sh >/dev/null )
grep -qxF "TEAMS_WEBHOOK_URL='https://example.invalid/hook'" "$tmp/.env"
( cd "$tmp" && bash scripts/render.sh >/dev/null )
[ "$(grep -c msteamsv2_configs "$tmp/build/alertmanager/alertmanager.yml")" = 2 ] || { echo "FAIL: teams receiver not in both receivers"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml >/dev/null

# --- re-run 7: Discord + email with NO Slack. Fresh dir: the shared tmp already holds a Slack URL and a blank
#     answer keeps it. 14 free answers (security n, so no auth-log question), then discord, email, smtp host,
#     from, user, password.
tmp7=$(mktemp -d)
cp -r core scripts .env.example "$tmp7/"
printf 'acme\n\n\n\n\n\n\n\n\n\ns3cret\nn\n\nn\nhttps://discord.com/api/webhooks/1/x\nops@example.invalid,dev@example.invalid\nsmtp.example.invalid:587\nalerts@example.invalid\nalerts@example.invalid\nsmtp-pw\n' \
  | ( cd "$tmp7" && bash scripts/init.sh >/dev/null )
grep -qxF "SLACK_WEBHOOK_URL=''" "$tmp7/.env"
grep -qxF "DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/1/x'" "$tmp7/.env"
grep -qxF "ALERT_EMAIL_TO='ops@example.invalid,dev@example.invalid'" "$tmp7/.env"
grep -qxF "SMTP_HOST='smtp.example.invalid:587'" "$tmp7/.env"
grep -qxF "SMTP_PASSWORD='smtp-pw'" "$tmp7/.env"
( cd "$tmp7" && bash scripts/render.sh >/dev/null )
AM7="$tmp7/build/alertmanager/alertmanager.yml"
! grep -q slack_configs "$AM7" || { echo "FAIL: slack_configs rendered with an empty SLACK_WEBHOOK_URL"; exit 1; }
[ "$(grep -c discord_configs "$AM7")" = 2 ] || { echo "FAIL: discord receiver not in both receivers"; exit 1; }
[ "$(grep -c email_configs "$AM7")" = 2 ] || { echo "FAIL: email receiver not in both receivers"; exit 1; }
grep -q 'smarthost: smtp.example.invalid:587' "$AM7" || { echo "FAIL: smarthost not rendered"; exit 1; }
grep -q 'auth_username: alerts@example.invalid' "$AM7" || { echo "FAIL: auth_username not rendered"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp7/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml >/dev/null
# routing still works with slack gone: critical reaches critical+webhook-triage
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp7/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 config routes test --config.file=/c/alertmanager.yml --verify.receivers=critical,webhook-triage severity=critical alertname=X >/dev/null

# --- re-run 8: email without SMTP_USER renders no auth lines; a Slack-only re-run keeps working (regression) ---
printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp7" && bash scripts/init.sh >/dev/null )   # 14 free + discord + email + host + from + user(blank keeps) ... blank keeps everything
grep -qxF "SMTP_USER='alerts@example.invalid'" "$tmp7/.env"
sed -i.bak "s/^SMTP_USER=.*/SMTP_USER=''/; s/^SMTP_PASSWORD=.*/SMTP_PASSWORD=''/" "$tmp7/.env" && rm -f "$tmp7/.env.bak"
( cd "$tmp7" && bash scripts/render.sh >/dev/null )
! grep -q auth_username "$AM7" || { echo "FAIL: auth_username rendered with an empty SMTP_USER"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp7/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml >/dev/null

# --- re-run 8b: an SMTP password containing a single quote and a backslash must survive as a valid
#     single-quoted YAML scalar (a raw quote would close the scalar early and break the parse) ---
sed -i.bak "s/^SMTP_USER=.*/SMTP_USER='alerts@example.invalid'/; s/^SMTP_PASSWORD=.*/SMTP_PASSWORD='pa'\\\\''ss\\\\x'/" "$tmp7/.env" && rm -f "$tmp7/.env.bak"
( cd "$tmp7" && bash scripts/render.sh >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp7/build/alertmanager:/c" --entrypoint amtool prom/alertmanager:v0.28.1 check-config /c/alertmanager.yml >/dev/null
python3 - "$AM7" <<'PY'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
pw = c["receivers"][0]["email_configs"][0]["auth_password"]
assert pw == "pa'ss\\x", pw
PY

# --- re-run 9: no receiver at all is refused by the wizard ---
tmp8=$(mktemp -d)
cp -r core scripts .env.example "$tmp8/"
if printf 'acme\n\n\n\n\n\n\n\n\n\ns3cret\nn\n\nn\n\n\n' | ( cd "$tmp8" && bash scripts/init.sh >/dev/null 2>&1 ); then
  echo "FAIL: wizard accepted a config with no receiver"; exit 1
fi
[ ! -e "$tmp8/.env" ] || { echo "FAIL: wizard wrote .env with no receiver"; exit 1; }

# --- re-run 9b: a Telegram bot token with no chat id is not a usable receiver either ---
tmp8b=$(mktemp -d)
cp -r core scripts .env.example "$tmp8b/"
if printf 'acme\n\n123456:ABCDEF\n\n\n\n\n\n\n\ns3cret\nn\n\nn\n\n\n' | ( cd "$tmp8b" && bash scripts/init.sh >/dev/null 2>&1 ); then
  echo "FAIL: wizard accepted a Telegram token with no chat id and no other receiver"; exit 1
fi
[ ! -e "$tmp8b/.env" ] || { echo "FAIL: wizard wrote .env with a Telegram token but no chat id"; exit 1; }

# --- old answer files stop early: the new trailing questions must take defaults at EOF, not abort ---
tmp9=$(mktemp -d)
cp -r core scripts .env.example "$tmp9/"
printf 'acme\nhttp://localhost:9/\n\n\n\n\n\n\n\n\n\nn\n\nn\n' | ( cd "$tmp9" && bash scripts/init.sh >/dev/null )
grep -qxF "DISCORD_WEBHOOK_URL=''" "$tmp9/.env"
grep -qxF "ALERT_EMAIL_TO=''" "$tmp9/.env"

# --- triage: a re-run with blank answers must remember the previous answer (probed from
#     TRIAGE_WEBHOOK_URL, since COMPOSE_PROFILES gets overwritten by the cAdvisor question first),
#     and an explicit "n" removes the profile and points the webhook back at the sink ---
tmp10=$(mktemp -d)
cp -r core scripts .env.example "$tmp10/"
# 18 answers: project, slack, 8 blanks (telegram token/chat id/teams/services-end/disk warn/disk
# crit/prom ret/loki ret), grafana pw, security y, container sock blank, cadvisor y, auth log path
# blank, discord blank, email blank, triage y
printf 'acme\nhttp://localhost:9/\n\n\n\n\n\n\n\n\ns3cret\ny\n\ny\n\n\n\ny\n' \
  | ( cd "$tmp10" && bash scripts/init.sh >/dev/null )
grep -qxF "COMPOSE_PROFILES='cadvisor,triage'" "$tmp10/.env"
grep -qxF "TRIAGE_WEBHOOK_URL='http://triage-agent:9096/alert'" "$tmp10/.env"
grep -qxF "TRIAGE_DRY_RUN='true'" "$tmp10/.env"   # free tier: always dry run, even after y
# not asked (no new wizard question): a hex token is generated when triage turns on and none exists yet
tok1=$(sed -n "s/^TRIAGE_WEBHOOK_TOKEN='\(.*\)'$/\1/p" "$tmp10/.env")
[[ "$tok1" =~ ^[0-9a-f]{48}$ ]] || { echo "FAIL: no 48-hex TRIAGE_WEBHOOK_TOKEN generated when triage turned on, got '$tok1'"; exit 1; }

# re-run with every answer blank: all 18 questions default, and the triage default must come back "y"
printf '%.0s\n' $(seq 1 18) | ( cd "$tmp10" && bash scripts/init.sh >/dev/null )
grep -qxF "COMPOSE_PROFILES='cadvisor,triage'" "$tmp10/.env"
grep -qxF "TRIAGE_WEBHOOK_URL='http://triage-agent:9096/alert'" "$tmp10/.env"
grep -qxF "TRIAGE_WEBHOOK_TOKEN='$tok1'" "$tmp10/.env" || { echo "FAIL: TRIAGE_WEBHOOK_TOKEN was not kept across a re-run"; exit 1; }

# re-run answering "n" to triage (17 blanks then n) removes the profile and resets the webhook
printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nn\n' | ( cd "$tmp10" && bash scripts/init.sh >/dev/null )
grep -qxF "COMPOSE_PROFILES='cadvisor'" "$tmp10/.env"
grep -qxF "TRIAGE_WEBHOOK_URL='http://localhost:9/'" "$tmp10/.env"
grep -qxF "TRIAGE_WEBHOOK_TOKEN=''" "$tmp10/.env" || { echo "FAIL: TRIAGE_WEBHOOK_TOKEN was not cleared when triage was turned off"; exit 1; }

# --- Grafana admin password: a first run (no .env) with an empty answer must not silently keep
#     the published 'change-me' default. It must generate a real, long, random one instead, and
#     tell the operator where to find it rather than printing it. ---
tmp11=$(mktemp -d)
cp -r core scripts .env.example "$tmp11/"
# 17 answers: project, slack, 9 blanks (telegram token/chat id/teams/services-end/disk warn/disk
# crit/prom ret/loki ret/grafana pw BLANK), security n, 4 blanks (container sock/cadvisor/discord/
# email), triage n
out11=$(printf 'acme\nhttp://localhost:9/\n\n\n\n\n\n\n\n\n\nn\n\n\n\n\nn\n' \
  | ( cd "$tmp11" && bash scripts/init.sh ) )
echo "$out11" | grep -qF '.env, GRAFANA_ADMIN_PASSWORD' \
  || { echo "FAIL: wizard did not say where a generated Grafana password lives (.env, GRAFANA_ADMIN_PASSWORD)"; exit 1; }
pw1=$(sed -n "s/^GRAFANA_ADMIN_PASSWORD='\(.*\)'\$/\1/p" "$tmp11/.env")
[ "$pw1" != "change-me" ] || { echo "FAIL: first-run empty answer kept the published 'change-me' default"; exit 1; }
[ -n "$pw1" ] || { echo "FAIL: first-run empty answer wrote an empty Grafana password"; exit 1; }
[ "${#pw1}" -ge 20 ] || { echo "FAIL: generated Grafana password is shorter than 20 characters (${#pw1})"; exit 1; }
[[ "$pw1" =~ ^[0-9a-f]+$ ]] || { echo "FAIL: generated Grafana password '$pw1' is not from the hex CSPRNG idiom (od -tx1 /dev/urandom)"; exit 1; }
echo "$out11" | grep -qF "$pw1" && { echo "FAIL: wizard printed the generated password itself to stdout"; exit 1; }

# --- re-run with an existing .env: a blank answer keeps the value just generated (unchanged) ---
printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp11" && bash scripts/init.sh >/dev/null )
pw2=$(sed -n "s/^GRAFANA_ADMIN_PASSWORD='\(.*\)'\$/\1/p" "$tmp11/.env")
[ "$pw2" = "$pw1" ] || { echo "FAIL: a blank answer on a re-run did not keep the existing Grafana password"; exit 1; }

# --- an existing .env with the OLD 'change-me' default (written before this fix) must not be
#     perpetuated on a re-run: treat it like empty and generate a real one -------------------
tmp13=$(mktemp -d)
cp -r core scripts .env.example "$tmp13/"
printf "GRAFANA_ADMIN_PASSWORD='change-me'\nSLACK_WEBHOOK_URL='http://localhost:9/'\n" > "$tmp13/.env"
printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | ( cd "$tmp13" && bash scripts/init.sh >/dev/null )
pw3=$(sed -n "s/^GRAFANA_ADMIN_PASSWORD='\(.*\)'\$/\1/p" "$tmp13/.env")
[ "$pw3" != "change-me" ] || { echo "FAIL: a re-run on an old .env kept the existing 'change-me' value"; exit 1; }
[ "${#pw3}" -ge 20 ] || { echo "FAIL: re-run on an old change-me .env generated a password shorter than 20 characters (${#pw3})"; exit 1; }

# --- the first-run prompt must say [empty], never [unchanged] --------------------------------
# ask_secret's own read -p prompt is invisible to a plain stdout/stderr capture in some
# environments (it can go straight to the controlling terminal), so this traces the wizard with
# `bash -x` and greps ITS OWN trace of that same read command, after $shown has been substituted
# into it -- xtrace always writes to fd 2, which a plain capture does not have to compete with.
tmp12=$(mktemp -d)
cp -r core scripts .env.example "$tmp12/"
trace=$(printf 'acme\nhttp://localhost:9/\n\n\n\n\n\n\n\n\n\nn\n\n\n\n\nn\n' \
  | ( cd "$tmp12" && bash -x scripts/init.sh ) 2>&1 1>/dev/null)
echo "$trace" | grep -qF "read -rs -p 'Grafana admin password [unchanged]" \
  && { echo "FAIL: first-run Grafana password prompt showed [unchanged] instead of [empty]"; exit 1; }
echo "$trace" | grep -qF "read -rs -p 'Grafana admin password [empty]" \
  || { echo "FAIL: first-run Grafana password prompt did not show [empty]: $(echo "$trace" | grep 'Grafana admin password' || echo NONE)"; exit 1; }

# --- a typed Grafana password Grafana itself would refuse (under 4 characters, or its own default
#     'admin') is re-asked in place. No new question: the answer after the accepted one still lands
#     on the security question, then cAdvisor ---
tmp14=$(mktemp -d)
cp -r core scripts .env.example "$tmp14/"
printf 'acme\nhttp://localhost:9/\n\n\n\n\n\n\n\n\nabc\nadmin\ngood-pw\ny\n\ny\n\n\n\nn\n' | ( cd "$tmp14" && bash scripts/init.sh >/dev/null )
grep -qxF "GRAFANA_ADMIN_PASSWORD='good-pw'" "$tmp14/.env" || { echo "FAIL: a short or 'admin' Grafana password was not re-asked"; exit 1; }
grep -qxF "MODULE_SECURITY='true'" "$tmp14/.env" || { echo "FAIL: re-asking the password shifted the later answers"; exit 1; }
grep -qxF "COMPOSE_PROFILES='cadvisor'" "$tmp14/.env" || { echo "FAIL: re-asking the password shifted the later answers"; exit 1; }
# an .env from before this check holding a too-short value: a blank re-run must not keep it (render
# would refuse it) and must not loop forever at EOF either -- it generates one, like change-me
printf "GRAFANA_ADMIN_PASSWORD='abc'\nSLACK_WEBHOOK_URL='http://localhost:9/'\n" > "$tmp14/.env"
printf '%.0s\n' $(seq 1 25) | ( cd "$tmp14" && bash scripts/init.sh >/dev/null )
pw4=$(sed -n "s/^GRAFANA_ADMIN_PASSWORD='\(.*\)'\$/\1/p" "$tmp14/.env")
[[ "$pw4" =~ ^[0-9a-f]{20,}$ ]] || { echo "FAIL: a blank re-run kept a too-short Grafana password instead of generating one"; exit 1; }

# a line break in the password is re-asked the same way (read -r keeps a CR; an older .env can hold
# either inside its quotes), and an .env holding one is not kept on a blank re-run
tmp15=$(mktemp -d)
cp -r core scripts .env.example "$tmp15/"
printf 'acme\nhttp://localhost:9/\n\n\n\n\n\n\n\n\npass\rword\ngood-pw\ny\n\ny\n\n\n\nn\n' | ( cd "$tmp15" && bash scripts/init.sh >/dev/null )
grep -qxF "GRAFANA_ADMIN_PASSWORD='good-pw'" "$tmp15/.env" || { echo "FAIL: a Grafana password with a CR was not re-asked"; exit 1; }
grep -qxF "MODULE_SECURITY='true'" "$tmp15/.env" || { echo "FAIL: re-asking the password shifted the later answers"; exit 1; }
printf "GRAFANA_ADMIN_PASSWORD='line-one\nline-two'\nSLACK_WEBHOOK_URL='http://localhost:9/'\n" > "$tmp15/.env"
printf '%.0s\n' $(seq 1 25) | ( cd "$tmp15" && bash scripts/init.sh >/dev/null )
pw5=$(sed -n "s/^GRAFANA_ADMIN_PASSWORD='\(.*\)'\$/\1/p" "$tmp15/.env")
[[ "$pw5" =~ ^[0-9a-f]{20,}$ ]] || { echo "FAIL: a blank re-run kept a Grafana password with a line break"; exit 1; }
# .env holds the Grafana password and every webhook token: owner-only, even when it already existed
# with wider permissions (umask only applies to a file init.sh creates)
chmod 644 "$tmp15/.env"
printf '%.0s\n' $(seq 1 25) | ( cd "$tmp15" && bash scripts/init.sh >/dev/null )
mode=$(stat -c %a "$tmp15/.env" 2>/dev/null || stat -f %Lp "$tmp15/.env")
[ "$mode" = 600 ] || { echo "FAIL: .env is mode $mode after init.sh, want 600"; exit 1; }
# ... and the mode is tightened BEFORE the secrets are written, never after: in the trace, the
# chmod of an existing .env comes before the heredoc that rewrites it.
chmod 644 "$tmp15/.env"
trace15=$(printf '%.0s\n' $(seq 1 25) | ( cd "$tmp15" && bash -x scripts/init.sh 2>&1 >/dev/null ))
c=$(grep -n "chmod 600 $tmp15/.env" <<<"$trace15" | head -1 | cut -d: -f1)
w=$(grep -n '^+ cat$' <<<"$trace15" | tail -1 | cut -d: -f1)
[ -n "$c" ] && [ -n "$w" ] && [ "$c" -lt "$w" ] || { echo "FAIL: init.sh must chmod 600 an existing .env before rewriting it (chmod line ${c:-none}, write line ${w:-none})"; exit 1; }

echo "test_init OK"

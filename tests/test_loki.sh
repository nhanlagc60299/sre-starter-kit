#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's#^SLACK_WEBHOOK_URL=.*#SLACK_WEBHOOK_URL=http://localhost:9/#; s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=fixture-pw/' .env.example > "$tmp/.env"
cp -r core "$tmp/core"
( cd "$tmp" && bash "$OLDPWD/scripts/render.sh" >/dev/null )
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/loki:3.5.0 -config.file=/c/loki.yml -verify-config
# -verify-config accepts the un-substituted template too, so check the value actually landed
grep -q 'retention_period: 168h' "$tmp/build/loki/loki.yml" || { echo "FAIL: LOKI_RETENTION_PERIOD not substituted"; exit 1; }
${CONTAINER_ENGINE:-docker} run --rm -v "$tmp/build/loki:/c" grafana/alloy:v1.9.0 fmt /c/config.alloy >/dev/null
# lokitool is not present in the loki image; assert the rules file rendered to the
# tenant path and declares exactly the two alerts, instead of relying on loki -verify-config
# (which does not parse rule file contents).
test -f "$tmp/build/loki/rules/fake/security.yml" || { echo "FAIL: security.yml missing at tenant path"; exit 1; }
python3 -c 'import yaml,sys; g=yaml.safe_load(open(sys.argv[1]))["groups"]; assert {r["alert"] for gr in g for r in gr["rules"]} == {"SSHFailedLoginBurst","RootLoginDetected"}, "unexpected alert set"' "$tmp/build/loki/rules/fake/security.yml"
test -f "$tmp/build/loki/rules/fake/logs.yml" || { echo "FAIL: logs.yml missing at tenant path"; exit 1; }
python3 -c 'import yaml,sys; g=yaml.safe_load(open(sys.argv[1]))["groups"]; assert {r["alert"] for gr in g for r in gr["rules"]} == {"LogErrorBurst","Http5xxInLogs"}, "unexpected alert set"' "$tmp/build/loki/rules/fake/logs.yml"
# The log alerts must not include the kit's own containers, or Grafana's startup chatter pages the customer.
grep -q 'service!~"prometheus|alertmanager|grafana|loki|alloy|blackbox|cadvisor|node-exporter"}' "$tmp/build/loki/rules/fake/logs.yml" || { echo "FAIL: log alerts do not exclude the kit's own services"; exit 1; }

# SSH usernames are chosen by the client before it authenticates, and sshd writes them into the very
# lines these rules read (audit run-5 C2): "Accepted password for root" as a username fired
# RootLoginDetected with no login, and "Failed password from <ip>" set the burst's ip label. Both
# rules now read only what sshd writes itself: its "sshd[pid]: " prefix (file mode) or the start
# of the line (journal mode), the fixed tail "from <addr> port <n> ssh2", and the last "from". Loki
# itself evaluates each rule's expr here over sshd-shaped lines, one labelled stream per case.
# The rendered loki.yml as shipped, except that the ring advertises loopback: with --network none
# there is no eth0 for Loki to find an address on.
mkdir -p "$tmp/lokitest"; cp -r "$tmp/build/loki/rules" "$tmp/lokitest/rules"
python3 - "$tmp/build/loki" "$tmp" <<'PY'
import json, sys, yaml
src, out = sys.argv[1], sys.argv[2]
rules = {r["alert"]: r["expr"] for g in yaml.safe_load(open(src + "/rules/fake/security.yml"))["groups"] for r in g["rules"]}
json.dump(rules, open(out + "/authlog_rules.json", "w"))
cfg = yaml.safe_load(open(src + "/loki.yml"))
cfg["common"]["instance_addr"] = "127.0.0.1"; cfg["memberlist"] = {"advertise_addr": "127.0.0.1"}
yaml.safe_dump(cfg, open(out + "/lokitest/loki.yml", "w"))
PY
cat > "$tmp/authlog_check.py" <<'PY'
import json, sys, time, urllib.parse, urllib.request
rules = json.load(open("/t/authlog_rules.json"))
L = "http://127.0.0.1:3100"
for _ in range(120):
    try:
        if urllib.request.urlopen(L + "/ready", timeout=2).status == 200: break
    except Exception: pass
    time.sleep(0.5)
else:
    sys.exit("FAIL: Loki never became ready")
REAL, FRAMED, V6 = "203.0.113.50", "198.51.100.7", "2001:db8::7"
SYSLOG, ISO = "Sep 29 10:00:00 vm sshd[4242]: ", "2026-09-29T10:00:00.123456+00:00 vm sshd-session[4242]: "
def preauth(user, pw):   # what sshd logs for one connection by an invalid user
    out = ["Invalid user %s from %s port %d" % (user, REAL, 40000 + p) for p in range(25)]
    out += ["Connection closed by invalid user %s %s port %d [preauth]" % (user, REAL, 40000 + p) for p in range(25)]
    if pw: out += ["Failed password for invalid user %s from %s port %d ssh2" % (user, REAL, 40000 + p) for p in range(25)]
    return out
CASES = {   # case -> (lines, SSHFailedLoginBurst {ip: count} it must return, RootLoginDetected fires?)
    "inj_fail_file":     ([SYSLOG + m for m in preauth("Failed password from " + FRAMED, False)], {}, False),
    "inj_fail_journal":  ([m for m in preauth("Failed password from " + FRAMED, False)], {}, False),
    "inj_fail_pw_file":  ([SYSLOG + m for m in preauth("Failed password for x from %s port 1 ssh2" % FRAMED, True)], {REAL: 25}, False),
    "inj_root_file":     ([SYSLOG + m for m in preauth("Accepted password for root", True)], {REAL: 25}, False),
    "inj_root_journal":  ([m for m in preauth("Accepted password for root from %s port 1 ssh2" % FRAMED, False)], {}, False),
    "real_fail_syslog":  ([SYSLOG + "Failed password for root from %s port %d ssh2" % (REAL, 50000 + p) for p in range(25)], {REAL: 25}, False),
    "real_fail_iso":     ([ISO + "Failed password for root from %s port %d ssh2" % (REAL, 50000 + p) for p in range(25)], {REAL: 25}, False),
    "real_fail_ipv6":    (["Failed password for invalid user admin from %s port %d ssh2" % (V6, 50000 + p) for p in range(25)], {V6: 25}, False),
    "real_root_file":    ([SYSLOG + "Accepted publickey for root from %s port 5 ssh2: ED25519 SHA256:dummy" % REAL], {}, True),
    "real_root_journal": (["Accepted password for root from %s port 5 ssh2" % REAL], {}, True),
}
now = time.time_ns()
streams = [{"stream": {"job": "authlog", "case": c}, "values": [[str(now - 60 * 10**9 + i * 10**6), l] for i, l in enumerate(lines)]}
           for c, (lines, _, _) in CASES.items()]
req = urllib.request.Request(L + "/loki/api/v1/push", data=json.dumps({"streams": streams}).encode(), headers={"Content-Type": "application/json"})
assert urllib.request.urlopen(req, timeout=10).status == 204
def query(expr, case):
    q = expr.replace('{job="authlog"}', '{job="authlog", case="%s"}' % case)
    assert q != expr, expr
    u = L + "/loki/api/v1/query?" + urllib.parse.urlencode({"query": q, "time": str(time.time_ns())})
    return json.load(urllib.request.urlopen(u, timeout=10))["data"]["result"]
bad = []
for _ in range(20):   # a pushed line can take a moment to be queryable
    if query(rules["RootLoginDetected"], "real_root_journal"): break
    time.sleep(0.5)
for c, (_, want_burst, want_root) in CASES.items():
    got = {r["metric"].get("ip", ""): int(float(r["value"][1])) for r in query(rules["SSHFailedLoginBurst"], c)}
    root = bool(query(rules["RootLoginDetected"], c))
    if got != want_burst: bad.append("%s: SSHFailedLoginBurst fires %s, want %s" % (c, got, want_burst))
    if root != want_root: bad.append("%s: RootLoginDetected fires=%s, want %s" % (c, root, want_root))
for b in bad: print("FAIL:", b)
sys.exit(1 if bad else 0)
PY
chmod -R a+rX "$tmp"
lk=srekit-test-loki-$$
${CONTAINER_ENGINE:-docker} run -d --rm --name "$lk" --network none -v "$tmp/lokitest:/etc/loki:ro" grafana/loki:3.5.0 -config.file=/etc/loki/loki.yml >/dev/null
trap '${CONTAINER_ENGINE:-docker} rm -f "$lk" >/dev/null 2>&1; rm -rf "$tmp"' EXIT
${CONTAINER_ENGINE:-docker} run --rm --network "container:$lk" -v "$tmp:/t:ro" python:3.12-alpine python3 /t/authlog_check.py \
  || { echo "FAIL: the SSH rules fire on client-chosen usernames or miss a real sshd event"; exit 1; }
echo "ok: the SSH rules fire on real sshd events only, with sshd's own address"
echo "test_loki OK"

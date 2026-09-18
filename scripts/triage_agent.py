#!/usr/bin/env python3
"""triage-agent: receives Alertmanager webhooks, gathers a context pack from the kit's own services,
redacts it, and either prints it (dry run, the default) or sends it to the triage API and posts the
returned note to the alert receivers. Standard library only, on purpose: anyone can read this file
end to end and know exactly what leaves their network. Only GETs against the kit's services."""
import base64, json, os, re, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCHEMA_VERSION = 1
MAX_BYTES = 40000          # ~12k tokens; see trim() for what goes first (test code may lower this)
HARD_CAP_BYTES = 40000     # fixed final safety net, independent of MAX_BYTES; see trim()
SOURCE_TIMEOUT = 5         # seconds per upstream call
TOTAL_DEADLINE = 30        # seconds for the whole build_pack, across every upstream call
DEDUP_SECONDS = 3600       # the webhook-triage route has no repeat_interval of its own and inherits
                           # the top-level route's 4h; this just bounds our own re-triage cadence,
                           # independent of whatever Alertmanager's routes are configured to re-notify at
RUNBOOK_MAX_LINES = 60
ENV = os.environ.get
# Value matcher excludes whitespace/quote/comma/semicolon/close-paren so it stops at the end of a
# quoted JSON value or a comma-separated field instead of swallowing whatever follows.
_REDACT_VALUE = r'[^\s"\',;)]+'
DEFAULT_REDACT = [
    # The keyword must directly precede the separator - that trailing requirement alone is what
    # separates "safe" from "secret": max_tokens=, token_count=, tokenizer_latency=, secretary_id=,
    # passwordless_login= and pwd_check_interval= all have the keyword followed by more identifier
    # characters before any separator, so none of them match; oldpassword=, apitoken=, mytoken=,
    # AWS_SECRET_ACCESS_KEY= (via "access_key") and "password":"..." (quoted JSON) all have the
    # keyword immediately before the separator, so all of them do.
    #
    # There is deliberately no boundary check on what comes BEFORE the keyword (no [\w.-]* wrap, no
    # negative lookbehind). A round-1 version wrapped the keyword in [\w.-]* on both sides, which
    # caught AWS_SECRET_ACCESS_KEY= via "secret" but destroyed every ordinary field with "token"/
    # "secret"/"password" as a substring. A round-2 fix added a (?<![A-Za-z0-9]) lookbehind before the
    # keyword to stop that - which fixed the false positives but then missed real secrets whose field
    # name is glued onto the keyword with no boundary at all (oldpassword=, apitoken=, mytoken=). The
    # trailing-separator requirement turned out to be the only check that needed to exist.
    (r'(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret))(["\']?\s*[:=]\s*["\']?)' + _REDACT_VALUE,
     r"\1\2[redacted]"),
    (r"(?i)bearer\s+\S+", "Bearer [redacted]"),
    (r"(?i)(?<![A-Za-z0-9])authorization:\s*\S+\s+\S+", "Authorization: [redacted]"),
    (r"(?i)https?://hooks\.(?:slack\.com|discord(?:app)?\.com)/" + _REDACT_VALUE, "[webhook-url-redacted]"),
    (r"://[^/\s:]+:[^@\s]+@", "://[redacted]@"),          # user:pass@ in URLs - must run before the
                                                            # email pattern, or "user:pass@host" reads
                                                            # as an email and eats the hostname with it
    # bounded quantifiers: an unbounded [\w.+-]+@[\w-]+\.[\w.-]+ backtracks O(n^2) on a long line with
    # an "@" but no "." after it (an attacker-controlled log line, easily tens of KB)
    (r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+", "[email]"),
]


def log(msg): print("triage-agent: " + msg, flush=True)


class Budget:
    """Monotonic deadline shared across every upstream call a single build_pack makes."""
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def remaining(self):
        return self.deadline - time.monotonic()


def get_json(url, headers=None, timeout=SOURCE_TIMEOUT):
    """GET and parse JSON; None on any failure. Never raises: every source is optional."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:  # noqa: BLE001 - a dead upstream must not kill the triage
        log("source unreachable %s: %s" % (url.split("?")[0], e.__class__.__name__))
        return None


def fetch_json(budget, url, headers=None):
    """get_json against the shared deadline: 'unreachable' without a call once the budget is spent."""
    remaining = budget.remaining()
    if remaining <= 0:
        return None, "unreachable"
    d = get_json(url, headers, timeout=min(SOURCE_TIMEOUT, remaining))
    return (None, "unreachable") if d is None else (d, "reached")


def combine(*statuses):
    """Merge the statuses of every call made against one logical endpoint (e.g. two /api/v1/query calls).
    'unreachable' wins even if another call to the same endpoint succeeded: a partial failure must not
    be reported as a clean "ok", or a consumer trusting sources[...] == "ok" would miss it."""
    statuses = [s for s in statuses if s]
    for pref in ("unreachable", "ok", "empty"):
        if pref in statuses:
            return pref
    return "skipped"


def prom_url(path, **params):
    return ENV("PROMETHEUS_URL", "http://prometheus:9090") + path + ("?" + urllib.parse.urlencode(params) if params else "")


def rule_for(name, budget):
    d, st = fetch_json(budget, prom_url("/api/v1/rules", type="alert"))
    if st == "unreachable":
        return None, "unreachable"
    if not isinstance(d, dict):        # an upstream returning the wrong shape is "empty", not a crash
        return None, "empty"
    for g in d.get("data", {}).get("groups", []):
        for r in g.get("rules", []):
            if r.get("name") == name:
                return {"query": r.get("query"), "health": r.get("health"), "group": g.get("name")}, "ok"
    return None, "empty"


def series_now(expr, budget, limit=20):
    if not expr:
        return None, "skipped"
    d, st = fetch_json(budget, prom_url("/api/v1/query", query=expr))
    if st == "unreachable":
        return None, "unreachable"
    if not isinstance(d, dict):
        return None, "empty"
    result = d.get("data", {}).get("result", [])[:limit]
    return [{"metric": x.get("metric", {}), "value": x["value"][1]} for x in result], ("ok" if result else "empty")


def series_30m(expr, budget, limit=20):
    if not expr:
        return None, "skipped"
    now = time.time()
    d, st = fetch_json(budget, prom_url("/api/v1/query_range", query=expr, start=now - 1800, end=now, step=60))
    if st == "unreachable":
        return None, "unreachable"
    if not isinstance(d, dict):
        return None, "empty"
    result = d.get("data", {}).get("result", [])[:limit]
    out = []
    for x in result:
        vals = [v[1] for v in x.get("values", [])]
        nums = [float(v) for v in vals if v not in ("NaN", "+Inf", "-Inf")]
        out.append({"metric": x.get("metric", {}), "points": len(vals),
                    "min": ("%g" % min(nums)) if nums else None, "max": ("%g" % max(nums)) if nums else None,
                    "first": vals[0] if vals else None, "last": vals[-1] if vals else None})
    return out, ("ok" if out else "empty")


def loki_errors(service, budget, limit=50):
    if not service:
        return [], "skipped"
    q = '{service="%s"} |~ "(?i)(error|exception|fatal|panic|traceback)"' % service
    now_ns = time.time_ns()
    url = ENV("LOKI_URL", "http://loki:3100") + "/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": q, "start": now_ns - 15 * 60 * 10**9, "end": now_ns, "limit": limit, "direction": "backward"})
    d, st = fetch_json(budget, url, {"X-Scope-OrgID": "fake"})
    if st == "unreachable":
        return [], "unreachable"
    if not isinstance(d, dict):
        return [], "empty"
    lines = []
    for s in d.get("data", {}).get("result", []):
        for ts, line in s.get("values", []):
            lines.append({"ts": ts, "line": line[:300]})
    lines.sort(key=lambda x: x["ts"], reverse=True)
    lines = lines[:limit]
    return lines, ("ok" if lines else "empty")


def firing_alerts(budget, limit=30):
    d, st = fetch_json(budget, ENV("ALERTMANAGER_URL", "http://alertmanager:9093") + "/api/v2/alerts?active=true&silenced=true&inhibited=true")
    if st == "unreachable":
        return [], "unreachable"
    if not isinstance(d, list):        # e.g. an error body like {"error": "..."} instead of the alert list
        return [], "empty"
    out = [{"labels": a.get("labels", {}), "startsAt": a.get("startsAt"), "state": a.get("status", {}).get("state"),
            "inhibitedBy": a.get("status", {}).get("inhibitedBy", []), "silencedBy": a.get("status", {}).get("silencedBy", [])}
           for a in d[:limit]]
    return out, ("ok" if out else "empty")


def deploys(budget, limit=10):
    now_ms = int(time.time() * 1000)
    url = ENV("GRAFANA_URL", "http://grafana:3000") + "/api/annotations?" + urllib.parse.urlencode(
        {"tags": "deploy", "from": now_ms - 2 * 3600 * 1000, "to": now_ms, "limit": limit})
    pw = ENV("GRAFANA_ADMIN_PASSWORD", "")
    hdr = {"Authorization": "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()} if pw else {}
    d, st = fetch_json(budget, url, hdr)
    if st == "unreachable":
        return [], "unreachable"
    if not isinstance(d, list):
        return [], "empty"
    out = [{"time": a.get("time"), "tags": a.get("tags", []), "text": a.get("text", "")} for a in d]
    return out, ("ok" if out else "empty")


def cap_lines(text, n=RUNBOOK_MAX_LINES):
    """Runbooks can run long; cap what leaves the box regardless of where it came from. Bounded on
    both axes: a line-count cap alone still lets one absurdly long unwrapped line (or a line with a
    pathological run of redact()-bait characters) through, so also hard-cap total characters."""
    lines = text.splitlines()
    capped = text if len(lines) <= n else "\n".join(lines[:n])
    return capped if len(capped) <= HARD_CAP_BYTES else capped[:HARD_CAP_BYTES]


def runbook(name):
    """Pro mounts runbooks/<Alert>.md; free has the matching ### section of docs/ALERTS.md. No network call, no budget."""
    p = os.path.join(ENV("RUNBOOK_DIR", "/runbooks"), name + ".md")
    if os.path.isfile(p):
        with open(p) as f:
            return {"source": "runbooks/%s.md" % name, "text": cap_lines(f.read())}, "ok"
    md = ENV("ALERTS_MD", "/docs/ALERTS.md")
    if os.path.isfile(md):
        with open(md) as f:
            md_text = f.read()
        m = re.search(r"^### %s\n(.*?)(?=^#{1,3} |\Z)" % re.escape(name), md_text, re.M | re.S)
        if m:
            return {"source": "docs/ALERTS.md#" + name.lower(), "text": cap_lines(m.group(1).strip())}, "ok"
    return {"source": None, "text": ""}, "empty"


def redact(obj):
    """Recurses over the whole pack; build the pattern list once here rather than on every recursive
    call (redact() used to rebuild it - including re-parsing TRIAGE_REDACT - once per string/list/dict
    in the tree)."""
    pats = list(DEFAULT_REDACT) + [(p, "[redacted]") for p in ENV("TRIAGE_REDACT", "").split(";;") if p.strip()]
    return _redact(obj, pats)


def _redact(obj, pats):
    if isinstance(obj, str):
        for pat, rep in pats:
            obj = re.sub(pat, rep, obj)
        return obj
    if isinstance(obj, list):
        return [_redact(x, pats) for x in obj]
    if isinstance(obj, dict):
        return {k: _redact(v, pats) for k, v in obj.items()}
    return obj


def trim(pack):
    """Shrink until the JSON fits MAX_BYTES. Cheapest context goes first; the runbook is last."""
    steps = [("logs", lambda: pack["logs"][:20]), ("logs", lambda: []), ("deploys", lambda: pack["deploys"][:3]),
             ("firing", lambda: pack["firing"][:10]), ("rule_30m", lambda: (pack["rule_30m"] or [])[:5]),
             ("rule_now", lambda: (pack["rule_now"] or [])[:5]), ("firing", lambda: []),
             ("up", lambda: None),
             # a big grouped alert (Alertmanager can group hundreds under one alertname/service/instance)
             # is the one field with no structural limit anywhere else in build_pack
             ("alerts", lambda: pack["alerts"][:20]),
             ("group", lambda: {k: pack["group"].get(k) for k in ("status", "receiver", "externalURL")}),
             ("runbook", lambda: {"source": pack["runbook"]["source"], "text": pack["runbook"]["text"][:3000]})]
    for key, shrink in steps:
        if len(json.dumps(pack)) <= MAX_BYTES:
            break
        pack[key] = shrink(); pack.setdefault("trimmed", []).append(key)
    # Last-resort valve: whatever is still oversized, keep cutting the runbook text until it fits.
    # ponytail: naive - always shrinks runbook.text even when it isn't the big field; fine at this size,
    # revisit if a single field can legitimately blow past HARD_CAP_BYTES on its own.
    while len(json.dumps(pack)) > HARD_CAP_BYTES:
        text = pack["runbook"]["text"]
        if not text:
            break
        pack["runbook"]["text"] = text[:max(0, len(text) - 500)]
        pack["truncated"] = True
    return pack


def build_pack(payload):
    alerts = payload.get("alerts", [])
    labels = alerts[0].get("labels", {}) if alerts else {}
    name = labels.get("alertname", "")
    budget = Budget(TOTAL_DEADLINE)

    pack = {"schema_version": SCHEMA_VERSION, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "project": ENV("PROJECT_NAME", ""),
            "group": {k: payload.get(k) for k in ("status", "receiver", "groupLabels", "commonLabels", "externalURL")},
            "alerts": [{k: a.get(k) for k in ("labels", "annotations", "startsAt", "fingerprint", "generatorURL")} for a in alerts]}

    pack["rule"], rules_status = rule_for(name, budget)
    rule_expr = pack["rule"]["query"] if pack["rule"] else None
    pack["rule_now"], now_status = series_now(rule_expr, budget)
    pack["rule_30m"], range_status = series_30m(rule_expr, budget)
    inst = labels.get("instance")
    pack["up"], up_status = series_now(('up{instance="%s"}' % inst) if inst else None, budget)
    pack["logs"], loki_status = loki_errors(labels.get("service") or labels.get("job"), budget)
    pack["firing"], am_status = firing_alerts(budget)
    pack["deploys"], grafana_status = deploys(budget)
    pack["runbook"], runbook_status = runbook(name)

    pack["sources"] = {
        "alertmanager": am_status,
        "rules": rules_status,
        "query": combine(now_status, up_status),
        "query_range": range_status,
        "loki": loki_status,
        "grafana": grafana_status,
        "runbook": runbook_status,
    }
    return trim(redact(pack))


class Dedup:
    """process() runs on a fresh thread per webhook POST, so seen() needs its own lock: without it,
    two concurrent requests for the same group can both read an empty/stale self.stamp and both
    proceed, defeating the dedup."""
    def __init__(self, seconds=DEDUP_SECONDS): self.seconds, self.stamp, self.lock = seconds, {}, threading.Lock()

    def seen(self, key):
        now = time.time()
        with self.lock:
            self.stamp = {k: t for k, t in self.stamp.items() if now - t < self.seconds}
            if key in self.stamp:
                return True
            self.stamp[key] = now
            return False


DEDUP = Dedup()


def process(payload):
    key = payload.get("groupKey") or json.dumps(payload.get("groupLabels", {}), sort_keys=True)
    if DEDUP.seen(key):
        log("skip: group already triaged within %ds: %s" % (DEDUP_SECONDS, key)); return
    try:
        pack = build_pack(payload)
    except Exception as e:  # noqa: BLE001 - an upstream returning garbage must not kill this thread
        # DEDUP.seen() above already marked this key seen; on failure we deliberately leave that mark
        # in place rather than undo it, so a repeatedly-firing alert is skipped for DEDUP_SECONDS
        # instead of hammering a broken upstream on every Alertmanager repeat.
        log("build_pack failed for %s: %s: %s" % (key, e.__class__.__name__, e)); return
    if ENV("TRIAGE_DRY_RUN", "true").lower() == "true":
        log("dry run pack (%d bytes, sources %s)" % (len(json.dumps(pack)), json.dumps(pack["sources"])))
        print(json.dumps(pack), flush=True); return
    # Task 10 adds: note = send_to_cloud(pack); post_note(note)
    log("TRIAGE_DRY_RUN=false but cloud delivery is not built yet; pack dropped")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/healthz" else 404); self.end_headers()

    def do_POST(self):
        if self.path != "/alert":
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(n).decode() or "{}")
        except ValueError:
            self.send_response(400); self.end_headers(); return
        self.send_response(200); self.end_headers()        # Alertmanager retries on non-2xx; never make it wait
        threading.Thread(target=process, args=(payload,), daemon=True).start()

    def log_message(self, *a): pass


def serve(port=9096):
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


if __name__ == "__main__":
    log("listening on :9096, dry_run=%s" % ENV("TRIAGE_DRY_RUN", "true"))
    ThreadingHTTPServer(("0.0.0.0", 9096), Handler).serve_forever()

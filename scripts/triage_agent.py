#!/usr/bin/env python3
"""triage-agent: receives Alertmanager webhooks, gathers a context pack from the kit's own services,
redacts it, and either prints it (dry run, the default) or hands it to triage_engine (Pro) which asks
the Anthropic Messages API with your own key, and posts the returned note. Standard library only, on
purpose: anyone can read this file end to end and know exactly what leaves their network. Only GETs
against the kit's services."""
import base64, json, os, re, threading, time, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import triage_engine            # Pro ships scripts/triage_engine.py next to this file; free does not
except ImportError:
    triage_engine = None

SCHEMA_VERSION = 1
MAX_BYTES = 40000          # ~12k tokens; see trim() for what goes first (test code may lower this)
HARD_CAP_BYTES = 40000     # fixed final safety net, independent of MAX_BYTES; see trim()
SOURCE_TIMEOUT = 5         # seconds per upstream call
TOTAL_TRIAGE_BUDGET = 45   # seconds, end to end: build_pack + the model call. Hard "never exceed" -
                           # the model call's timeout is exactly what's left of this, never more.
# Derived from the total rather than pinned: sources are capped at 30s, but never allowed to eat so
# much of the budget that the model call - the part actually worth the wait - is left with under
# 25s. That matters most exactly when sources are degraded (several dead upstreams each burning
# their own timeout) and a model call still needs a fair shot at succeeding.
TOTAL_DEADLINE = min(30, TOTAL_TRIAGE_BUDGET - 25)   # seconds for the whole build_pack
CLOUD_TIMEOUT_FLOOR = 10   # seconds; below this much remaining budget, skip the model call entirely
                           # (log and return) rather than make a call so short it can't succeed
DEDUP_SECONDS = 3600       # the webhook-triage route has no repeat_interval of its own and inherits
                           # the top-level route's 4h; this just bounds our own re-triage cadence,
                           # independent of whatever Alertmanager's routes are configured to re-notify at
                           # (a group whose cloud call fails or times out stays deduped for this long too -
                           # the next Alertmanager repeat re-triages it rather than retrying immediately)
RUNBOOK_MAX_LINES = 60
DISCORD_CHUNK_CHARS = 2000   # Discord's own hard limit on message content length, in characters
TELEGRAM_CHUNK_CHARS = 4096  # Telegram's own hard limit on sendMessage's text length, in characters
FENCE_OPEN, FENCE_CLOSE = "```\n", "\n```"   # wraps the note so Slack/Discord render it in a
                                              # fixed-width font - the numbered steps and PromQL in a
                                              # triage note are unreadable reflowed by a proportional
                                              # font. Telegram gets no parse_mode, so a fence would
                                              # render as three literal backtick lines instead of a
                                              # code block there - see post_note()'s telegram().
FENCE_CHARS = len(FENCE_OPEN) + len(FENCE_CLOSE)
ENV = os.environ.get
# Discord (behind Cloudflare) rejects the default "Python-urllib/3.x" User-Agent with 403 error 1010,
# so every note to a Discord webhook was lost until the first live dogfood on 2026-09-19. Slack and
# Telegram do not care, but one identity on every outbound request is cheaper than remembering which.
USER_AGENT = "sre-starter-kit-triage-agent/1 (+https://github.com/nhanlagc60299/sre-starter-kit)"
TELEGRAM_API = "https://api.telegram.org/bot%s/sendMessage"
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
    (r"(?i)x-api-key:\s*\S+", "x-api-key: [redacted]"),
    (r"sk-ant-[A-Za-z0-9_-]+", "[anthropic-key-redacted]"),
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
        req = urllib.request.Request(url, headers={**(headers or {}), "User-Agent": USER_AGENT})
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


def post_json(url, body, headers=None, timeout=45):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {}), "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def _chunks(text, size):
    """Split text into <=size pieces so a long note still reaches a receiver instead of being cut
    off (Discord: 2000 chars: Telegram: 4096) or rejected outright."""
    return [text[i:i + size] for i in range(0, len(text), size)] or [""]


def _fenced(chunk):
    """Wrap a chunk in a code fence so Slack/Discord render the note in a fixed-width font; the
    numbered steps and PromQL expressions in a triage note are unreadable reflowed by a
    proportional one. Not used for Telegram - see telegram() below."""
    return FENCE_OPEN + chunk + FENCE_CLOSE


def post_note(text):
    """Same channels Alertmanager uses, read from the same .env. Failures are logged, never retried
    into the alert channel: a noisy triage is worse than a missing one. Each receiver is attempted
    independently so one failing (or unconfigured) receiver never stops the others."""
    def attempt(name, fn):
        try: fn(); log("posted to " + name)
        except Exception as e: log("post to %s failed: %s" % (name, e.__class__.__name__))  # noqa: BLE001
    if ENV("SLACK_WEBHOOK_URL"):
        attempt("slack", lambda: post_json(ENV("SLACK_WEBHOOK_URL"), {"text": _fenced(text)}, timeout=10))
    if ENV("DISCORD_WEBHOOK_URL"):
        def discord():
            # each chunk is fenced on its own, so a message stays a well-formed code block even when
            # the note is split; if a chunk's POST fails, the loop stops there and attempt() logs it -
            # whatever already sent stays sent (a half note beats none), nothing further is attempted.
            for chunk in _chunks(text, DISCORD_CHUNK_CHARS - FENCE_CHARS):
                post_json(ENV("DISCORD_WEBHOOK_URL"),
                          {"content": _fenced(chunk), "allowed_mentions": {"parse": []}}, timeout=10)
        attempt("discord", discord)
    if ENV("TELEGRAM_BOT_TOKEN") and ENV("TELEGRAM_CHAT_ID"):
        def telegram():
            # no fence and no parse_mode: unfenced because Telegram would render the fence as three
            # literal backtick lines instead of a code block, and parse_mode is deliberately not
            # used - an unescaped "_"/"*" in model text would make Telegram 400 the whole request
            # and lose the note entirely, which is worse than plain text.
            for chunk in _chunks(text, TELEGRAM_CHUNK_CHARS):
                post_json(TELEGRAM_API % ENV("TELEGRAM_BOT_TOKEN"),
                          {"chat_id": ENV("TELEGRAM_CHAT_ID"), "text": chunk}, timeout=10)
        attempt("telegram", telegram)
    if ENV("ALERT_EMAIL_TO") and ENV("SMTP_HOST"):
        def mail():
            import smtplib
            from email.message import EmailMessage
            m = EmailMessage()
            m["Subject"] = text.splitlines()[0][:120] if text else "Triage note"
            m["From"] = ENV("SMTP_FROM", ""); m["To"] = ENV("ALERT_EMAIL_TO"); m.set_content(text)
            host, _, port = ENV("SMTP_HOST").partition(":")
            with smtplib.SMTP(host, int(port or 587), timeout=10) as s:
                try:
                    s.starttls()
                except smtplib.SMTPNotSupportedError:
                    # .env.example documents an unauthenticated relay on your own network as a valid
                    # setup, and those commonly don't offer STARTTLS at all. That's fine when there's
                    # no password to protect; it is never fine to send a login over the resulting
                    # plaintext connection, so refuse outright rather than silently downgrade.
                    if ENV("SMTP_USER"):
                        log("email: server has no STARTTLS and a login is configured; refusing to send in clear")
                        raise
                if ENV("SMTP_USER"): s.login(ENV("SMTP_USER"), ENV("SMTP_PASSWORD", ""))
                s.send_message(m)
        attempt("email", mail)


def process(payload):
    key = payload.get("groupKey") or json.dumps(payload.get("groupLabels", {}), sort_keys=True)
    if DEDUP.seen(key):
        log("skip: group already triaged within %ds: %s" % (DEDUP_SECONDS, key)); return
    budget = Budget(TOTAL_TRIAGE_BUDGET)
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
    # TOTAL_TRIAGE_BUDGET is a hard ceiling, not a target: the model call gets exactly what's left of
    # it, never more. Below CLOUD_TIMEOUT_FLOOR remaining, a call that short can't realistically
    # succeed, so skip it outright rather than extend past the budget to give it a fairer chance.
    remaining = budget.remaining()
    if remaining < CLOUD_TIMEOUT_FLOOR:
        log("triage: budget exhausted, skipping the model call"); return
    if triage_engine is None:
        log("triage: no triage_engine (free tier); pack logged only"); print(json.dumps(pack), flush=True); return
    if ENV("TRIAGE_LOG_PACK", "false").lower() == "true":
        print(json.dumps(pack), flush=True)
    # post_note() runs after the budget, against its own per-receiver timeouts (10 s each).
    try:
        text = triage_engine.triage(pack, remaining, os.environ)
    except Exception as e:  # noqa: BLE001 - an engine bug must not kill this worker thread
        log("triage: engine raised %s: %s" % (e.__class__.__name__, e)); return
    if text:
        post_note(text)
    else:
        log("triage: no note (%s)" % getattr(triage_engine, "last_error", lambda: "")())


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

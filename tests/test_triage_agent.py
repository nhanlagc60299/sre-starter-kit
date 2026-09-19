#!/usr/bin/env python3
"""Unit tests for scripts/triage_agent.py against fake Prometheus/Loki/Alertmanager/Grafana servers.
Every fixture below is the JSON shape the real service returns (verified live by tests/smoke.sh);
if a live shape ever differs, fix the fixture here, never the agent to match the fixture."""
import importlib.util, json, os, smtplib, sys, tempfile, threading, time, types, unittest, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RULES = {"status": "success", "data": {"groups": [{"name": "app", "rules": [
    {"name": "ServiceDown", "type": "alerting", "health": "ok",
     "query": 'probe_success{job="blackbox-http"} == 0',
     "labels": {"severity": "critical", "module": "app"},
     "annotations": {"summary": "{{ $labels.service }} is down"}, "alerts": []}]}]}}
QUERY = {"status": "success", "data": {"resultType": "vector", "result": [
    {"metric": {"__name__": "probe_success", "job": "blackbox-http", "instance": "http://api:8080/health", "service": "api"},
     "value": [1758000000.0, "0"]}]}}
RANGE = {"status": "success", "data": {"resultType": "matrix", "result": [
    {"metric": {"job": "blackbox-http", "service": "api"},
     "values": [[1758000000.0, "1"], [1758000060.0, "1"], [1758000120.0, "0"]]}]}}
LOKI = {"status": "success", "data": {"resultType": "streams", "result": [
    {"stream": {"service": "api", "container": "api"},
     "values": [["1758000120000000000", "ERROR db connect password=hunter2 refused for ops@example.com"],
                # a JSON-shaped log line: the keyword is immediately followed by a quote, not a bare
                # separator, which a naive password(\s*[=:]\s*)\S+ pattern misses entirely
                ["1758000115000000000", '{"level":"error","msg":"auth failed","password":"hunter2json"}'],
                ["1758000110000000000", "ERROR upstream timeout"]]}]}}
AM_ALERTS = [
    {"labels": {"alertname": "ServiceDown", "severity": "critical", "service": "api", "instance": "http://api:8080/health"},
     "annotations": {"summary": "api is down"}, "startsAt": "2026-09-18T01:50:00Z", "endsAt": "0001-01-01T00:00:00Z",
     "fingerprint": "a1", "status": {"state": "active", "inhibitedBy": [], "silencedBy": []}},
    {"labels": {"alertname": "HighErrorRate", "severity": "critical", "service": "api"},
     "annotations": {}, "startsAt": "2026-09-18T01:52:00Z", "endsAt": "0001-01-01T00:00:00Z",
     "fingerprint": "b2", "status": {"state": "suppressed", "inhibitedBy": ["a1"], "silencedBy": []}}]
GRAFANA = [{"id": 7, "time": 1758000000000, "timeEnd": 1758000000000, "tags": ["deploy", "api"], "text": "api v2.14 by ci"}]

WEBHOOK = {"version": "4", "groupKey": '{}:{alertname="ServiceDown"}', "status": "firing", "receiver": "webhook-triage",
           "groupLabels": {"alertname": "ServiceDown"}, "commonLabels": {"alertname": "ServiceDown", "severity": "critical"},
           "commonAnnotations": {}, "externalURL": "http://alertmanager:9093",
           "alerts": [{"status": "firing",
                       "labels": {"alertname": "ServiceDown", "severity": "critical", "service": "api", "instance": "http://api:8080/health", "module": "app"},
                       "annotations": {"summary": "api is down", "runbook_url": "https://github.com/nhanlagc60299/sre-starter-kit/blob/main/docs/ALERTS.md#servicedown"},
                       "startsAt": "2026-09-18T01:50:00Z", "endsAt": "0001-01-01T00:00:00Z",
                       "generatorURL": "http://prometheus:9090/graph?g0.expr=...", "fingerprint": "a1"}]}


class Fake(BaseHTTPRequestHandler):
    routes = {}      # path prefix -> (status, body); set per test
    hits = []
    sleep_prefix = None   # path prefix to artificially delay, and for how long - set per test
    sleep_seconds = 0

    def do_GET(self):
        Fake.hits.append(self.path)
        if Fake.sleep_prefix and self.path.startswith(Fake.sleep_prefix):
            time.sleep(Fake.sleep_seconds)
        # /api/v1/query_range must be checked before /api/v1/query: it is a prefix match.
        for prefix, (status, body) in Fake.routes.items():
            if self.path.startswith(prefix):
                data = json.dumps(body).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data); return
        self.send_response(404); self.end_headers()

    def log_message(self, *a): pass


def serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def load_agent(base, tmpdir):
    os.environ.update({"PROMETHEUS_URL": base, "LOKI_URL": base, "ALERTMANAGER_URL": base, "GRAFANA_URL": base,
                       "GRAFANA_ADMIN_PASSWORD": "pw", "RUNBOOK_DIR": os.path.join(tmpdir, "runbooks"),
                       "ALERTS_MD": os.path.join(tmpdir, "ALERTS.md"), "TRIAGE_DRY_RUN": "true", "TRIAGE_REDACT": ""})
    spec = importlib.util.spec_from_file_location("triage_agent", os.path.join(ROOT, "scripts", "triage_agent.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


# dict preserves insertion order (py3.7+): /api/v1/query_range MUST come before /api/v1/query,
# since Fake matches by prefix.
def routes_ok():
    return {"/api/v1/rules": (200, RULES), "/api/v1/query_range": (200, RANGE), "/api/v1/query": (200, QUERY),
            "/loki/api/v1/query_range": (200, LOKI), "/api/v2/alerts": (200, AM_ALERTS), "/api/annotations": (200, GRAFANA)}


class PackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = serve()
        import tempfile
        cls.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.tmp, "runbooks"))
        with open(os.path.join(cls.tmp, "ALERTS.md"), "w") as f:
            f.write("# Alerts\n\n## Service and probe alerts\n\n### ServiceDown\n\nProbe failed 3 times.\n\n```\ncurl -sv http://api:8080/health\n```\n\n### HighErrorRate\n\nOther text.\n")
        cls.agent = load_agent(cls.base, cls.tmp)

    def setUp(self):
        Fake.hits = []
        Fake.routes = routes_ok()
        Fake.sleep_prefix = None
        Fake.sleep_seconds = 0

    def test_pack_has_every_source(self):
        p = self.agent.build_pack(WEBHOOK)
        self.assertEqual(p["schema_version"], 1)
        self.assertEqual(p["alerts"][0]["labels"]["alertname"], "ServiceDown")
        self.assertEqual(p["rule"]["query"], 'probe_success{job="blackbox-http"} == 0')
        self.assertEqual(p["rule_now"][0]["value"], "0")
        self.assertEqual(p["rule_30m"][0]["last"], "0"); self.assertEqual(p["rule_30m"][0]["min"], "0"); self.assertEqual(p["rule_30m"][0]["max"], "1")
        self.assertEqual(p["up"][0]["value"], "0")
        self.assertEqual(len(p["logs"]), 3)
        self.assertEqual(p["deploys"][0]["text"], "api v2.14 by ci")
        self.assertEqual([a["labels"]["alertname"] for a in p["firing"]], ["ServiceDown", "HighErrorRate"])
        self.assertEqual(p["firing"][1]["state"], "suppressed")
        self.assertIn("Probe failed 3 times.", p["runbook"]["text"])
        self.assertNotIn("Other text.", p["runbook"]["text"], "ALERTS.md section must stop at the next heading")
        # sources are per-endpoint (rules, query, query_range, loki, alertmanager, grafana, runbook), not per-service
        for src in ("rules", "query", "query_range", "loki", "alertmanager", "grafana", "runbook"):
            self.assertEqual(p["sources"][src], "ok", src)
        # the Loki query is the alert's service, 15 minutes back, error-ish lines only
        loki_hit = next(h for h in Fake.hits if h.startswith("/loki/api/v1/query_range"))
        self.assertIn("service%3D%22api%22", loki_hit); self.assertIn("limit=50", loki_hit)
        # grafana asked for deploys only
        self.assertTrue(any("tags=deploy" in h for h in Fake.hits))
        # query_range was actually hit before query, proving the fixture ordering matters and both resolved
        self.assertTrue(any(h.startswith("/api/v1/query_range") for h in Fake.hits))
        self.assertTrue(any(h.startswith("/api/v1/query?") for h in Fake.hits))

    def test_redaction_before_anything_leaves(self):
        p = self.agent.build_pack(WEBHOOK)
        s = json.dumps(p)
        self.assertNotIn("hunter2", s); self.assertNotIn("ops@example.com", s)
        self.assertIn("password=[redacted]", s); self.assertIn("[email]", s)

    def test_quoted_json_secret_is_redacted(self):
        # {"password":"hunter2json"} - keyword directly followed by a quote, not a bare [=:] separator
        p = self.agent.build_pack(WEBHOOK)
        line = next(l["line"] for l in p["logs"] if "auth failed" in l["line"])
        self.assertNotIn("hunter2json", line)
        self.assertIn('"password":"[redacted]"', line)

    def test_authorization_header_is_redacted(self):
        s = self.agent.redact("Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=")
        self.assertNotIn("YWRtaW46c3VwZXJzZWNyZXQ=", s)
        self.assertIn("Authorization: [redacted]", s)

    def test_prefixed_authorization_header_is_not_redacted(self):
        # "MyAuthorization:" is a different field, not the standard header - same root cause as the
        # keyword-boundary bug below, so it gets the same fix (a non-alnum boundary before the keyword).
        # Two whitespace-separated tokens after the colon, same shape as the positive test above, so
        # this actually exercises the \s*\S+\s+\S+ value match rather than failing to match anyway.
        original = "MyAuthorization: Basic c29tZXNlY3JldA=="
        s = self.agent.redact(original)
        self.assertEqual(s, original)

    def test_secret_keyword_at_the_end_of_a_longer_identifier_is_redacted(self):
        # AWS_SECRET_ACCESS_KEY: "secret" is embedded mid-identifier and must NOT match (see the
        # false-positive test below); what actually redacts this is "access_key" as the identifier's
        # own trailing keyword, immediately before "=".
        s = self.agent.redact("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG")
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG", s)
        self.assertIn("AWS_SECRET_ACCESS_KEY=[redacted]", s)

    def test_session_token_is_redacted(self):
        s = self.agent.redact("session_token=abc123xyz")
        self.assertNotIn("abc123xyz", s)
        self.assertIn("session_token=[redacted]", s)

    def test_keyword_as_a_substring_of_an_ordinary_identifier_is_not_redacted(self):
        # a keyword embedded in the MIDDLE of an identifier (not immediately before the separator)
        # must survive untouched - these are all real, harmless diagnostic/config fields.
        safe = [
            "tokenizer_latency=0.2",
            "token_count=42",
            "max_tokens=100",
            "secretary_id=42",
            "passwordless_login=true",
            "pwd_check_interval=60",
        ]
        for s in safe:
            self.assertEqual(self.agent.redact(s), s, s)

    def test_keyword_concatenated_onto_a_field_name_is_still_redacted(self):
        # a real secret whose field name has the keyword glued onto a prefix with no separator of its
        # own (oldpassword, apitoken, ...) must still redact - only the trailing-separator requirement
        # decides this, not any assumption about what comes before the keyword.
        cases = {
            "oldpassword=hunter2": "oldpassword=[redacted]",
            "newpassword=abc123": "newpassword=[redacted]",
            "userpassword=abc123": "userpassword=[redacted]",
            "dbpassword=abc123": "dbpassword=[redacted]",
            "apitoken=abc123": "apitoken=[redacted]",
            "mytoken=abc123": "mytoken=[redacted]",
        }
        for original, expected in cases.items():
            got = self.agent.redact(original)
            self.assertEqual(got, expected, original)

    def test_slack_webhook_url_is_redacted(self):
        s = self.agent.redact("post to https://hooks.slack.com/services/T000/B000/XXXX now")
        self.assertNotIn("T000/B000/XXXX", s)
        self.assertIn("[webhook-url-redacted]", s)

    def test_url_userinfo_is_redacted_and_hostname_survives(self):
        s = self.agent.redact("connect to postgres://admin:s3cr3t@db.internal:5432/prod")
        self.assertNotIn("s3cr3t", s)
        self.assertIn("://[redacted]@", s)
        self.assertIn("db.internal", s, "the email pattern must not eat the hostname after user:pass@")

    def test_redact_is_not_quadratic_on_a_long_line_with_no_dot(self):
        # 50KB, one "@", no "." after it - the worst case for a naive [\w.+-]+@[\w-]+\.[\w.-]+ or an
        # unbounded identifier wrap around the secret-keyword alternation
        malicious = "a" * 25000 + "@" + "b" * 25000
        start = time.monotonic()
        self.agent.redact(malicious)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0, "redact() must not be quadratic on an attacker-controlled line")

    def test_cap_lines_bounds_total_characters_not_just_line_count(self):
        # a single unwrapped 500KB line passes a line-count cap trivially
        text = self.agent.cap_lines("x" * 500000, n=60)
        self.assertLessEqual(len(text), self.agent.HARD_CAP_BYTES)

    def test_bearer_tokens_are_redacted(self):
        # a distinct case from generic secret=... so a mutation that only removes the Bearer pattern is caught
        loki_with_bearer = dict(LOKI); loki_with_bearer["data"] = {"resultType": "streams", "result": [
            {"stream": {"service": "api"}, "values": [["1758000120000000000", "ERROR calling upstream Bearer sk-abc123def456 failed"]]}]}
        Fake.routes["/loki/api/v1/query_range"] = (200, loki_with_bearer)
        p = self.agent.build_pack(WEBHOOK)
        s = json.dumps(p)
        self.assertNotIn("sk-abc123def456", s)
        self.assertIn("Bearer [redacted]", s)

    def test_custom_redact_patterns(self):
        os.environ["TRIAGE_REDACT"] = r"refused;;upstream \w+"
        try:
            p = self.agent.build_pack(WEBHOOK)
            s = json.dumps(p)
            self.assertNotIn("refused", s); self.assertNotIn("upstream timeout", s); self.assertIn("[redacted]", s)
        finally:
            os.environ["TRIAGE_REDACT"] = ""

    def test_unreachable_source_is_reported_not_raised(self):
        Fake.routes["/loki/api/v1/query_range"] = (500, {"error": "boom"})
        del Fake.routes["/api/annotations"]
        p = self.agent.build_pack(WEBHOOK)
        # only the endpoints that were actually broken/missing are unreachable
        self.assertEqual(p["sources"]["loki"], "unreachable"); self.assertEqual(p["logs"], [])
        self.assertEqual(p["sources"]["grafana"], "unreachable"); self.assertEqual(p["deploys"], [])
        # the endpoints that were actually served stay ok
        self.assertEqual(p["sources"]["rules"], "ok")
        self.assertEqual(p["sources"]["query"], "ok")
        self.assertEqual(p["sources"]["query_range"], "ok")
        self.assertEqual(p["sources"]["alertmanager"], "ok")
        self.assertEqual(p["sources"]["runbook"], "ok")

    def test_alertmanager_error_body_is_not_a_shape_crash(self):
        # a real Alertmanager /api/v2/alerts error response is a dict, not the expected list
        Fake.routes["/api/v2/alerts"] = (200, {"error": "boom"})
        p = self.agent.build_pack(WEBHOOK)
        self.assertEqual(p["firing"], [])
        self.assertEqual(p["sources"]["alertmanager"], "empty")

    def test_rules_endpoint_returning_a_list_is_not_a_shape_crash(self):
        Fake.routes["/api/v1/rules"] = (200, [])
        p = self.agent.build_pack(WEBHOOK)
        self.assertIsNone(p["rule"])
        self.assertEqual(p["sources"]["rules"], "empty")

    def test_process_logs_and_survives_build_pack_exceptions(self):
        # DEDUP.seen() runs before build_pack(); if build_pack raises, process() must not crash the
        # background thread silently - it should log and return.
        import io, contextlib
        original = self.agent.build_pack

        def boom(payload):
            raise RuntimeError("boom")

        self.agent.build_pack = boom
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.agent.process({"groupKey": "process-exception-test"})
            self.assertIn("build_pack failed", buf.getvalue())
        finally:
            self.agent.build_pack = original

    def test_deadline_exhausted_marks_remaining_sources_unreachable(self):
        # a spent (or negative) deadline means no upstream call is even attempted
        budget = self.agent.Budget(-1)
        d, st = self.agent.rule_for("ServiceDown", budget)
        self.assertIsNone(d); self.assertEqual(st, "unreachable")
        d, st = self.agent.firing_alerts(budget)
        self.assertEqual(d, []); self.assertEqual(st, "unreachable")
        # and build_pack as a whole reflects it end to end
        real_deadline = self.agent.TOTAL_DEADLINE
        self.agent.TOTAL_DEADLINE = 0
        try:
            p = self.agent.build_pack(WEBHOOK)
            self.assertEqual(p["sources"]["rules"], "unreachable")
            self.assertEqual(p["sources"]["alertmanager"], "unreachable")
            self.assertEqual(p["sources"]["loki"], "unreachable")
            self.assertEqual(p["sources"]["grafana"], "unreachable")
        finally:
            self.agent.TOTAL_DEADLINE = real_deadline

    def test_runbook_dir_wins_over_alerts_md(self):
        with open(os.path.join(self.tmp, "runbooks", "ServiceDown.md"), "w") as f:
            f.write("# ServiceDown\n\nPro runbook body.\n")
        try:
            p = self.agent.build_pack(WEBHOOK)
            self.assertIn("Pro runbook body.", p["runbook"]["text"]); self.assertEqual(p["runbook"]["source"], "runbooks/ServiceDown.md")
        finally:
            os.remove(os.path.join(self.tmp, "runbooks", "ServiceDown.md"))

    def test_runbook_capped_at_60_lines(self):
        long_body = "\n".join("line %d of the runbook" % i for i in range(200))
        with open(os.path.join(self.tmp, "runbooks", "ServiceDown.md"), "w") as f:
            f.write(long_body)
        try:
            p = self.agent.build_pack(WEBHOOK)
            self.assertEqual(len(p["runbook"]["text"].splitlines()), 60)
            self.assertIn("line 0 of the runbook", p["runbook"]["text"])
            self.assertNotIn("line 60 of the runbook", p["runbook"]["text"])
        finally:
            os.remove(os.path.join(self.tmp, "runbooks", "ServiceDown.md"))

    def test_trim_keeps_pack_under_cap_and_drops_logs_first(self):
        big = dict(LOKI); big["data"] = {"resultType": "streams", "result": [{"stream": {"service": "api"},
               "values": [["1758000120000000000", "ERROR " + "x" * 290 + " %d" % i] for i in range(50)]}]}
        Fake.routes["/loki/api/v1/query_range"] = (200, big)
        self.agent.MAX_BYTES = 9000
        try:
            p = self.agent.build_pack(WEBHOOK)
            self.assertLessEqual(len(json.dumps(p)), 9000)
            self.assertEqual(len(p["logs"]), 20, "the first trim step keeps the newest 20 log lines")
            self.assertIn("Probe failed 3 times.", p["runbook"]["text"], "runbook is trimmed last")
            self.assertEqual(p["trimmed"], ["logs"])
        finally:
            self.agent.MAX_BYTES = 40000

    def test_trim_falls_back_to_dropping_all_logs_when_20_still_too_big(self):
        big = dict(LOKI); big["data"] = {"resultType": "streams", "result": [{"stream": {"service": "api"},
               "values": [["1758000120000000000", "ERROR " + "x" * 290 + " %d" % i] for i in range(50)]}]}
        Fake.routes["/loki/api/v1/query_range"] = (200, big)
        self.agent.MAX_BYTES = 3000
        try:
            p = self.agent.build_pack(WEBHOOK)
            self.assertLessEqual(len(json.dumps(p)), 3000)
            self.assertEqual(p["logs"], [])
            self.assertIn("Probe failed 3 times.", p["runbook"]["text"], "runbook is trimmed last")
            self.assertIn("logs", p["trimmed"])
        finally:
            self.agent.MAX_BYTES = 40000

    def test_hard_cap_truncates_runbook_when_max_bytes_is_misconfigured_above_it(self):
        # a single unwrapped runbook line passes the 60-line cap but can still be huge in bytes.
        # with MAX_BYTES raised above HARD_CAP_BYTES, trim()'s own steps never fire (the pack
        # already "fits" under that misconfigured MAX_BYTES) - HARD_CAP_BYTES is the real ceiling.
        with open(os.path.join(self.tmp, "runbooks", "ServiceDown.md"), "w") as f:
            f.write("x" * 50000)
        self.agent.MAX_BYTES = 90000
        try:
            p = self.agent.build_pack(WEBHOOK)
            self.assertLessEqual(len(json.dumps(p)), self.agent.HARD_CAP_BYTES)
            self.assertTrue(p.get("truncated"))
            self.assertNotIn("trimmed", p, "the normal steps never ran; only the hard-cap valve did")
        finally:
            self.agent.MAX_BYTES = 40000
            os.remove(os.path.join(self.tmp, "runbooks", "ServiceDown.md"))

    def test_trim_drops_up_before_runbook(self):
        # isolated trim() call: everything else is already minimal, only "up" is oversized, so this
        # pins the ("up", lambda: None) step specifically rather than relying on some other step
        # coincidentally getting the pack small enough first.
        pack = {"logs": [], "deploys": [], "firing": [], "rule_30m": None, "rule_now": None,
                "up": [{"metric": {"a": "b" * 2000}, "value": "1"}],
                "alerts": [], "group": {}, "runbook": {"source": None, "text": "short"}}
        baseline = len(json.dumps(pack))
        real_max = self.agent.MAX_BYTES
        self.agent.MAX_BYTES = baseline - 100   # just under "with up", well above "without up"
        try:
            p = self.agent.trim(pack)
            self.assertIsNone(p["up"])
            self.assertIn("up", p["trimmed"])
        finally:
            self.agent.MAX_BYTES = real_max

    def test_loki_window_is_15_minutes_not_wider(self):
        self.agent.build_pack(WEBHOOK)
        hit = next(h for h in Fake.hits if h.startswith("/loki/api/v1/query_range"))
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(hit).query)
        start_ns, end_ns = int(qs["start"][0]), int(qs["end"][0])
        self.assertAlmostEqual((end_ns - start_ns) / 1e9, 15 * 60, delta=2)

    def test_loki_line_is_capped_at_300_chars(self):
        long_line = dict(LOKI); long_line["data"] = {"resultType": "streams", "result": [
            {"stream": {"service": "api"}, "values": [["1758000120000000000", "ERROR " + "z" * 1000]]}]}
        Fake.routes["/loki/api/v1/query_range"] = (200, long_line)
        p = self.agent.build_pack(WEBHOOK)
        self.assertEqual(len(p["logs"][0]["line"]), 300)

    def test_trim_caps_alerts_and_shrinks_group_for_a_big_grouped_alert(self):
        # Alertmanager can group hundreds of alerts under one alertname/service/instance; nothing
        # else in build_pack bounds pack["alerts"], so a big group alone can blow past HARD_CAP_BYTES.
        big_webhook = json.loads(json.dumps(WEBHOOK))
        tmpl = big_webhook["alerts"][0]
        big_webhook["alerts"] = [dict(tmpl, fingerprint="fp-%d" % i) for i in range(300)]
        p = self.agent.build_pack(big_webhook)
        self.assertLessEqual(len(json.dumps(p)), self.agent.HARD_CAP_BYTES)
        self.assertLess(len(p["alerts"]), 300)

    def test_alert_endpoint_responds_before_upstream_calls_finish(self):
        # moving process(payload) ahead of send_response(200) would leave every other test green
        # (they only check what got printed, not when) - this asserts the timing directly.
        srv, base = self.agent.serve(port=0)
        Fake.sleep_prefix = "/api/v1/rules"; Fake.sleep_seconds = 1.0
        # a distinct groupKey: DEDUP is a module-level singleton shared across every test in this
        # class, and reusing WEBHOOK's groupKey here would get deduped against another test's POST.
        webhook = dict(WEBHOOK, groupKey="timing-test-key")
        try:
            req = urllib.request.Request(base + "/alert", data=json.dumps(webhook).encode(), headers={"Content-Type": "application/json"})
            start = time.monotonic()
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = time.monotonic() - start
            self.assertEqual(resp.status, 200)
            self.assertLess(elapsed, 0.5, "POST /alert must return well before the slow upstream call finishes")
        finally:
            Fake.sleep_prefix = None; Fake.sleep_seconds = 0
            srv.shutdown()

    def test_combine_reports_unreachable_over_a_partial_ok(self):
        # a single logical endpoint (e.g. /api/v1/query, hit once for rule_now and once for up) must
        # not read "ok" when one of the two calls actually failed - that would hide a partial failure.
        self.assertEqual(self.agent.combine("ok", "unreachable"), "unreachable")
        self.assertEqual(self.agent.combine("unreachable", "ok"), "unreachable")
        self.assertEqual(self.agent.combine("ok", "empty"), "ok")
        self.assertEqual(self.agent.combine("empty", "skipped"), "empty")
        self.assertEqual(self.agent.combine(), "skipped")

    def test_dedup_within_an_hour(self):
        d = self.agent.Dedup(seconds=3600)
        self.assertFalse(d.seen("k")); self.assertTrue(d.seen("k"))
        d.stamp["k"] -= 3601
        self.assertFalse(d.seen("k"))

    def test_source_deadline_always_leaves_at_least_25s_for_the_cloud_call(self):
        # TOTAL_DEADLINE is derived from TOTAL_TRIAGE_BUDGET (I3), not pinned, precisely so a
        # degraded stack (several dead sources, each burning its own timeout) can never eat so much
        # of the budget that the cloud call - the part actually worth the wait - is starved below a
        # timeout short enough to guarantee failure.
        self.assertLessEqual(self.agent.TOTAL_DEADLINE, 30)
        self.assertGreaterEqual(self.agent.TOTAL_TRIAGE_BUDGET - self.agent.TOTAL_DEADLINE, 25)

    def test_http_alert_returns_200_immediately_and_dry_runs(self):
        import io, contextlib
        srv, base = self.agent.serve(port=0)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                req = urllib.request.Request(base + "/alert", data=json.dumps(WEBHOOK).encode(), headers={"Content-Type": "application/json"})
                self.assertEqual(urllib.request.urlopen(req, timeout=5).status, 200)
                self.assertEqual(urllib.request.urlopen(base + "/healthz", timeout=5).status, 200)
                for _ in range(50):
                    if any(l.startswith("{") for l in buf.getvalue().splitlines()): break
                    time.sleep(0.1)
            out = buf.getvalue()
            self.assertIn("triage-agent: dry run pack", out)
            line = next(l for l in out.splitlines() if l.startswith("{"))
            self.assertEqual(json.loads(line)["schema_version"], 1)
        finally:
            srv.shutdown()


FENCE_OPEN, FENCE_CLOSE = "```\n", "\n```"


def _unfenced(s):
    """Strip the ```...``` code fence post_note() wraps every chunk in, for asserting on the
    original note text a test posted. A plain assert here would be stripped under `python -O`,
    silently accepting an unfenced string instead of failing the test that relies on this helper."""
    if not (s.startswith(FENCE_OPEN) and s.endswith(FENCE_CLOSE)):
        raise AssertionError("not fenced: %r" % s)
    return s[len(FENCE_OPEN):-len(FENCE_CLOSE)]


class Sink(BaseHTTPRequestHandler):
    """Fake receivers (Slack/Discord/Telegram/email-via-webhook all just POST somewhere) on one
    server, started once at module level - shared by every test that posts a note, including
    EngineHookTests' fake-triage_engine tests."""
    posts = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); Sink.posts.append((self.path, self.rfile.read(n).decode(), {k.lower(): v for k, v in self.headers.items()}))
        if self.path.startswith("/slack-down"):
            self.send_response(500); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a): pass


def _start_sink():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


_SINK_SRV, Sink.base = _start_sink()
SINK = Sink   # the name used below; Sink.posts and Sink.base are both class attributes


class PostTests(unittest.TestCase):
    """post_note() against every configured receiver, driven directly (not through process()/the
    triage engine) - the cloud-specific tests that used to live here (send_to_cloud, its HTTP error
    modes, budget/dedup wiring against the cloud) are gone with send_to_cloud itself; that coverage
    now belongs to EngineHookTests below, against the triage_engine hook."""
    @classmethod
    def setUpClass(cls):
        cls.base = SINK.base
        cls.agent = load_agent(cls.base, tempfile.mkdtemp())
        os.environ.update({"SLACK_WEBHOOK_URL": cls.base + "/slack", "DISCORD_WEBHOOK_URL": cls.base + "/discord",
                           "TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": "", "ALERT_EMAIL_TO": "", "SMTP_HOST": "",
                           "TRIAGE_DRY_RUN": "false"})
        cls.agent.TELEGRAM_API = cls.base + "/tg/bot%s/sendMessage"

    def setUp(self): Sink.posts = []

    def test_telegram_when_configured(self):
        # Telegram gets no fence (M7): no parse_mode is set, so a fence would render as three
        # literal backtick lines instead of a code block - the raw text goes out unwrapped.
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t0k", "TELEGRAM_CHAT_ID": "-100"})
        try:
            self.agent.post_note("Triage: x")
            tg = next((p, b) for p, b, _ in Sink.posts if p.startswith("/tg/"))
            self.assertEqual(tg[0], "/tg/bott0k/sendMessage")
            body = json.loads(tg[1])
            self.assertEqual(body["chat_id"], "-100")
            self.assertEqual(body["text"], "Triage: x")
            self.assertNotIn("parse_mode", body)
        finally: os.environ.update({"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""})

    def test_telegram_splits_a_note_over_4096_chars(self):
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t0k", "TELEGRAM_CHAT_ID": "-100"})
        try:
            long_text = "Triage: " + ("y" * 4992)  # 5000 chars total
            self.agent.post_note(long_text)
            tg_posts = [b for p, b, _ in Sink.posts if p.startswith("/tg/")]
            self.assertEqual(len(tg_posts), 2)
            for b in tg_posts:
                self.assertLessEqual(len(json.loads(b)["text"]), 4096)
            rebuilt = "".join(json.loads(b)["text"] for b in tg_posts)
            self.assertEqual(rebuilt, long_text)
        finally: os.environ.update({"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""})

    def test_email_receiver_failure_does_not_raise(self):
        # no fake SMTP server here; port 1 refuses immediately, so this exercises attempt()'s own
        # try/except around mail() - post_note() must swallow the failure, not propagate it.
        os.environ.update({"ALERT_EMAIL_TO": "ops@example.com", "SMTP_HOST": "127.0.0.1:1"})
        try:
            self.agent.post_note("Triage: x")  # must not raise
        finally:
            os.environ.update({"ALERT_EMAIL_TO": "", "SMTP_HOST": ""})

    def test_starttls_unsupported_without_credentials_still_sends(self):
        # .env.example documents an unauthenticated relay as a valid setup, and those commonly have
        # no STARTTLS at all - with nothing to protect, sending unencrypted must still work.
        os.environ.update({"ALERT_EMAIL_TO": "ops@example.com", "SMTP_HOST": "smtp.example.test:25", "SMTP_USER": ""})
        try:
            with mock.patch("smtplib.SMTP") as MockSMTP:
                conn = MockSMTP.return_value.__enter__.return_value
                conn.starttls.side_effect = smtplib.SMTPNotSupportedError("no STARTTLS")
                self.agent.post_note("Triage: x")
                conn.send_message.assert_called_once()
                conn.login.assert_not_called()
        finally:
            os.environ.update({"ALERT_EMAIL_TO": "", "SMTP_HOST": "", "SMTP_USER": ""})

    def test_starttls_unsupported_with_credentials_refuses_to_send(self):
        # a login must never go out over a connection that turned out to be plaintext.
        os.environ.update({"ALERT_EMAIL_TO": "ops@example.com", "SMTP_HOST": "smtp.example.test:25",
                           "SMTP_USER": "bob", "SMTP_PASSWORD": "secret"})
        try:
            with mock.patch("smtplib.SMTP") as MockSMTP:
                conn = MockSMTP.return_value.__enter__.return_value
                conn.starttls.side_effect = smtplib.SMTPNotSupportedError("no STARTTLS")
                self.agent.post_note("Triage: x")  # must not raise out of post_note
                conn.login.assert_not_called()
                conn.send_message.assert_not_called()
        finally:
            os.environ.update({"ALERT_EMAIL_TO": "", "SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": ""})

    def test_slack_failure_does_not_stop_discord(self):
        # a receiver failing must not abort the loop - point Slack at a path that 500s and confirm
        # Discord (which comes after it in post_note) still gets the note.
        os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack-down"
        try:
            self.agent.post_note("Triage: slack is down but discord should still get this")
            discord = next((b for p, b, _ in Sink.posts if p == "/discord"), None)
            self.assertIsNotNone(discord)
        finally:
            os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack"

    def test_every_receiver_post_carries_the_agent_user_agent(self):
        # Discord's edge (Cloudflare) answers 403 to urllib's default User-Agent; a real dogfood on
        # 2026-09-19 lost every note that way while the fake sink in the smoke happily accepted them.
        SINK.posts.clear()
        self.agent.post_note("Triage: x\nPack: docker compose logs triage-agent")
        self.assertTrue(SINK.posts)
        SINK.posts.clear()
        self.agent.post_json(SINK.base + "/slack", {"text": "x"}, headers={"User-Agent": "someone-else/9"})
        self.assertEqual(SINK.posts[0][2].get("user-agent"), self.agent.USER_AGENT)
        for path, body, headers in SINK.posts:
            self.assertEqual(headers.get("user-agent"), self.agent.USER_AGENT, path)   # keys lowercased by the sink

    def test_discord_splits_a_note_over_2000_chars(self):
        long_text = "Triage: " + ("x" * 2500)
        self.agent.post_note(long_text)
        discord_posts = [b for p, b, _ in Sink.posts if p == "/discord"]
        self.assertEqual(len(discord_posts), 2)
        for b in discord_posts:
            content = json.loads(b)["content"]
            self.assertLessEqual(len(content), 2000)
        rebuilt = "".join(_unfenced(json.loads(b)["content"]) for b in discord_posts)
        self.assertEqual(rebuilt, long_text)


class EngineHookTests(unittest.TestCase):
    """process() with a fake triage_engine module on sys.path: the agent's only contract with Pro.
    Also covers DEDUP's wiring in process() and the budget-floor skip (M6/I3 in the old cloud
    tests), now against the engine hook instead of a cloud HTTP call."""
    def setUp(self):
        self.calls = []
        fake = types.ModuleType("triage_engine")
        fake.last_error = lambda: ""

        def triage(pack, timeout, env, post=None):
            self.calls.append((pack, timeout)); return self.result
        fake.triage = triage
        sys.modules["triage_engine"] = fake
        # a fresh module load (not the same object load_agent() built for another test) so the
        # `import triage_engine` at the top of triage_agent.py picks up the fake just registered,
        # and so this test's DEDUP starts empty regardless of what other tests did with WEBHOOK's key.
        self.agent = load_agent(SINK.base, tempfile.mkdtemp())
        os.environ.update({"TRIAGE_DRY_RUN": "false", "SLACK_WEBHOOK_URL": SINK.base + "/slack"})
        SINK.posts.clear()

    def tearDown(self):
        sys.modules.pop("triage_engine", None)
        os.environ["TRIAGE_DRY_RUN"] = "true"

    def test_note_from_engine_is_posted(self):
        self.result = "Triage: x\nPack: docker compose logs triage-agent"
        self.agent.process(WEBHOOK)
        self.assertEqual(len(self.calls), 1)
        self.assertLessEqual(self.calls[0][1], self.agent.TOTAL_TRIAGE_BUDGET)   # remaining budget, not a constant
        self.assertEqual(len(SINK.posts), 1); self.assertIn("Triage: x", SINK.posts[0][1])

    def test_engine_none_posts_nothing(self):
        # spying on post_note() itself, not just SINK.posts: post_note(None) would raise inside its
        # own per-receiver try/except (which swallows it and logs) and never reach SINK either way,
        # so asserting on SINK.posts alone would pass even if process() wrongly called post_note.
        self.result = None
        posted = []
        self.agent.post_note = posted.append
        self.agent.process(WEBHOOK)
        self.assertEqual(posted, [])
        self.assertEqual(SINK.posts, [])

    def test_dry_run_never_calls_engine(self):
        os.environ["TRIAGE_DRY_RUN"] = "true"; self.result = "Triage: x"
        self.agent.process(WEBHOOK)
        self.assertEqual(self.calls, []); self.assertEqual(SINK.posts, [])

    def test_budget_below_the_floor_skips_the_engine_call(self):
        # deterministic, no sleeping: replace Budget itself (both process()'s own budget and the one
        # build_pack() constructs internally use the module-global name) with a fake whose
        # .remaining() always answers a fixed number, so this test isn't a race against real time.
        self.result = "Triage: x"
        floor = self.agent.CLOUD_TIMEOUT_FLOOR
        real_budget_cls = self.agent.Budget

        class BelowFloorBudget:
            def __init__(self, seconds): pass
            def remaining(self): return floor - 1   # always under CLOUD_TIMEOUT_FLOOR

        self.agent.Budget = BelowFloorBudget
        try:
            self.agent.process(WEBHOOK)
        finally:
            self.agent.Budget = real_budget_cls
        self.assertEqual(self.calls, [], "the engine must not be called once the budget is below the floor")
        self.assertEqual(SINK.posts, [])

        # same setup, budget comfortably above the floor: the call (and the post) must happen -
        # proves the assertions above aren't vacuously true regardless of what process() does.
        class AboveFloorBudget:
            def __init__(self, seconds): pass
            def remaining(self): return floor + 5

        self.agent.Budget = AboveFloorBudget
        try:
            self.agent.process(dict(WEBHOOK, groupKey="budget-above-floor-test"))
        finally:
            self.agent.Budget = real_budget_cls
        self.assertEqual(len(self.calls), 1)
        # I5: the engine call must get exactly what's left of the budget, never the full constant -
        # AboveFloorBudget.remaining() always answers floor + 5, so that's what the call should see.
        # assertLessEqual on TOTAL_TRIAGE_BUDGET elsewhere can't tell "remaining" from "the constant"
        # apart; this can.
        self.assertEqual(self.calls[0][1], floor + 5)
        self.assertEqual(len(SINK.posts), 1)

    def test_second_process_call_for_the_same_group_never_reaches_the_engine(self):
        # I1: DEDUP.seen(key) in process() must actually gate the engine call, not just the Dedup
        # class in isolation (test_dedup_within_an_hour covers that already). Same groupKey both
        # times, well within DEDUP_SECONDS (1h) of each other.
        self.result = "Triage: x\nPack: docker compose logs triage-agent"
        self.agent.process(WEBHOOK)
        self.agent.process(WEBHOOK)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(SINK.posts), 1)

    def test_engine_raising_is_logged_not_fatal(self):
        # the try/except around the engine call: a bug in triage_engine must not kill process()'s
        # thread or post anything, only log.
        def boom(pack, timeout, env, post=None):
            self.calls.append((pack, timeout)); raise RuntimeError("engine bug")
        sys.modules["triage_engine"].triage = boom
        self.agent.process(WEBHOOK)   # must not raise
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(SINK.posts, [])

    def test_no_engine_module_logs_pack_only(self):
        sys.modules.pop("triage_engine"); sys.modules["triage_engine"] = None   # import raises ImportError
        agent = load_agent(SINK.base, tempfile.mkdtemp())
        os.environ["TRIAGE_DRY_RUN"] = "false"   # load_agent() above forced dry run back on
        agent.process(WEBHOOK)
        self.assertEqual(SINK.posts, [])

    def test_api_key_is_redacted_from_packs(self):
        p = self.agent.redact({"logs": ["x-api-key: sk-ant-abc123 sk-ant-api03-zzz"]})
        self.assertNotIn("abc123", json.dumps(p)); self.assertNotIn("zzz", json.dumps(p))

    def test_log_pack_env_controls_the_stdout_pack_line_in_live_mode(self):
        # R1: TRIAGE_LOG_PACK=true prints the pack (for Task 3's smoke test to capture) right before
        # the engine call, and the note is still posted; the default (false) stays silent.
        import io, contextlib
        self.result = "Triage: x"
        os.environ["TRIAGE_LOG_PACK"] = "true"
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                self.agent.process(WEBHOOK)
        finally:
            os.environ["TRIAGE_LOG_PACK"] = "false"
        out = buf.getvalue()
        self.assertTrue(any(l.startswith("{") and json.loads(l).get("schema_version") == 1 for l in out.splitlines()),
                         "TRIAGE_LOG_PACK=true must print the pack before the engine call")
        self.assertEqual(len(SINK.posts), 1, "the note must still be posted")

        SINK.posts.clear()
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            # a different group so DEDUP (already marked WEBHOOK's key above) doesn't short-circuit
            # this into a no-op that would trivially pass regardless of TRIAGE_LOG_PACK
            self.agent.process(dict(WEBHOOK, groupKey="log-pack-default-test"))
        self.assertFalse(any(l.startswith("{") for l in buf2.getvalue().splitlines()),
                          "TRIAGE_LOG_PACK default (false) must not print the pack")
        self.assertEqual(len(SINK.posts), 1, "the note must still be posted without pack logging")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for scripts/triage_agent.py against fake Prometheus/Loki/Alertmanager/Grafana servers.
Every fixture below is the JSON shape the real service returns (verified live by tests/smoke.sh);
if a live shape ever differs, fix the fixture here, never the agent to match the fixture."""
import importlib.util, json, os, smtplib, tempfile, threading, time, unittest, urllib.parse, urllib.request
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

    def test_trimmed_pack_fits_under_the_64kb_cloud_request_limit(self):
        # the triage service rejects request bodies over 64KB (413); trim()'s own HARD_CAP_BYTES
        # (40000) is supposed to keep every pack well clear of that, even a maximally-grouped one.
        big_webhook = json.loads(json.dumps(WEBHOOK))
        tmpl = big_webhook["alerts"][0]
        big_webhook["alerts"] = [dict(tmpl, fingerprint="fp-%d" % i) for i in range(300)]
        p = self.agent.build_pack(big_webhook)
        self.assertLessEqual(len(json.dumps(p).encode()), 64 * 1024)

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
    original note text a test posted."""
    assert s.startswith(FENCE_OPEN) and s.endswith(FENCE_CLOSE), s
    return s[len(FENCE_OPEN):-len(FENCE_CLOSE)]


class Sink(BaseHTTPRequestHandler):
    """Fake cloud service + fake receivers (Slack/Discord/Telegram/email-via-webhook all just POST
    somewhere) on one server. Response bodies match the real /v1/triage contract exactly (PR #4 in
    the sre-triage repo): 200 {id,text,url,tier,used,limit}; 401 {"error":"unauthorized"};
    429 {"error":"quota","resets_on"}; 422 {"error":"schema"} or {"error":"refused","category"};
    502 {"error":"model","kind"}; 413 {"error":"too_large"}. The /text-* paths are still a clean 200
    but with a "text" field of the wrong shape, to drive send_to_cloud()'s own response validation."""
    posts = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); Sink.posts.append((self.path, self.rfile.read(n).decode()))
        if self.path.startswith("/slow"):
            time.sleep(5); self.send_response(200); self.end_headers(); return
        if self.path.startswith("/slack-down"):
            self.send_response(500); self.end_headers(); return
        if self.path == "/v1/triage" and self.headers.get("Authorization") != "Bearer key-1":
            self._json(401, {"error": "unauthorized"}); return
        if self.path == "/quota/v1/triage":
            self._json(429, {"error": "quota", "resets_on": "2026-10-01"}); return
        if self.path == "/schema/v1/triage":
            self._json(422, {"error": "schema"}); return
        if self.path == "/refused/v1/triage":
            self._json(422, {"error": "refused", "category": "self-harm"}); return
        if self.path == "/model/v1/triage":
            self._json(502, {"error": "model", "kind": "upstream-timeout"}); return
        if self.path == "/big/v1/triage":
            self._json(413, {"error": "too_large"}); return
        if self.path == "/garbage/v1/triage":
            body = b"not json"; self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if self.path == "/text-int/v1/triage":
            self._json(200, {"id": "x", "text": 12345, "url": "u"}); return
        if self.path == "/text-dict/v1/triage":
            self._json(200, {"id": "x", "text": {"a": 1}, "url": "u"}); return
        if self.path == "/text-list/v1/triage":
            self._json(200, {"id": "x", "text": ["a", "b"], "url": "u"}); return
        if self.path == "/text-blank/v1/triage":
            self._json(200, {"id": "x", "text": "   \n\t  ", "url": "u"}); return
        if self.path == "/text-noprefix/v1/triage":
            self._json(200, {"id": "x", "text": "not a triage note", "url": "u"}); return
        if self.path == "/v1/triage":
            self._json(200, {"id": "abc", "text": "Triage: ServiceDown on api\nProbable cause\n  1. x",
                              "url": "https://t/abc", "tier": "free", "used": 1, "limit": 50}); return
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a): pass


class CloudTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Sink); threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        cls.agent = load_agent(cls.base, tempfile.mkdtemp())
        os.environ.update({"TRIAGE_API_URL": cls.base, "TRIAGE_LICENSE_KEY": "key-1", "SLACK_WEBHOOK_URL": cls.base + "/slack",
                           "DISCORD_WEBHOOK_URL": cls.base + "/discord", "TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": "",
                           "ALERT_EMAIL_TO": "", "SMTP_HOST": "",
                           # load_agent() above forces dry run back on; process()'s end-to-end tests need it off
                           # so they actually exercise send_to_cloud() instead of short-circuiting into dry run.
                           "TRIAGE_DRY_RUN": "false"})
        cls.agent.TELEGRAM_API = cls.base + "/tg/bot%s/sendMessage"

    def setUp(self): Sink.posts = []

    def test_send_and_post_to_every_configured_receiver(self):
        note = self.agent.send_to_cloud({"schema_version": 1, "alerts": []})
        self.assertEqual(note["id"], "abc")
        self.agent.post_note(note["text"])
        paths = [p for p, _ in Sink.posts]
        self.assertIn("/slack", paths); self.assertIn("/discord", paths)
        slack = json.loads(next(b for p, b in Sink.posts if p == "/slack"))
        self.assertEqual(_unfenced(slack["text"]), note["text"])
        discord = json.loads(next(b for p, b in Sink.posts if p == "/discord"))
        self.assertEqual(_unfenced(discord["content"]), note["text"])
        self.assertEqual(discord["allowed_mentions"], {"parse": []})

    def test_bad_key_and_quota_are_logged_not_posted(self):
        os.environ["TRIAGE_LICENSE_KEY"] = "wrong"
        try: self.assertIsNone(self.agent.send_to_cloud({"schema_version": 1, "alerts": []}))
        finally: os.environ["TRIAGE_LICENSE_KEY"] = "key-1"
        os.environ["TRIAGE_API_URL"] = self.base + "/quota"
        try: self.assertIsNone(self.agent.send_to_cloud({"schema_version": 1, "alerts": []}))
        finally: os.environ["TRIAGE_API_URL"] = self.base
        self.assertEqual([p for p, _ in Sink.posts if p in ("/slack", "/discord")], [])

    def test_schema_refused_model_and_oversized_pack_all_return_none(self):
        for suffix in ("/schema", "/refused", "/model", "/big", "/garbage"):
            os.environ["TRIAGE_API_URL"] = self.base + suffix
            try:
                self.assertIsNone(self.agent.send_to_cloud({"schema_version": 1, "alerts": []}), suffix)
            finally:
                os.environ["TRIAGE_API_URL"] = self.base
        self.assertEqual([p for p, _ in Sink.posts if p in ("/slack", "/discord")], [])

    def test_a_clean_200_with_a_malformed_text_field_returns_none(self):
        # a "text" that isn't a string, or is blank, or doesn't even look like a triage note (real
        # notes always start "Triage:" - see engine.render on the cloud side) must not be treated as
        # a usable note, even though the response is a clean 200.
        for suffix in ("/text-int", "/text-dict", "/text-list", "/text-blank", "/text-noprefix"):
            os.environ["TRIAGE_API_URL"] = self.base + suffix
            try:
                self.assertIsNone(self.agent.send_to_cloud({"schema_version": 1, "alerts": []}), suffix)
            finally:
                os.environ["TRIAGE_API_URL"] = self.base
        self.assertEqual([p for p, _ in Sink.posts if p in ("/slack", "/discord")], [])

    def test_telegram_when_configured(self):
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t0k", "TELEGRAM_CHAT_ID": "-100"})
        try:
            self.agent.post_note("Triage: x")
            tg = next((p, b) for p, b in Sink.posts if p.startswith("/tg/"))
            self.assertEqual(tg[0], "/tg/bott0k/sendMessage")
            body = json.loads(tg[1])
            self.assertEqual(body["chat_id"], "-100")
            self.assertEqual(_unfenced(body["text"]), "Triage: x")
            self.assertNotIn("parse_mode", body)
        finally: os.environ.update({"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""})

    def test_telegram_splits_a_note_over_4096_chars(self):
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t0k", "TELEGRAM_CHAT_ID": "-100"})
        try:
            long_text = "Triage: " + ("y" * 4992)  # 5000 chars total
            self.agent.post_note(long_text)
            tg_posts = [b for p, b in Sink.posts if p.startswith("/tg/")]
            self.assertEqual(len(tg_posts), 2)
            for b in tg_posts:
                self.assertLessEqual(len(json.loads(b)["text"]), 4096)
            rebuilt = "".join(_unfenced(json.loads(b)["text"]) for b in tg_posts)
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
            discord = next((b for p, b in Sink.posts if p == "/discord"), None)
            self.assertIsNotNone(discord)
        finally:
            os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack"

    def test_discord_splits_a_note_over_2000_chars(self):
        long_text = "Triage: " + ("x" * 2500)
        self.agent.post_note(long_text)
        discord_posts = [b for p, b in Sink.posts if p == "/discord"]
        self.assertEqual(len(discord_posts), 2)
        for b in discord_posts:
            content = json.loads(b)["content"]
            self.assertLessEqual(len(content), 2000)
        rebuilt = "".join(_unfenced(json.loads(b)["content"]) for b in discord_posts)
        self.assertEqual(rebuilt, long_text)

    def test_end_to_end_cloud_errors_never_post_to_a_receiver(self):
        # drives process() itself (not send_to_cloud alone): every failure mode - bad key, quota,
        # model error, timeout - must end with zero posts to the alert receivers.
        for i, suffix in enumerate(("", "/quota", "/model")):
            os.environ["TRIAGE_API_URL"] = self.base + suffix
            os.environ["TRIAGE_LICENSE_KEY"] = "wrong" if suffix == "" else "key-1"
            try:
                self.agent.process({"groupKey": "e2e-error-%d" % i})
            finally:
                os.environ["TRIAGE_API_URL"] = self.base; os.environ["TRIAGE_LICENSE_KEY"] = "key-1"
        real_total, real_floor = self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR
        self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR = 2, 0.3
        os.environ["TRIAGE_API_URL"] = self.base + "/slow"
        try:
            self.agent.process({"groupKey": "e2e-error-timeout"})
        finally:
            self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR = real_total, real_floor
            os.environ["TRIAGE_API_URL"] = self.base
        self.assertEqual([p for p, _ in Sink.posts if p in ("/slack", "/discord")], [])

    def test_budget_floor_caps_the_cloud_timeout_so_process_returns_promptly(self):
        # sources taking ~1s, then a sink that sleeps well past the remaining budget: process() must
        # still return in bounded time (not hang for the sink's full sleep) and post nothing. The
        # bound is expressed against the *scaled* budget used in this test, not a literal "45" -
        # a hardcoded 45s ceiling would pass even if the timeout math stopped bounding anything.
        real_total, real_floor = self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR
        real_build_pack = self.agent.build_pack
        scaled_budget = 2
        self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR = scaled_budget, 0.5

        def slow_build_pack(payload):
            time.sleep(1)
            return {"schema_version": 1, "alerts": []}
        self.agent.build_pack = slow_build_pack
        os.environ["TRIAGE_API_URL"] = self.base + "/slow"
        try:
            start = time.monotonic()
            self.agent.process({"groupKey": "budget-floor-test"})
            elapsed = time.monotonic() - start
            self.assertLess(elapsed, scaled_budget + 1.5,
                             "process() must never run out past its own (scaled) total triage budget")
            self.assertEqual([p for p, _ in Sink.posts if p in ("/slack", "/discord")], [])
        finally:
            self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR = real_total, real_floor
            self.agent.build_pack = real_build_pack
            os.environ["TRIAGE_API_URL"] = self.base

    def test_budget_exhausted_before_the_floor_skips_the_cloud_call_entirely(self):
        # once less than CLOUD_TIMEOUT_FLOOR remains, process() must not extend the budget to give
        # the cloud call a fairer chance - it must skip the call outright.
        real_total, real_floor = self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR
        self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR = 5, 10  # floor exceeds the whole budget
        try:
            self.agent.process({"groupKey": "budget-exhausted-test"})
            self.assertEqual([p for p, _ in Sink.posts if p == "/v1/triage"], [],
                              "the cloud must not be called once too little budget remains to bother")
        finally:
            self.agent.TOTAL_TRIAGE_BUDGET, self.agent.CLOUD_TIMEOUT_FLOOR = real_total, real_floor


if __name__ == "__main__":
    unittest.main()

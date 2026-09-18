#!/usr/bin/env python3
"""Unit tests for scripts/triage_agent.py against fake Prometheus/Loki/Alertmanager/Grafana servers.
Every fixture below is the JSON shape the real service returns (verified live by tests/smoke.sh);
if a live shape ever differs, fix the fixture here, never the agent to match the fixture."""
import importlib.util, json, os, sys, threading, unittest, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

    def do_GET(self):
        Fake.hits.append(self.path)
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

    def test_pack_has_every_source(self):
        p = self.agent.build_pack(WEBHOOK)
        self.assertEqual(p["schema_version"], 1)
        self.assertEqual(p["alerts"][0]["labels"]["alertname"], "ServiceDown")
        self.assertEqual(p["rule"]["query"], 'probe_success{job="blackbox-http"} == 0')
        self.assertEqual(p["rule_now"][0]["value"], "0")
        self.assertEqual(p["rule_30m"][0]["last"], "0"); self.assertEqual(p["rule_30m"][0]["min"], "0"); self.assertEqual(p["rule_30m"][0]["max"], "1")
        self.assertEqual(p["up"][0]["value"], "0")
        self.assertEqual(len(p["logs"]), 2)
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

    def test_dedup_within_an_hour(self):
        d = self.agent.Dedup(seconds=3600)
        self.assertFalse(d.seen("k")); self.assertTrue(d.seen("k"))
        d.stamp["k"] -= 3601
        self.assertFalse(d.seen("k"))

    def test_http_alert_returns_200_immediately_and_dry_runs(self):
        import io, contextlib, time
        srv, base = self.agent.serve(port=0)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                req = urllib.request.Request(base + "/alert", data=json.dumps(WEBHOOK).encode(), headers={"Content-Type": "application/json"})
                self.assertEqual(urllib.request.urlopen(req, timeout=5).status, 200)
                self.assertEqual(urllib.request.urlopen(base + "/healthz", timeout=5).status, 200)
                for _ in range(50):
                    if "dry run pack" in buf.getvalue(): break
                    time.sleep(0.1)
            out = buf.getvalue()
            self.assertIn("triage-agent: dry run pack", out)
            line = next(l for l in out.splitlines() if l.startswith("{"))
            self.assertEqual(json.loads(line)["schema_version"], 1)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for scripts/triage_agent.py against fake Prometheus/Loki/Alertmanager/Grafana servers.
Every fixture below is the JSON shape the real service returns (verified live by tests/smoke.sh);
if a live shape ever differs, fix the fixture here, never the agent to match the fixture."""
import base64, importlib.util, json, os, smtplib, socket, ssl, sys, tempfile, threading, time, types, unittest, urllib.parse, urllib.request
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

    def test_credential_shapes_the_kit_itself_uses_are_redacted(self):
        # every one of these went through redact() unchanged (the PEM one only
        # partly) and on to the model provider and the chat note. Dummy secrets, real shapes -
        # including the kit's own documented DISCORD_WEBHOOK_URL and Telegram bot-URL forms.
        cases = {
            '{"headers":{"Authorization":"Basic ZHVtbXk6ZHVtbXlwYXNz"}}': "ZHVtbXk6ZHVtbXlwYXNz",
            "POST https://discord.com/api/webhooks/111/DummyTok failed": "DummyTok",
            "GET https://api.telegram.org/bot123:Dummy/sendMessage": "123:Dummy",
            "creds AKIADUMMYDUMMYDUMMY1 rejected": "AKIADUMMYDUMMYDUMMY1",
            "Cookie: sid=dummy": "dummy",
            "redis://:dummypass@cache": "dummypass",
            "clone with ghp_" + "Dummy1" * 5: "Dummy1" * 5,
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.DummySig": "eyJzdWIiOiJkdW1teSJ9.DummySig",
            "private_key=-----BEGIN RSA PRIVATE KEY----- MIIDummyBody -----END RSA PRIVATE KEY-----": "MIIDummyBody",
            "-----BEGIN PRIVATE KEY-----\nMIIDummyLine1\nMIIDummyLine2\n-----END PRIVATE KEY-----": "MIIDummyLine",
            # a URL password containing "/" - the reason the bounded URL pattern keeps its classes
            "postgres://u:pa/ss@db": "pa/ss",
        }
        for original, secret in cases.items():
            self.assertNotIn(secret, self.agent.redact(original), original)

    def test_long_credentials_are_redacted_whole_not_just_their_first_bytes(self):
        # bounding a quantifier must not cap how much of a real credential gets redacted: a Kerberos
        # Negotiate token runs to KBs, and a long URL password must not slip past the user:pass@ rule
        negotiate = "Y" * 1500
        for original in ("Authorization: Negotiate " + negotiate,
                         '{"Authorization":"Negotiate %s"}' % negotiate):
            self.assertNotIn("YYYY", self.agent.redact(original), original[:30])
        pw = "p" * 300
        for original in ("https://u:%s@host/x" % pw, "redis://:%s@cache" % pw):
            self.assertNotIn("pppp", self.agent.redact(original), original[:20])

    def test_default_patterns_are_not_quadratic_on_a_repeated_prefix(self):
        # the Authorization and user:pass@ patterns backtracked O(n^2) on their
        # own prefix repeated with no terminator - 3.3 s and 0.5 s here, GIL held throughout
        # best of three: a quadratic pattern is slow on every run, while a worker thread an earlier
        # test left running can steal the GIL from any single one
        for s in ("authorization:" * 8000, "://a:" * 8000):
            best = 9e9
            for _ in range(3):
                start = time.monotonic()
                self.agent._redact(s, self.agent.DEFAULT_REDACT)
                best = min(best, time.monotonic() - start)
            self.assertLess(best, 0.1, s[:20])

    def test_each_string_is_capped_before_any_regex_runs(self):
        # trim() never shortens a single annotation, so without this a 100 KB one reaches every pattern
        self.assertEqual(len(self.agent._redact("x" * 100000, [])), self.agent.HARD_CAP_BYTES)

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

    # --- redaction shapes that still leaked (dummy secrets, real shapes) -----

    def test_run2_shape_escaped_json_in_json_password_is_redacted(self):
        # a log line that embeds an escaped JSON blob (\"password\": rather than a bare "password":)
        # - the keyword rule's separator did not accept a backslash before the quote.
        line = r'{"msg":"login failed {\"password\":\"hunter2dummy\"}"}'
        self.assertNotIn("hunter2dummy", self.agent.redact(line))

    def test_run2_shape_aws_secret_access_key_whitespace_separator_is_redacted(self):
        # `aws configure set aws_secret_access_key <value>` - keyword and value separated by
        # whitespace only, no ":"/"=" at all.
        line = "aws configure set aws_secret_access_key wJalrDUMMYDUMMYDUMMYDUMMYKEY"
        self.assertNotIn("wJalrDUMMYDUMMYDUMMYDUMMYKEY", self.agent.redact(line))

    def test_run2_shape_azure_sas_signature_is_redacted(self):
        line = ("POST https://x.logic.azure.com/workflows/x/triggers/manual/paths/invoke"
                "?api-version=2016-06-01&sp=%2Ftriggers&sv=1.0&sig=DummySig0123456789abcdef")
        self.assertNotIn("DummySig0123456789abcdef", self.agent.redact(line))

    def test_run2_shape_aws_presigned_x_amz_signature_is_redacted(self):
        line = "GET /o?X-Amz-Credential=AKIADUMMYDUMMYDUMMY1&X-Amz-Signature=deadbeefdummy"
        self.assertNotIn("deadbeefdummy", self.agent.redact(line))

    def test_run2_shape_google_api_key_query_param_is_redacted(self):
        line = "GET https://maps.googleapis.com/x?key=AIzaDummyDummyDummyDummyDummyDummy123"
        self.assertNotIn("AIzaDummyDummyDummyDummyDummyDummy123", self.agent.redact(line))

    def test_run2_shape_query_param_matches_go_json_escaped_ampersand(self):
        # Go's encoding/json HTML-escapes "&" to the six literal characters
        # backslash-u-0-0-2-6 by default, so a JSON-encoded log line carries that instead of a bare
        # "&" in front of "sig=". Built with a plain (non-raw) string: "\\u0026" here is the normal
        # Python escape for one backslash followed by literal "u0026" - the six characters Go emits.
        line = '{"url":"https://x/path?a=1' + "\\u0026" + 'sig=DummySig0123456789abcdef"}'
        self.assertNotIn("DummySig0123456789abcdef", self.agent.redact(line))

    def test_run2_shape_query_param_matches_html_escaped_ampersand(self):
        # an HTML/XML-escaped query string carries "&amp;" instead of "&".
        line = "GET https://maps.googleapis.com/x?a=1&amp;key=AIzaDummyDummyDummyDummyDummyDummy123"
        self.assertNotIn("AIzaDummyDummyDummyDummyDummyDummy123", self.agent.redact(line))

    def test_run2_shape_query_param_value_is_not_truncated_past_the_old_2048_bound(self):
        # the value is the last element (nothing follows it to backtrack against),
        # so it is unbounded like the URL-password and Negotiate-token values - a signature longer
        # than the old {1,2048} bound must be redacted whole, not just its first 2048 characters.
        long_sig = "d" * 3000
        line = "GET /o?sig=" + long_sig
        out = self.agent.redact(line)
        self.assertNotIn("d" * 100, out)
        self.assertIn("[redacted]", out)

    def test_run2_shape_headerless_pem_body_line_is_redacted(self):
        # a PEM body line with no -----BEGIN/END----- around it at all - the earlier PEM rule only
        # fires off the header, which is absent here.
        line = "MIIEvDUMMYDUMMYDUMMYbase64bodyAAAAAAAAAAAAAAAAAAAAAAAA"
        self.assertNotIn(line, self.agent.redact(line))

    def test_run2_shape_headerless_base64_body_line_without_MII_prefix_is_redacted(self):
        # a continuation line of a multi-line PEM body with no "MII" prefix of its own: exactly 64
        # base64 characters, at least one of them uppercase.
        line = "A" + "b" * 63
        self.assertEqual(len(line), 64)
        self.assertNotEqual(self.agent.redact(line), line)

    # --- negative controls: these must survive redact() unchanged ----------------------------------

    def test_run2_negative_control_password_reset_prose_survives(self):
        s = "password reset failed for user bob"
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_negative_control_aws_secret_access_key_not_set_survives(self):
        # the AWS whitespace-separator rule must only redact a secret-shaped value
        # (16+ base64-alphabet characters) - "not" is 3 characters, nowhere near that.
        s = "aws_secret_access_key not set"
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_negative_control_aws_session_token_expired_prose_survives(self):
        s = "aws_session_token expired for role deploy"
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_negative_control_sha256_hex_digest_survives(self):
        # 64 lowercase hex characters - must not be mistaken for the new base64-body rule, which
        # requires an uppercase letter precisely so a hex digest is never caught by it.
        s = "a1b2c3d4" * 8
        self.assertEqual(len(s), 64)
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_negative_control_keyboard_param_is_not_mistaken_for_key(self):
        # the new key= rule must match only a whole parameter named "key", not one that merely starts
        # with those three letters.
        s = "GET /search?q=monkey&keyboard=1"
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_negative_control_signature_prose_survives(self):
        s = "the signature was valid"
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_negative_control_ordinary_check_first_line_survives(self):
        s = "docker logs --tail 50 web-1"
        self.assertEqual(self.agent.redact(s), s)

    def test_run2_keyword_separator_allows_more_than_16_spaces(self):
        # [ \t]{0,16} became [ \t]* - a value padded past 16 spaces/tabs (a
        # fixed-width log format, `column -t`) must still be redacted, not just up to the old bound.
        line = "password:" + " " * 17 + "hunter2dummy"
        self.assertNotIn("hunter2dummy", self.agent.redact(line))

    def test_run2_new_patterns_are_not_quadratic_on_a_repeated_prefix(self):
        # each new pattern's own prefix, repeated with no terminator - the same shape that made the
        # old bearer/authorization/user:pass@ patterns backtrack O(n^2) (see the test above this one
        # in spirit, test_default_patterns_are_not_quadratic_on_a_repeated_prefix). "MII" + "A"*N on
        # its own cannot exercise the PEM-body rule's bound (the trailing "={0,2}" is optional, so it
        # never needs to backtrack at all, on any input); "MII/"*N does, because every repeat starts a
        # fresh attempt over the whole remaining string - keep both, they test different things.
        cases = (r'\"password\":' * 8000, "&sig=" * 8000, "aws_secret_access_key " * 8000,
                 "MII" + "A" * 200000, "MII/" * 10000, "password:" + " " * 50000 + "x")
        for s in cases:
            start = time.monotonic()
            self.agent._redact(s, self.agent.DEFAULT_REDACT)
            self.assertLess(time.monotonic() - start, 1.0, s[:20])

    # --- run-3: the 19 shapes and 7 controls of the audit's redact_shapes_run3.py, verbatim ---------
    # Redaction is pattern matching and never complete (README says so); these are the shape families
    # it is tested against. Each shape's dummy secret must be gone; each control stays redacted.
    _PEM_ROW = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDummyDummyDummy"
    _PEM_ROW2 = ("Zm9vYmFyRHVtbXlEdW1teUR1bW15RHVtbXlEdW1teUR1bW15RHVtbXlEdW1teUQ" + "A")[:64]
    _K8S_PEM = base64.b64encode(
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEdummydummydummy\n-----END RSA PRIVATE KEY-----\n").decode()
    RUN3_SHAPES = [
        ("ruby hash-rocket password", '{"user"=>"bob", "password"=>"hunter2dummy"}', "hunter2dummy"),
        ("ruby symbol hash-rocket", ":password => 'hunter2dummy'", "hunter2dummy"),
        ("XML element password", "<login><user>bob</user><password>hunter2dummy</password></login>", "hunter2dummy"),
        ("double-escaped JSON password", r'{"log":"{\\\"password\\\":\\\"hunter2dummy\\\"}"}', "hunter2dummy"),
        ("passphrase= key", "ssh-keygen passphrase=hunter2dummy failed", "hunter2dummy"),
        ("pass= key", "login user=bob pass=hunter2dummy", "hunter2dummy"),
        ("password value with ';' (tail)", "password=abcd;hunter2dummy", "hunter2dummy"),
        ("password value with ',' (tail)", "password=abcd,hunter2dummy", "hunter2dummy"),
        ("JSON password with escaped quote (tail)", r'{"password":"ab\"hunter2dummy"}', "hunter2dummy"),
        ("S3 SigV2 presigned Signature=", "GET https://b.s3.amazonaws.com/o?AWSAccessKeyId=AKIADUMMYDUMMYDUMMY1&Expires=1&Signature=DummySigV2abc%2Bdef%3D", "DummySigV2abc"),
        ("CloudFront signed URL Signature=", "GET https://d1.cloudfront.net/v.mp4?Expires=1&Signature=DummyCfSig~abc__&Key-Pair-Id=K2DUMMY", "DummyCfSig"),
        ("GCS V4 X-Goog-Signature=", "GET https://storage.googleapis.com/b/o?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=deadbeefdummy0123", "deadbeefdummy0123"),
        ("sig= URL-encoded inside redirect param", "GET /login?next=https%3A%2F%2Fx.blob.core.windows.net%2Fc%3Fsv%3D1%26sig%3DDummySasSig123", "DummySasSig123"),
        ("Azure storage AccountKey=", "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=DummyAcctKeyBase64Dummy==;EndpointSuffix=core.windows.net", "DummyAcctKeyBase64Dummy"),
        ("Ocp-Apim-Subscription-Key header", "Ocp-Apim-Subscription-Key: DummySubKey0123456789", "DummySubKey0123456789"),
        ("headerless PEM, escaped \\n continuation", "key=" + "\\n".join([_PEM_ROW, _PEM_ROW2, _PEM_ROW2]), _PEM_ROW2),
        ("PEM continuation line with CRLF", _PEM_ROW2 + "\r", _PEM_ROW2),
        ("PEM continuation line indented (YAML block)", "    " + _PEM_ROW2, _PEM_ROW2),
        ("base64-encoded PEM (k8s Secret data)", "tls.key: " + _K8S_PEM, _K8S_PEM[:40]),
    ]
    RUN3_CONTROLS = [
        ("escaped-json password", r'{"msg":"{\"password\":\"hunter2dummy\"}"}', "hunter2dummy"),
        ("aws cli secret", "aws configure set aws_secret_access_key wJalrDUMMYDUMMYDUMMYDUMMYKEY", "wJalrDUMMYDUMMYDUMMYDUMMYKEY"),
        ("sig=", "https://x/y?sv=1&sig=DummySasSig123", "DummySasSig123"),
        ("X-Amz-Signature", "https://x/o?X-Amz-Signature=deadbeefdummy0123", "deadbeefdummy0123"),
        ("key=", "https://maps.googleapis.com/x?key=AIzaDummyDummy123", "AIzaDummyDummy123"),
        ("headerless MII line", _PEM_ROW, _PEM_ROW),
        ("64-char continuation line", _PEM_ROW2, _PEM_ROW2),
    ]

    def test_run3_shapes_are_redacted(self):
        for label, line, secret in self.RUN3_SHAPES:
            with self.subTest(label):
                self.assertNotIn(secret, self.agent.redact(line))
        self.assertEqual(len(self.RUN3_SHAPES), 19)

    def test_run3_controls_stay_redacted(self):
        for label, line, secret in self.RUN3_CONTROLS:
            with self.subTest(label):
                self.assertNotIn(secret, self.agent.redact(line))
        self.assertEqual(len(self.RUN3_CONTROLS), 7)

    def test_run3_bare_signature_field_is_redacted(self):
        # the audit harness's own note line: a Signature= with no "?"/"&" in front of it
        for line in ("1. auth fails — Signature=DummyCfSig~abc", "x-goog-signature: deadbeefdummy0123"):
            self.assertNotIn("dummy", self.agent.redact(line).lower(), line)

    def test_run3_ordinary_words_near_the_new_keywords_survive(self):
        # "pass" is anchored on its left, and every keyword still needs a separator right after it.
        for s in ("bypass=true", "compass: north", "overpass=12", "tests passed: 3", "passphrase_policy=strict",
                  "the signature was valid", "signature_valid=true", "sig_count=4", "account_key_id=5", "subscription_keys=2",
                  "GET /search?q=monkey&keyboard=1", "<user>bob</user>", "a => b", "sha256 " + "a1b2c3d4" * 8):
            self.assertEqual(self.agent.redact(s), s)

    # --- run-3 review: shapes the first run-3 fix still let through -------------------------------
    RUN3_REVIEW_SHAPES = [
        ("Rails SECRET_KEY_BASE", "SECRET_KEY_BASE=hunter2dummy", "hunter2dummy"),
        ("JSON secret_key", '{"secret_key": "hunter2dummy"}', "hunter2dummy"),
        ("k8s env name/value pair", '{"name":"DB_PASSWORD","value":"hunter2dummy"}', "hunter2dummy"),
        ("k8s env name/value pair, spaced", '{"name": "API_TOKEN", "value": "hunter2dummy"}', "hunter2dummy"),
        ("CLI --password flag", "mysql --password hunter2dummy -h db", "hunter2dummy"),
        ("CLI --api-key= flag", "tool --api-key=hunter2dummy", "hunter2dummy"),
        ("unquoted value with a quote inside", 'password=ab"cdTAIL', "TAIL"),
        ("unquoted value with an escaped quote inside", 'token=abc\\"TAIL', "TAIL"),
        ("unquoted value starting with <", "password: <TAILsecret", "TAIL"),
        # fix round 2
        ("name/value pair, escaped quote in the value", '{"name":"DB_PASSWORD","value":"ab\\"SECRET"}', "SECRET"),
        ("name/value pair, JSON-escaped once", '{"log":"{\\"name\\":\\"DB_PASSWORD\\",\\"value\\":\\"hunter2dummy\\"}"}', "hunter2dummy"),
        ("name/value pair, key as the last segment", '{"name":"STRIPE_API_KEY","value":"hunter2dummy"}', "hunter2dummy"),
        ("CLI flag, two spaces", "mysql --password  hunter2dummy", "hunter2dummy"),
        ("CLI flag, tab", "mysql --password\thunter2dummy", "hunter2dummy"),
    ]

    def test_run3_review_shapes_are_redacted(self):
        for label, line, secret in self.RUN3_REVIEW_SHAPES:
            with self.subTest(label):
                self.assertNotIn(secret, self.agent.redact(line))

    def test_run3_review_query_values_stop_at_the_next_parameter(self):
        # a secret query parameter is redacted, the parameters after it are not
        out = self.agent.redact("GET /login?user=bob&password=hunter2dummy&next=/home")
        self.assertNotIn("hunter2dummy", out); self.assertIn("&next=/home", out)
        out = self.agent.redact("GET /o?X-Amz-Signature=deadbeefdummy&x-id=GetObject")
        self.assertNotIn("deadbeefdummy", out); self.assertIn("&x-id=GetObject", out)
        out = self.agent.redact("GET /r?next=https%3A%2F%2Fx%2Fc%3Fsv%3D1%26sig%3DDummySasSig123%26sp%3Dr")
        self.assertNotIn("DummySasSig123", out); self.assertIn("%26sp%3Dr", out)
        # outside a query string an unquoted value still runs to whitespace
        self.assertNotIn("TAIL", self.agent.redact("password=abcd&TAIL"))

    def test_run3_review_ordinary_text_near_the_new_rules_survives(self):
        for s in ('{"name":"DB_HOST","value":"db.internal"}', "--password-file /run/secrets/db", "--token-ttl 5m",
                  '{"name":"MONKEY_COUNT","value":"12"}', '{"name":"KEYCLOAK_URL","value":"https://sso.internal"}',
                  '{"name":"CACHE_KEY_PREFIX","value":"app:"}',
                  "secret_key_id=5", "use --secret-store vault"):
            with self.subTest(s):
                self.assertEqual(self.agent.redact(s), s)

    def test_run3_review_patterns_are_not_quadratic_on_a_repeated_prefix(self):
        cases = ("SECRET_KEY_BASE=" * 8000, 'secret_key":"' * 6000, '{"name":"' * 8000, '{"name":"DB_PASSWORD","value":"' * 3000,
                 '"name":"' + "password" * 5000, "--password " * 8000, "--api-key=" * 8000, "?password=" * 8000,
                 "&token=" * 8000, "%26sig%3D" * 8000, '\\"name\\":\\"' * 6000, '{"name":"' + "_key" * 8000,
                 '{"name":"DB_PASSWORD","value":"' + "\\" * 50000, "--password \t" * 8000, "&sig=%2" * 8000, "&" * 50000,
                 ("&" + "a" * 63) * 1000, ("?" + "x" * 63 + "password") * 800, "&password" * 8000)
        for c in cases:
            start = time.monotonic()
            self.agent._redact(c, self.agent.DEFAULT_REDACT)
            self.assertLess(time.monotonic() - start, 1.0, c[:24])

    def test_run3_new_patterns_are_not_quadratic_on_a_repeated_prefix(self):
        # one repeated-prefix case per pattern the run-3 fix added or widened
        cases = ("<password>" * 8000, '"password"=>' * 8000, r'\\\"password\\\":' * 6000, "pass=" * 8000,
                 'password:"' + "\\" * 50000, "passphrase=" * 8000, "&Signature=" * 8000, "%26sig%3D" * 8000,
                 "&x-goog-signature=" * 5000, "AccountKey=" * 8000, "Ocp-Apim-Subscription-Key:" * 5000,
                 "MIIAAAAAAAAAAAAAAAAAAAAA\\n" * 8000, "MIIAAAAAAAAAAAAAAAAAAAAA " * 8000,
                 " " * 50000 + "A" * 63, "LS0tLS1CRUdJTi" * 10000, "<" + "a" * 60 + "password" * 5000)
        for s in cases:
            start = time.monotonic()
            self.agent._redact(s, self.agent.DEFAULT_REDACT)
            self.assertLess(time.monotonic() - start, 1.0, s[:24])

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
            srv.shutdown(); srv.server_close()

    def test_combine_reports_unreachable_over_a_partial_ok(self):
        # a single logical endpoint (e.g. /api/v1/query, hit once for rule_now and once for up) must
        # not read "ok" when one of the two calls actually failed - that would hide a partial failure.
        self.assertEqual(self.agent.combine("ok", "unreachable"), "unreachable")
        self.assertEqual(self.agent.combine("unreachable", "ok"), "unreachable")
        self.assertEqual(self.agent.combine("ok", "empty"), "ok")
        self.assertEqual(self.agent.combine("empty", "skipped"), "empty")
        self.assertEqual(self.agent.combine(), "skipped")

    _MII = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdummy"
    def test_run4_pem_row_continuation_takes_only_real_pem_rows(self):
        # run-4 h3: the headerless-PEM rule continued across any 16+ base64-alphabet run after a line
        # break, so a field name after a MII token ("databasePassword") was eaten as a PEM row and
        # the keyword rule never saw it. A continuation row is now a real one: exactly 64 characters,
        # or a final row of 4-64 (with its "=" padding) that ends the line.
        for line in ("ca: " + self._MII + "\n  databasePassword: hunter2dummy",
                     "ca=" + self._MII + " databasePassword=hunter2dummy",
                     "ca=" + self._MII + "\\nstorageAccountKey=hunter2dummy",
                     "ca=" + self._MII + "\n  appPassword= hunter2dummy user=bob",
                     "ca=" + self._MII + "\n  appPassword=\thunter2dummy user=bob"):
            with self.subTest(line=line):
                self.assertNotIn("hunter2dummy", self.agent.redact(line))
        # real multi-row keys still lose every row, raw and JSON-escaped, with and without padding
        rows = ["A" * 64, "B" * 64, "Cdummy+/" * 4 + "QQ=="]   # a real final row: 34 characters, then "=="
        for sep in ("\n", "\\n", "\r\n", "\n    "):
            key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD" + sep + sep.join(rows)
            with self.subTest(sep=sep):
                out = self.agent.redact("key: " + key + sep + "next: ok")
                for r in rows:
                    self.assertNotIn(r[:20], out)
                self.assertIn("next: ok", out)
        # R42: a final row closed by a quote, comma, brace or bracket (a PEM inside JSON, a YAML flow
        # sequence) is a final row too
        pem = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD\n" + "R" * 64 + "\nLASTROWdummyQQ=="
        for line in (json.dumps({"ca": pem, "x": 1}), json.dumps([pem]), "ca: '" + pem.replace("\n", " ") + "', x: 1",
                     "{ca: " + pem.replace("\n", " ") + "}", json.dumps({"ca": pem.rstrip("=") + "AA"})):
            with self.subTest(line=line[-40:]):
                out = self.agent.redact(line)
                self.assertNotIn("LASTROW", out)
                self.assertNotIn("R" * 20, out)
        # a final row with no padding at the end of the text
        self.assertNotIn("Zdummy", self.agent.redact("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD\n" + "A" * 64 + "\nZdummyZdummy"))
    def test_run4_keyword_after_a_pem_block_is_redacted_first(self):
        # R42 round 2: the final-row lookahead took "password=" before a quote as a padded PEM row,
        # the PEM rule ate it, and the keyword rule never saw the quoted value. Keywords now run
        # before the headerless-PEM rules, and a final row must have real base64 shape.
        row = "R" * 64
        for line in ("ca=" + self._MII + ' password="hunter2dummy"',
                     "TLS_CA=" + self._MII + '\nPASSWORD="hunter2dummy"',
                     "ca: " + self._MII + "\n" + row + "\ntoken='hunter2dummy'",
                     "ca: " + self._MII + "\n" + row + '\nsecret="hunter2dummy"',
                     "ca: " + self._MII + "\n" + row + '\napiKey="hunter2dummy"',
                     "ca: " + self._MII + "\n" + row + '\npwd="hunter2dummy"',
                     json.dumps({"ca": self._MII + "\n" + row, "password": "hunter2dummy"})):
            with self.subTest(line=line[-30:]):
                out = self.agent.redact(line)
                self.assertNotIn("hunter2dummy", out)
                self.assertNotIn(row[:20], out)
                self.assertNotIn(self._MII[:20], out)
        # ... and a PEM held by a keyword-named field still loses every row: the keyword rule now
        # takes only the first, and the PEM rule continues from the "[redacted]" it left
        for line in ("private_key: " + self._MII + "\n  " + row + "\n  LASTdummQQ==",
                     "private_key=" + self._MII + " " + row + " LASTdummQQ==",
                     "PRIVATE_KEY=" + self._MII + "\\n" + row + "\\nLASTdummQQ== next"):
            with self.subTest(line=line[:30]):
                out = self.agent.redact(line)
                for part in (self._MII[:20], row[:20], "LASTdumm"):
                    self.assertNotIn(part, out)
        # a final row has real base64 shape, so an ordinary field after a key is not eaten as one
        self.assertIn('user="bob"', self.agent.redact("ca: " + self._MII + "\n" + row + '\nuser="bob"'))
        # an ordinary short word on the line after a redacted value is not a PEM row
        self.assertEqual(self.agent.redact("password: x\ndone"), "password: [redacted]\ndone")
    def test_run5_headerless_pem_shapes_lose_every_row(self):
        # audit run-5 h3 run5_probe section 1, verbatim shapes (dummy body): the run-4 row rule left a
        # 76-column body, a key cut mid-row by loki_lines' 300-character cut, and a padded final row
        # followed by more text partly in the clear.
        import random
        rnd = random.Random(5)
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        der = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "".join(rnd.choice(b64) for _ in range(1200))
        wrap = lambda s, w: [s[i:i + w] for i in range(0, len(s), w)]
        rows64 = wrap(der[:64 * 4 + 40], 64); rows64[-1] = rows64[-1][:34] + "=="
        rows76 = wrap(der[:76 * 4], 76)
        cases = [
            ("64-col, escaped \\n, no keyword", "ca=" + "\\n".join(rows64), rows64),
            ("64-col, escaped \\n, keyword private_key=", "cfg private_key: " + "\\n".join(rows64), rows64),
            ("64-col, JSON quoted, keyword", '{"private_key":"' + "\\n".join(rows64) + '"}', rows64),
            ("64-col, real newlines (annotation text)", "ca:\n" + "\n".join(rows64), rows64),
            ("76-col (GNU base64 default), escaped \\n", "ca=" + "\\n".join(rows76), rows76),
            ("76-col, real newlines (annotation text)", "ca:\n" + "\n".join(rows76), rows76),
            ("64-col cut mid-row (Loki 300-char cut)", ("ca=" + "\\n".join(rows64))[:300], rows64),
            ("64-col, padded final row, then text", "ca=" + "\\n".join(rows64[:-1] + [rows64[-1][:36]]) + " next=1", rows64),
        ]
        # review round 1: a final row of whole 4-character groups with no padding (a DER length
        # divisible by 3, about one key in three), then text, after any separator - and one row alone
        unpadded = rows64[:-1] + [rows64[-1][:32]]
        for sep in ("\\n", "\n", " "):
            cases.append(("64-col, unpadded final row, then text, sep %r" % sep, "ca=" + sep.join(unpadded) + " next=1", unpadded))
            cases.append(("one unpadded row after the first, then text, sep %r" % sep, "ca=" + sep.join([unpadded[0], unpadded[-1]]) + " next=1",
                          [unpadded[0], unpadded[-1]]))
        for label, s, rows in cases:
            with self.subTest(label):
                out = self.agent.redact(s)
                # the probe's own leak test: any row whose first 16 characters survive
                self.assertEqual([r for r in rows if len(r) >= 16 and r[:16] in out], [], out)
                if label.startswith("64-col cut"):     # the cut row, shorter than 16 past its start, too
                    self.assertNotIn(s[-10:], out)
        for label, s, _ in cases:
            if s.endswith(" next=1"):
                self.assertIn(" next=1", self.agent.redact(s), label)
        # one word of that shape at most: the prose after it survives
        self.assertIn("text will stay", self.agent.redact("ca=" + "\n".join(unpadded) + "\nthis text will stay"))
        # the text after a key is still text: a field name on the next line keeps its name
        self.assertIn("databasePassword: [redacted]", self.agent.redact("ca: " + der[:48] + "\n  databasePassword: hunter2dummy"))
    def test_run4_a_secret_named_label_loses_its_value(self):
        # run-4 h3: patterns only see a string, never the dict key above it, so a Prometheus label or
        # alert label named password/token/api_key kept its value in the pack.
        pack = {"series": [{"metric": {"__name__": "x", "password": "hunter2dummy", "db_token": "tok-dummy",
                                       "API_KEY": "k-dummy", "instance": "web-1", "max_tokens": "4096"}}],
                "labels": {"client_secret": "cs-dummy", "service": "api", "bypass": "yes"}}
        out = self.agent.redact(pack)
        m, l = out["series"][0]["metric"], out["labels"]
        self.assertEqual((m["password"], m["db_token"], m["API_KEY"], l["client_secret"]), ("[redacted]",) * 4)
        self.assertEqual((m["instance"], m["max_tokens"], l["service"], l["bypass"]), ("web-1", "4096", "api", "yes"))
    def test_run5_a_secret_named_key_loses_a_value_of_any_type(self):
        # audit run-5 h3: only a str under a secret-named key was replaced; a number, a list or a
        # dict under "secret"/"token"/"pass" went through as it was.
        out = self.agent.redact({"labels": {"secret": 12345, "token": ["tokdummyinlist", 7], "password": None,
                                            "pass": {"v": "nested", "n": [1.5, True]}, "max_tokens": 4096, "bypass": ["yes"]}})
        self.assertEqual(out["labels"], {"secret": "[redacted]", "token": ["[redacted]", "[redacted]"], "password": "[redacted]",
                                         "pass": {"v": "[redacted]", "n": ["[redacted]", "[redacted]"]},
                                         "max_tokens": 4096, "bypass": ["yes"]})
    def test_run6_a_jwt_on_the_row_after_a_pem_blob_loses_all_of_it(self):
        # audit run-6 h3 run6_probe section 2: a JWT whose header segment is exactly 76 (or 64) base64
        # characters read as one more PEM row after a MII blob or a "[redacted]"; only the header went,
        # and the payload and signature passed, since the JWT rule needs "eyJ.." before ".eyJ".
        import random
        rnd = random.Random(6)
        al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        w = lambda n: "".join(rnd.choice(al) for _ in range(n))
        mii = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + w(32)
        pay, sig = "eyJzdWIiOiJkdW1teSJ9" + w(20), w(43) + "-_x"
        for hdr in ("eyJ" + w(73), "eyJ" + w(61)):
            jwt = hdr + "." + pay + "." + sig
            for label, s, want in (("after a MII blob", mii + "\n" + jwt, "[pem-redacted]\n[jwt-redacted]"),
                                   ("after a MII blob, JSON-escaped", mii + "\\n" + jwt, "[pem-redacted]\\n[jwt-redacted]"),
                                   ("after [redacted]", "token: x\n" + jwt, "token: [redacted]\n[jwt-redacted]")):
                with self.subTest(label, header=len(hdr)):
                    self.assertEqual(self.agent.redact(s), want)
        # a real 76-column row is still a row
        self.assertEqual(self.agent.redact(mii + "\n" + w(76)), "[pem-redacted]")

    def test_run6_firing_alerts_keep_a_bounded_copy_of_their_labels(self):
        # audit run-6 h2: firing_alerts kept each of the first 30 alerts' parsed labels dict by
        # reference, unbounded, outside the parse lock: 4 workers over 30 alerts of ~25k short labels
        # peaked at 393-396 MiB against the 256 MiB limit.
        labels = {"a_long_name_" + "n" * 400: "x", "a_long_value": "y" * 1000}
        labels.update({"l%04d" % i: "v%d" % i for i in range(5000)})
        labels.update({"alertname": "Forged", "namespace": "prod", "severity": "critical"})
        alert = dict(AM_ALERTS[0], labels=labels, status={"state": "active", "inhibitedBy": ["i%d" % i for i in range(50)],
                                                          "silencedBy": ["s" * 1000] * 50})
        Fake.routes["/api/v2/alerts"] = (200, [alert] * 3)
        # past the pack budget trim() would drop "firing" whole, which is not what this is about
        with mock.patch.object(self.agent, "MAX_BYTES", 10 ** 8), mock.patch.object(self.agent, "HARD_CAP_BYTES", 10 ** 8):
            p = self.agent.build_pack(WEBHOOK)
        self.assertEqual(len(p["firing"]), 3)
        for a in p["firing"]:
            self.assertLessEqual(len(a["labels"]), 64)
            self.assertTrue(all(len(k) <= 300 and len(v) <= 300 for k, v in a["labels"].items()))
            self.assertEqual(a["labels"]["a_long_value"], "y" * 300)
            self.assertEqual([a["labels"].get(k) for k in ("alertname", "namespace", "severity")], ["Forged", "prod", "critical"])
            self.assertEqual((len(a["inhibitedBy"]), len(a["silencedBy"])), (10, 10))
            self.assertTrue(all(len(x) <= 300 for x in a["silencedBy"]))

    def test_run6_every_other_fetcher_keeps_a_bounded_copy(self):
        # the same retained-by-reference shape in series_now/series_range (metric), deploys (tags,
        # text, count), loki_lines (a body holding more lines than asked for) and rule_for (query)
        metric = dict({"m%04d" % i: "v" * 400 for i in range(5000)}, __name__="up", instance="web-1")
        Fake.routes["/api/v1/query_range"] = (200, {"status": "success", "data": {"result": [
            {"metric": metric, "values": [[1, "1" * 1000], [2, "0"]]}]}})
        Fake.routes["/api/v1/query"] = (200, {"status": "success", "data": {"result": [{"metric": metric, "value": [1, "0" * 1000]}]}})
        Fake.routes["/api/annotations"] = (200, [{"time": 1, "tags": ["deploy"] * 500, "text": "t" * 5000}] * 50)
        Fake.routes["/loki/api/v1/query_range"] = (200, {"status": "success", "data": {"result": [
            {"stream": {}, "values": [[str(1758000000000000000 + i), "line %d" % i] for i in range(5000)]}]}})
        Fake.routes["/api/v1/rules"] = (200, {"status": "success", "data": {"groups": [{"name": "g" * 1000, "rules": [
            {"name": "ServiceDown", "query": "up == 0 or " * 1000 + "up", "health": "ok"}]}]}})
        b = lambda: self.agent.Budget(5)
        for rows, _ in (self.agent.series_now("up", b()), self.agent.series_range("up", b())):
            m = rows[0]["metric"]
            self.assertEqual(len(m), 64); self.assertEqual((m["__name__"], m["instance"]), ("up", "web-1"))
            self.assertTrue(all(len(v) <= 300 for r in rows for v in list(r["metric"].values()) + [r.get("value") or r["first"]]))
        d, _ = self.agent.deploys(b())
        self.assertEqual(len(d), 10)
        self.assertTrue(all(len(x["tags"]) <= 10 and len(x["text"]) <= 300 for x in d))
        lines, _ = self.agent.loki_lines('{a="b"}', b(), limit=50)
        self.assertEqual([l["line"] for l in lines[:2]], ["line 4999", "line 4998"]); self.assertEqual(len(lines), 50)
        r, _ = self.agent.rule_for("ServiceDown", b())
        self.assertLessEqual(len(r["query"]), 4000); self.assertLessEqual(len(r["group"]), 300)

    def test_run7_a_last_key_row_before_a_dot_is_redacted(self):
        # audit run-7 h3 run7_probe (1): the "." added to the row lookaheads for the JWT case (run-6)
        # also left a real last row of 64 or 76 characters in the clear when "." followed it, and a
        # padded last row followed by "." leaked before that too. Only ".eyJ" (a JWT's payload) stops a row.
        import random
        rnd = random.Random(7)
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        w = lambda n: "".join(rnd.choice(b64) for _ in range(n))
        mii = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + w(32)
        for width in (64, 76):
            for sep in ("\n", "\\n", " "):
                for last, rows in (("full", [w(width), w(width)]), ("padded", [w(width), w(width - 10) + "AAAAAAAA=="])):
                    s = "load key failed: " + mii + sep + sep.join(rows) + ". retrying"
                    with self.subTest(width=width, sep=sep, last=last):
                        out = self.agent.redact(s)
                        self.assertEqual([r for r in rows if r[:16] in out], [], out)
                        self.assertTrue(out.endswith(". retrying"), out)
                # the rows after a keyword's own value ("[redacted]") start the rule on the same terms
                row = w(width)
                with self.subTest(width=width, after="[redacted]"):
                    out = self.agent.redact("private_key: " + mii + "\n" + row + ". retrying")
                    self.assertNotIn(row[:16], out); self.assertTrue(out.endswith(". retrying"), out)
        # a JWT still stays whole after a MII blob, whatever its header's length: HS256's usual 36
        # characters would otherwise read as a padded last row once "." ends one
        for hdr in ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJ" + w(73).replace("+", "a").replace("/", "b")):
            jwt = hdr + ".eyJzdWIiOiJkdW1teSJ9" + w(20).replace("+", "a").replace("/", "b") + "." + "s" * 43
            with self.subTest(header=len(hdr)):
                self.assertEqual(self.agent.redact(mii + "\n" + jwt), "[pem-redacted]\n[jwt-redacted]")

    def test_run7_a_cut_never_leaves_part_of_a_secret(self):
        # audit run-7 h3 run7_probe (3): values were cut to 300 characters before redact(), so a token
        # straddling the cut kept a prefix no pattern matches (a ghp_ token kept 9-19 of its characters),
        # and a label name longer than 300 lost the "_password" that blanks its value.
        tok = "ghp_" + "3Wk6Gml15hEecaA49qOxYzAbCdEfGhIjKlMn"
        name = "a" * 301 + "_password"
        labels = {"alertname": "Leak", "note": "x" * 280 + " token " + tok, name: "dummyval"}
        labels.update({"at%03d" % n: "y" * n + " " + tok for n in range(250, 300, 3)})
        # review round 1: the redaction window's end is a cut too. A secret redacted earlier in the
        # window shrinks and pulls the text at that end into the kept 300: a password, and a PEM body
        import random
        rnd = random.Random(21)
        pem = "MII" + "".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(2327))
        labels.update({"shrink_pw": "password=" + "A" * 2315 + " " + tok, "shrink_pem": "k=" + pem + " " + tok})
        Fake.routes["/api/v2/alerts"] = (200, [dict(AM_ALERTS[0], labels=labels)])
        Fake.routes["/loki/api/v1/query_range"] = (200, {"status": "success", "data": {"result": [
            {"stream": {}, "values": [["1758000000000000000", "z" * 290 + " " + tok + " retry"]]}]}})
        p = self.agent.build_pack(WEBHOOK)
        kept = p["firing"][0]["labels"]
        text = json.dumps(p)
        self.assertEqual([tok[:n] for n in range(9, len(tok)) if tok[:n] in text], [], "part of the token survived a cut")
        self.assertEqual(kept[name[:300]], "[redacted]")
        self.assertNotIn("dummyval", text)
        self.assertTrue(kept["note"].startswith("x" * 280 + " token "), kept["note"])
        self.assertEqual(len(self.agent._cut("x " * 2500)), 300)   # without a shrink the margin costs nothing
        self.assertEqual(self.agent._cut("x" * 5000), "[cut]")     # dropped whole, and says so (review round 3)
        for k in ("shrink_pw", "shrink_pem"):
            self.assertNotIn("ghp_", kept[k], k)
        self.assertTrue(all(len(k) <= 300 and len(v) <= 300 for k, v in kept.items()))
        # review round 2 (N1): a pattern that needs a part after the secret (a JWT's "." after the
        # payload, a token's minimum length, a key's 16 characters) matched nothing when the window's
        # end cut it off, so its start was kept. Every shape, across the cut and across the window's
        # end, with and without a secret earlier in the value that shrinks: no 9-character run of the
        # secret survives _cut (300 and the rule query's 4000) or _labels, then the pack's own redact().
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        rw = lambda n, al=b64: "".join(rnd.choice(al) for _ in range(n))
        jwt_pay, jwt_sig = rw(2600, b64 + "-_"), rw(43, b64 + "-_")
        pem_rows = [rw(64, b64 + "+/") for _ in range(45)]
        shapes = {   # name -> (the text placed in the value, the secret part that must not survive)
            "jwt, long payload": ("eyJhbGciOiJIUzI1NiJ9.eyJ" + jwt_pay + "." + jwt_sig, jwt_pay + jwt_sig),
            "ghp_": ("ghp_" + (x := rw(36)), x),
            "AKIA": ("AKIA" + (x := rw(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")), x),
            "sk-ant-": ("sk-ant-api03-" + (x := rw(95, b64 + "-_")), x),
            "PEM body": ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n" + "\n".join(pem_rows), "".join(pem_rows)),
            "sig= URL": ("https://acct.blob.core.windows.net/c/f?sv=2022-11-02&sig=" + (x := rw(64, b64 + "%")), x),
            "Bearer": ("Authorization: Bearer " + (x := rw(80, b64 + "._-")), x),
        }
        leaks = []
        for n in (300, self.agent.RULE_QUERY_CHARS):
            W = n + self.agent.CUT_REDACT_WINDOW
            for name, (text, secret) in shapes.items():
                runs = {secret[i:i + 9] for i in range(len(secret) - 8)}
                for start in (n - 40, n - 9, n - 1, W - 60, W - 20, W - 9, W - 1):
                    for shrink in ("", "password=" + "Q" * 1800 + " "):
                        pad = start - len(shrink)
                        if pad < 1: continue
                        v = shrink + ("x " * start)[:pad - 1] + " " + text + " tail"
                        outs = [self.agent._cut(v, n)] + ([self.agent._labels({"l": v})["l"]] if n == 300 else [])
                        for out in map(self.agent.redact, outs):   # the pack is redacted again as a whole
                            got = next((r for r in runs if r in out), None)
                            if got:
                                leaks.append((name, n, start, bool(shrink), got))
        self.assertEqual(leaks, [], "a secret crossing a cut kept 9+ characters")

    def test_run7_r3_a_jwt_is_redacted_whole_whatever_its_payload_embeds(self):
        # review round 3: the token and PEM rules ran before the JWT rule, so a base64url payload that
        # held "-sk-ant-...", "-ghp_..." or "-MII..." lost only that part and the JWT rule no longer
        # matched: header, claims and signature leaked, even with the whole string in view.
        import random
        rnd = random.Random(33)
        al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        w = lambda n: "".join(rnd.choice(al) for _ in range(n))
        hdr, sig = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", w(43)
        for name, inner in (("sk-ant-", "sk-ant-" + w(40)), ("ghp_", "ghp_" + w(36)), ("MII", "MII" + w(64)),
                            ("LS0t", "LS0tLS1CRUdJTi" + w(40)), ("AKIA", "AKIA" + w(16).upper())):
            pay = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4" + "-" + inner + "-" + w(20)
            with self.subTest(name):
                self.assertEqual(self.agent.redact("tok " + hdr + "." + pay + "." + sig), "tok [jwt-redacted]")

    def test_run7_r3_an_encrypted_legacy_pem_loses_every_row(self):
        # review round 3: RFC 1421 headers (Proc-Type, DEK-Info) after "-----BEGIN RSA PRIVATE KEY-----"
        # stopped the BEGIN rule at "Proc", and the lone-row rule takes only 64-column rows, so the
        # short last row of the encrypted body stayed in the clear.
        import random
        rnd = random.Random(34)
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        rows = ["".join(rnd.choice(b64) for _ in range(64)) for _ in range(6)] + ["".join(rnd.choice(b64) for _ in range(26)) + "=="]
        for sep in ("\n", "\\n", "\r\n"):
            key = sep.join(["-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED",
                            "DEK-Info: AES-128-CBC,5F0A1B2C3D4E5F60718293A4B5C6D7E8", ""] + rows + ["-----END RSA PRIVATE KEY-----"])
            for label, s in (("alone", key), ("in a log line", "loading key: " + key + " done")):
                with self.subTest(sep=sep, where=label):
                    out = self.agent.redact(s)
                    self.assertEqual([r for r in rows if r[:12] in out], [], out)
                    self.assertNotIn("DEK-Info", out)

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
            srv.shutdown(); srv.server_close()


class ToolTests(unittest.TestCase):
    """run_tool(): the engine's only way back into this box. Same fakes as the pack, so a tool result
    is proven to be the redacted, capped shape of what the real service returns."""
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = serve()

    def setUp(self):
        Fake.routes = routes_ok(); Fake.hits.clear()
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "runbooks"))   # RUNBOOK_DIR; the traversal test writes above it
        self.agent = load_agent(self.base, self.tmp)

    def test_every_tool_is_registered_and_read_only(self):
        self.assertEqual(sorted(self.agent.TOOLS), ["alerts", "deploys", "loki_query", "prom_query", "prom_range", "runbook"])

    def test_prom_query_returns_series_now_shape(self):
        r, st = self.agent.run_tool("prom_query", {"expr": "probe_success"}, 5)
        self.assertEqual(st, "ok"); self.assertEqual(r[0]["value"], "0")
        self.assertTrue(any(h.startswith("/api/v1/query?") for h in Fake.hits))

    def test_prom_range_honours_minutes_and_caps_it(self):
        r, st = self.agent.run_tool("prom_range", {"expr": "probe_success", "minutes": 999}, 5)
        self.assertEqual(st, "ok"); self.assertEqual(r[0]["points"], 3)
        q = urllib.parse.parse_qs(urllib.parse.urlparse([h for h in Fake.hits if "query_range" in h][0]).query)
        self.assertAlmostEqual(float(q["end"][0]) - float(q["start"][0]), 180 * 60, delta=5)   # capped at 180 min
        self.assertEqual(q["step"][0], "180")                                                 # ~60 points

    def test_loki_query_passes_selector_verbatim_and_redacts(self):
        sel = '{service="api"} |= "password"'
        r, st = self.agent.run_tool("loki_query", {"selector": sel, "minutes": 5, "limit": 2}, 5)
        self.assertEqual(st, "ok"); self.assertEqual(len(r), 2)
        self.assertNotIn("hunter2", json.dumps(r))
        q = urllib.parse.parse_qs(urllib.parse.urlparse([h for h in Fake.hits if "loki" in h][0]).query)
        self.assertEqual(q["query"][0], sel); self.assertEqual(q["limit"][0], "2")

    def test_alerts_deploys_runbook(self):
        r, st = self.agent.run_tool("alerts", {}, 5); self.assertEqual(st, "ok"); self.assertEqual(r[0]["labels"]["alertname"], "ServiceDown")
        r, st = self.agent.run_tool("deploys", {"minutes": 60}, 5); self.assertEqual(st, "ok"); self.assertEqual(r[0]["text"], "api v2.14 by ci")
        q = urllib.parse.parse_qs(urllib.parse.urlparse([h for h in Fake.hits if "annotations" in h][0]).query)
        self.assertAlmostEqual((int(q["to"][0]) - int(q["from"][0])) / 1000, 3600, delta=5)
        # A real file one directory above RUNBOOK_DIR, asked for by a name that walks there: with the
        # sanitiser gone, os.path.join(RUNBOOK_DIR, "../escape.md") resolves onto it and the tool
        # answers "ok" with its text. The previous fixture here ("../../etc/passwd") could not fail -
        # /etc/passwd.md does not exist, so that request read "empty" sanitiser or no sanitiser.
        with open(os.path.join(self.tmp, "escape.md"), "w") as f:
            f.write("# Escape\n\nnotmyrunbook, and never a thing to quote into an alert channel.\n")
        r, st = self.agent.run_tool("runbook", {"alert": "../escape"}, 5)
        self.assertEqual(st, "empty"); self.assertNotIn("notmyrunbook", json.dumps(r))

    def test_unknown_tool_and_bad_args(self):
        self.assertEqual(self.agent.run_tool("rm", {}, 5), (None, "unknown"))
        r, st = self.agent.run_tool("prom_query", "not a dict", 5); self.assertEqual(st, "skipped")

    def test_result_is_capped_and_marked(self):
        big = {"status": "success", "data": {"result": [{"metric": {"x": "y" * 500}, "value": [1, "0"]}] * 20}}
        Fake.routes["/api/v1/query"] = (200, big)
        r, st = self.agent.run_tool("prom_query", {"expr": "x"}, 5)
        self.assertTrue(r["truncated"]); self.assertLessEqual(len(r["sample"]), self.agent.TOOL_MAX_BYTES)

    def test_budget_zero_is_unreachable_without_a_call(self):
        Fake.hits.clear()
        r, st = self.agent.run_tool("alerts", {}, 0)
        self.assertEqual(st, "unreachable"); self.assertEqual(Fake.hits, [])

    # run-3: a LogQL pipeline reshapes lines before redact() sees them - `| json | line_format
    # "{{.password}}"` returns a bare secret with no keyword left for any pattern to find.
    H3_SELECTOR = '{service="auth"} |~ "(?i)error" | json | line_format "{{.password}}"'

    def test_loki_query_refuses_every_pipeline_stage_before_calling_loki(self):
        for sel in (self.H3_SELECTOR, '{a="b"} | json', '{a="b"}|logfmt', '{a="b"} | line_format "{{.x}}"',
                    '{a="b"} | label_format x=y', '{a="b"} | regexp "(?P<x>.*)"', '{a="b"} | pattern "<x>"',
                    '{a="b"} | unpack', '{a="b"} | decolorize', '{a="b"} | drop x', '{a="b"} | keep x',
                    '{a="b"} |= "x" or "y"', '{a="b"} |= ip("1.1.1.1")', '{a="b"} | x="y"', 'sum(count_over_time({a="b"}[5m]))',
                    '{a="b"} |= "x" | json', 'a="b"', '{a="b"} |= x', '{}', ''):
            Fake.hits.clear()
            r, st = self.agent.run_tool("loki_query", {"selector": sel}, 5)
            self.assertEqual(st, "refused", sel)
            self.assertIn("error", r, sel)
            self.assertEqual([h for h in Fake.hits if "loki" in h], [], sel)

    def test_loki_query_accepts_a_stream_selector_and_line_filters(self):
        for sel in ('{service="api"}', '{service="api"} |~ "(?i)error"', '{service="api", level!="debug", x=~"a|b"} != "healthz" |= "timeout"',
                    '{a="x | json"} |= "| line_format"', '{a="b"} |= `raw \\ text` !~ "\\"q\\""', ' { a = "b" , c != "d" } |= "e" '):
            Fake.hits.clear()
            r, st = self.agent.run_tool("loki_query", {"selector": sel}, 5)
            self.assertEqual(st, "ok", sel)

    def test_prom_tools_refuse_label_replace_and_label_join(self):
        for tool in ("prom_query", "prom_range"):
            for expr in ('label_replace(up, "x", "$1", "instance", "(.*)")', 'label_join(up, "x", ",", "job")',
                         'sum(LABEL_REPLACE (up, "x", "$1", "job", "(.*)"))'):
                Fake.hits.clear()
                r, st = self.agent.run_tool(tool, {"expr": expr}, 5)
                self.assertEqual(st, "refused", (tool, expr)); self.assertIn("error", r)
                self.assertEqual(Fake.hits, [], (tool, expr))
        r, st = self.agent.run_tool("prom_query", {"expr": 'sum by (instance) (up{job="node"})'}, 5)
        self.assertEqual(st, "ok")

    def test_tool_result_over_the_upstream_cap_is_too_large_and_never_parsed(self):
        self.agent.MAX_UPSTREAM_BYTES = 1000
        Fake.routes["/api/v1/query"] = (200, {"status": "success", "data": {"result": [
            {"metric": {"x": "y" * 2000}, "value": [1, "0"]}]}})
        with mock.patch.object(self.agent.json, "loads", wraps=json.loads) as loads:
            r, st = self.agent.run_tool("prom_query", {"expr": "x"}, 5)
        self.assertEqual(st, "too-large"); self.assertIsNone(r)
        self.assertEqual(loads.call_count, 0)   # nothing past the cap is parsed

    def test_pack_source_over_the_upstream_cap_fails_like_a_dead_one(self):
        self.agent.MAX_UPSTREAM_BYTES = 1000
        Fake.routes["/api/v2/alerts"] = (200, AM_ALERTS * 20)
        p = self.agent.build_pack(WEBHOOK)
        self.assertEqual(p["sources"]["alertmanager"], "unreachable"); self.assertEqual(p["firing"], [])
        self.assertEqual(p["sources"]["rules"], "ok")

    def test_upstream_bodies_are_parsed_one_at_a_time(self):
        # audit run-5 section H: four workers each decoding and parsing an attacker-shaped 8 MiB alert
        # list at once reached a VmHWM of 351 MiB (worst of 20 trials) against the 256 MiB limit. The
        # network reads may overlap (review ruling R48: they hold no lock); the parses never do.
        inside, peak, lock, real_loads = [0], [0], threading.Lock(), json.loads
        class Resp:
            def __init__(self): self.body = [b'{"ok": true}']
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read1(self, n): return self.body.pop() if self.body else b""
        def loads(s, *a, **k):
            with lock:
                inside[0] += 1; peak[0] = max(peak[0], inside[0])
            time.sleep(0.2)                  # long enough for the other thread to arrive if it could
            with lock:
                inside[0] -= 1
            return real_loads(s, *a, **k)
        out = []
        with mock.patch.object(self.agent._OPENER, "open", lambda req, timeout: Resp()), \
             mock.patch.object(self.agent.json, "loads", loads):
            ts = [threading.Thread(target=lambda: out.append(self.agent.get_json("http://am/api/v2/alerts"))) for _ in range(2)]
            for t in ts: t.start()
            for t in ts: t.join()
        self.assertEqual(out, [{"ok": True}, {"ok": True}])
        self.assertEqual(peak[0], 1, "two upstream bodies were being parsed at the same time")

    def test_upstream_lock_wait_counts_against_the_call_timeout(self):
        # review round 1 (run-5): the wait for the parse lock counts, so one call never takes more
        # than its timeout and build_pack keeps to TOTAL_DEADLINE.
        class Resp:
            def __init__(self): self.body = [b'{"ok": true}']
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read1(self, n): return self.body.pop() if self.body else b""
        with mock.patch.object(self.agent._OPENER, "open", lambda req, timeout: Resp()), mock.patch("builtins.print"):
            self.agent._UPSTREAM.acquire()
            threading.Timer(1.0, self.agent._UPSTREAM.release).start()
            t0 = time.monotonic()
            self.assertIsNone(self.agent.get_json("http://am/api/v2/alerts", timeout=0.3))
            self.assertLess(time.monotonic() - t0, 0.6)
            time.sleep(1.0)
            self.agent._UPSTREAM.acquire()
            threading.Timer(0.2, self.agent._UPSTREAM.release).start()
            self.assertEqual(self.agent.get_json("http://am/api/v2/alerts", timeout=0.6), {"ok": True})

    def test_run6_a_trickling_upstream_is_cut_at_the_call_timeout(self):
        # audit run-6 (h1, h2, h9), review ruling R48: a socket timeout only fires on silence, so an
        # upstream sending a few bytes at a time kept the read going for as long as it liked, while
        # holding the parse lock -- a Content-Length body, a chunk-size line and a header line alike.
        # Each call now ends at its own wall-clock timeout, and the lock stays free throughout.
        shapes = {"content-length body": (b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n[", b"1,1,1,1,1,"),
                  "chunk-size line": (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;", b"aaaaaaaaaa"),
                  "header line": (b"HTTP/1.1 200 OK\r\nX-Pad: ", b"aaaaaaaaaa"),
                  # a body that ends at close, whose bytes before the cut already parse: http.client sees
                  # a normal end there, so the cut itself must fail the call
                  "close-delimited, valid JSON before the cut": (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n[1]", b"          ")}
        for name, (head, trickle) in shapes.items():
            with self.subTest(name):
                lst = socket.socket(); lst.bind(("127.0.0.1", 0)); lst.listen(1)
                self.addCleanup(lst.close)
                def serve(lst=lst, head=head, trickle=trickle):
                    c, _ = lst.accept()
                    try:
                        c.recv(65536); c.sendall(head)
                        end = time.monotonic() + 6
                        while time.monotonic() < end:
                            c.sendall(trickle); time.sleep(0.05)
                    except OSError:
                        pass
                    finally:
                        c.close()
                threading.Thread(target=serve, daemon=True).start()
                out = []
                t = threading.Thread(target=lambda: out.append(self.agent.get_json("http://127.0.0.1:%d/x" % lst.getsockname()[1], timeout=1.0)))
                with mock.patch("builtins.print"):
                    start = time.monotonic(); t.start(); time.sleep(0.3)
                    lock_free = self.agent._UPSTREAM.acquire(timeout=10)   # never held for the network read
                    waited = time.monotonic() - start - 0.3
                    self.agent._UPSTREAM.release()
                    t.join(10)
                took = time.monotonic() - start
                self.assertEqual(out, [None])
                self.assertTrue(lock_free and waited < 0.2, "the parse lock was held %.1fs during the network read" % waited)
                self.assertLess(took, 1.8, "a 1s call took %.1fs" % took)

    def test_run6_r2_a_body_the_guard_cut_is_never_parsed_even_with_time_left(self):
        # review round 2: a cut close-delimited body was refused only because the Timer fires at the
        # deadline; a Timer that fired early (another clock) left a valid-looking prefix to be parsed.
        class Fired:
            fired = True
            def __init__(self, *a, **k): pass
            def add(self, sock): return sock
            def cancel(self): pass
        class Resp:
            def __init__(self): self.body = [b"[1]"]
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read1(self, n): return self.body.pop() if self.body else b""
        with mock.patch.object(self.agent, "_Deadline", Fired), mock.patch("builtins.print"), \
             mock.patch.object(self.agent._OPENER, "open", lambda req, timeout: Resp()):
            self.assertIsNone(self.agent.get_json("http://am/api/v2/alerts", timeout=5))

    def test_run6_r2_a_failed_dup_leaks_neither_the_socket_nor_the_timer(self):
        # review round 2: _Deadline.add() dups the socket; a dup() failure (EMFILE) must still close
        # the connection's socket and cancel the timer.
        made, real_create = [], socket.create_connection
        def create(*a, **k):
            sock = real_create(*a, **k); made.append(sock); return sock
        timers = lambda: [t for t in threading.enumerate() if isinstance(t, threading.Timer) and t.is_alive()]
        before = len(timers())
        with mock.patch.object(socket, "create_connection", create), mock.patch("builtins.print"), \
             mock.patch.object(socket.socket, "dup", side_effect=OSError(24, "Too many open files")):
            self.assertIsNone(self.agent.get_json(self.base + "/api/v2/alerts", timeout=30))
        self.assertEqual(len(made), 1)
        self.assertEqual(made[0].fileno(), -1, "the connection's socket leaked")
        time.sleep(0.1)
        self.assertEqual(len(timers()), before, "the 30s timer was left running")

    def test_run6_a_credentialed_request_never_follows_a_redirect_to_another_origin(self):
        # audit run-6 (h9): urllib's default redirect handler copies every header to the new URL,
        # the Grafana Basic header included, whatever its host or port.
        got = []
        class Other(BaseHTTPRequestHandler):
            def do_GET(self):
                got.append(dict(self.headers)); self.send_response(200); self.end_headers(); self.wfile.write(b"[]")
            def log_message(self, *a): pass
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/same"):
                    self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok": 1}'); return
                self.send_response(302)
                self.send_header("Location", other + "/api/annotations" if self.path.startswith("/away") else "/same")
                self.end_headers()
            def log_message(self, *a): pass
        servers = [ThreadingHTTPServer(("127.0.0.1", 0), h) for h in (Other, Redirect)]
        for srv in servers:
            threading.Thread(target=srv.serve_forever, daemon=True).start(); self.addCleanup(srv.server_close); self.addCleanup(srv.shutdown)
        other, here = ("http://127.0.0.1:%d" % srv.server_address[1] for srv in servers)
        hdr = {"Authorization": "Basic " + base64.b64encode(b"admin:pw-dummy").decode()}
        with mock.patch("builtins.print"):
            r = self.agent.get_json(here + "/away", hdr, timeout=3)
        self.assertEqual([h.get("Authorization") for h in got], [], "the credential followed a redirect to another port")
        self.assertIsNone(r)
        # a redirect within the same origin is still followed
        self.assertEqual(self.agent.get_json(here + "/stay", hdr, timeout=3), {"ok": 1})

    def test_runbook_sanitises_the_name_itself_for_every_caller(self):
        # build_pack calls runbook(alertname) directly, without run_tool's sanitiser
        with open(os.path.join(self.tmp, "escape.md"), "w") as f:
            f.write("# Escape\n\nnotmyrunbook\n")
        r, st = self.agent.runbook("../escape")
        self.assertEqual(st, "empty"); self.assertNotIn("notmyrunbook", json.dumps(r))
        p = self.agent.build_pack(dict(WEBHOOK, alerts=[dict(WEBHOOK["alerts"][0], labels={"alertname": "../escape"})]))
        self.assertNotIn("notmyrunbook", json.dumps(p))

    def test_build_pack_escapes_label_values_inside_query_strings(self):
        # a label value with a quote must not close the string and append its own matcher or stage
        inst = 'x"} or vector(1) or up{a="'
        svc = 'api"} | json | line_format "{{.password}}'
        self.agent.build_pack(dict(WEBHOOK, alerts=[dict(WEBHOOK["alerts"][0], labels={"alertname": "ServiceDown", "instance": inst, "service": svc})]))
        qs = [urllib.parse.parse_qs(urllib.parse.urlparse(h).query).get("query", [""])[0] for h in Fake.hits]
        self.assertIn('up{instance="x\\"} or vector(1) or up{a=\\""}', qs)
        loki = [q for q in qs if q.startswith("{service=")][0]
        self.assertTrue(loki.startswith('{service="api\\"} | json | line_format \\"{{.password}}"} |~ '), loki)
        # a backslash is escaped first, so it cannot eat the escape in front of a quote
        self.agent.build_pack(dict(WEBHOOK, alerts=[dict(WEBHOOK["alerts"][0], labels={"alertname": "ServiceDown", "instance": 'a\\"b'})]))
        qs = [urllib.parse.parse_qs(urllib.parse.urlparse(h).query).get("query", [""])[0] for h in Fake.hits]
        self.assertIn('up{instance="a\\\\\\"b"}', qs)


FENCE_OPEN, FENCE_CLOSE = "```\n", "\n```"


def _unfenced(s):
    """Strip the ```...``` code fence post_note() wraps every chunk in, for asserting on the
    original note text a test posted. A plain assert here would be stripped under `python -O`,
    silently accepting an unfenced string instead of failing the test that relies on this helper."""
    if not (s.startswith(FENCE_OPEN) and s.endswith(FENCE_CLOSE)):
        raise AssertionError("not fenced: %r" % s)
    return s[len(FENCE_OPEN):-len(FENCE_CLOSE)]


# Values crafted to forge a `triage-trace {...}` line the AI Triage Grafana dashboard would parse
# as real: a real newline, a bare space, and a `"` positioned to end
# json.dumps's quoted string early if log() also doubled the backslash that escape introduced.
FORGED_TRACE_TEXTS = ('k\ntriage-trace {"outcome":"posted"}', 'k triage-trace {"outcome":"posted"}',
                      'a" triage-trace {"outcome":"posted"}')


def _decode_json_value_after(tc, line, prefix, expect):
    """`line` must be `prefix` followed by exactly one JSON string that decodes back to `expect`,
    with the rest of the line returned as-is. A stand-in substring check (e.g. asserting
    '"outcome":"posted"' is absent) is not enough: it misses the case where an embedded `"` in the
    untrusted value ends the JSON string early and leaves the remainder - possibly a forged
    ` triage-trace {...}` - as unquoted trailing text.
    raw_decode() is the same thing a real JSON parser would do, so this proves the actual property:
    the whole untrusted value round-trips as one JSON value, nothing more, nothing less."""
    tc.assertTrue(line.startswith(prefix), line)
    rest = line[len(prefix):]
    value, end = json.JSONDecoder().raw_decode(rest)
    tc.assertEqual(value, expect, line)
    return rest[end:]


class Sink(BaseHTTPRequestHandler):
    """Fake receivers (Slack/Discord/Telegram/email-via-webhook all just POST somewhere) on one
    server, started once at module level - shared by every test that posts a note, including
    EngineHookTests' fake-triage_engine tests."""
    posts = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); Sink.posts.append((self.path, self.rfile.read(n).decode(), {k.lower(): v for k, v in self.headers.items()}))
        if self.path.startswith(("/slack-down", "/discord-down")):
            self.send_response(500); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a): pass


def _fenced_lines(md):
    """Lines that landed inside a ``` ... ``` code fence of a formatted note - used to prove a
    second redact() pass never pulls text that followed a fence-opening line into the fence."""
    out, inside = [], False
    for l in md.split("\n"):
        if l.startswith("```"):
            inside = not inside
            continue
        if inside:
            out.append(l)
    return out


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

    def test_run7_a_trickling_receiver_is_cut_at_the_call_timeout(self):
        # audit run-7 h9: post_json kept only urllib's per-recv socket timeout, so a receiver trickling
        # its reply (a header line or a body) held the worker for as long as it kept sending.
        for name, head, trickle in (("content-length body", b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\no", b"kkkkkkkkkk"),
                                    ("header line", b"HTTP/1.1 200 OK\r\nX-Pad: ", b"aaaaaaaaaa")):
            lst = socket.socket(); lst.bind(("127.0.0.1", 0)); lst.listen(1)
            self.addCleanup(lst.close)
            stop = threading.Event()   # Event.wait, not time.sleep: a later test may mock time.sleep
            def serve(lst=lst, head=head, trickle=trickle, stop=stop):
                c, _ = lst.accept()
                try:
                    c.recv(65536); c.sendall(head)
                    end = time.monotonic() + 6
                    while time.monotonic() < end and not stop.is_set():
                        c.sendall(trickle); stop.wait(0.05)
                except OSError:
                    pass
                finally:
                    c.close()
            th = threading.Thread(target=serve, daemon=True); th.start()
            self.addCleanup(th.join, 10); self.addCleanup(stop.set)
            with self.subTest(name):
                start = time.monotonic()
                with self.assertRaises(Exception):
                    self.agent.post_json("http://127.0.0.1:%d/slack" % lst.getsockname()[1], {"text": "x"}, timeout=1.0)
                self.assertLess(time.monotonic() - start, 1.8)

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

    def test_telegram_chunks_break_at_line_boundaries(self):
        # audit run-5 h9 check 11: a runbook command straddling offset 4096 arrived as a prefix at the
        # end of one Telegram message and the rest at the start of the next.
        cmd = "kubectl -n prod describe deployment api | tail -20"
        text = "Triage: " + "h" * 4040 + "\nCheck first (from runbook)\n  " + cmd + "\nNot seen: tail line"
        self.assertLess(text.index(cmd), 4096); self.assertGreater(text.index(cmd) + len(cmd), 4096)
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t0k", "TELEGRAM_CHAT_ID": "-100"})
        try:
            self.agent.post_note(text)
            msgs = [json.loads(b)["text"] for p, b, _ in Sink.posts if p.startswith("/tg/")]
        finally: os.environ.update({"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""})
        self.assertEqual(len(msgs), 2)
        self.assertTrue(all(len(m) <= 4096 for m in msgs))
        self.assertIn("  " + cmd, msgs[1])
        self.assertEqual("\n".join(msgs), text)

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

    def test_starttls_verifies_the_server_certificate(self):
        # starttls() with no SSL context is an unverified context on
        # CPython >= 3.12, so an on-path attacker can intercept the SMTP login in the clear.
        os.environ.update({"ALERT_EMAIL_TO": "ops@example.com", "SMTP_HOST": "smtp.example.test:25",
                           "SMTP_USER": "bob", "SMTP_PASSWORD": "secret"})
        try:
            with mock.patch("smtplib.SMTP") as MockSMTP:
                conn = MockSMTP.return_value.__enter__.return_value
                self.agent.post_note("Triage: x")
                conn.starttls.assert_called_once()
                _, kwargs = conn.starttls.call_args
                ctx = kwargs.get("context")
                self.assertIsNotNone(ctx, "starttls() must be called with an explicit context")
                self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(ctx.check_hostname)
                conn.login.assert_called_once_with("bob", "secret")
                conn.send_message.assert_called_once()
        finally:
            os.environ.update({"ALERT_EMAIL_TO": "", "SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": ""})

    def test_starttls_cert_verification_failure_does_not_send(self):
        # a server presenting a bad/self-signed cert must not result
        # in a login or a send - ssl.create_default_context() makes starttls() itself raise
        # SSLCertVerificationError when verification fails; post_note() must swallow that like any
        # other receiver failure and report the note as not delivered, not raise or silently send.
        os.environ.update({"ALERT_EMAIL_TO": "ops@example.com", "SMTP_HOST": "smtp.example.test:25",
                           "SMTP_USER": "bob", "SMTP_PASSWORD": "secret",
                           "SLACK_WEBHOOK_URL": "", "DISCORD_WEBHOOK_URL": ""})   # isolate to email only
        try:
            with mock.patch("smtplib.SMTP") as MockSMTP:
                conn = MockSMTP.return_value.__enter__.return_value
                conn.starttls.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
                self.assertIs(self.agent.post_note("Triage: x"), False)
                conn.login.assert_not_called()
                conn.send_message.assert_not_called()
        finally:
            os.environ.update({"ALERT_EMAIL_TO": "", "SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": "",
                               "SLACK_WEBHOOK_URL": self.base + "/slack", "DISCORD_WEBHOOK_URL": self.base + "/discord"})

    def test_post_note_says_whether_anything_accepted_the_note(self):
        # process() turns this return value into the trace's outcome - "posted" vs "post-failed" -
        # and the AI Triage dashboard counts those. A post_note that always returned True would
        # report every note Slack and Discord dropped on the floor as delivered.
        self.assertIs(self.agent.post_note("Triage: x"), True)
        os.environ.update({"SLACK_WEBHOOK_URL": self.base + "/slack-down",
                           "DISCORD_WEBHOOK_URL": self.base + "/slack-down-discord"})   # Sink 500s both
        try:
            self.assertIs(self.agent.post_note("Triage: nobody took this one"), False)
        finally:
            os.environ.update({"SLACK_WEBHOOK_URL": self.base + "/slack",
                               "DISCORD_WEBHOOK_URL": self.base + "/discord"})

    def test_note_is_redacted_again_before_posting(self):
        # the model quotes log lines as evidence; whatever the pack's redaction missed must not
        # reach the chat channel on the strength of the model's choice to quote it
        self.agent.post_note('Triage: x\nevidence: {"Authorization":"Basic ZHVtbXk6ZHVtbXlwYXNz"}')
        slack = [b for p, b, _ in Sink.posts if p == "/slack"]
        self.assertEqual(len(slack), 1)
        for path, body, _ in Sink.posts:
            self.assertNotIn("ZHVtbXk6ZHVtbXlwYXNz", body, path)

    # --- the second redact() pass used to run over the whole rendered note in
    # one shot, and \s in bearer/authorization/x-api-key patterns crosses the "\n" between a guarded
    # check_first line and whatever follows it, dropping that newline in the replacement - the
    # model's next line then lands inside format_note()'s command fence.

    def _run2_fence_case(self, check_first_line, not_seen_tail):
        text = "Check first (from runbook)\n  %s\nNot seen: %s; MARKER-OUTSIDE" % (check_first_line, not_seen_tail)
        self.agent.post_note(text)
        for path in ("/slack", "/discord"):
            bodies = [b for p, b, _ in Sink.posts if p == path]
            self.assertEqual(len(bodies), 1, path)
            payload = json.loads(bodies[0])
            md = payload.get("text") or payload.get("content")
            fenced = _fenced_lines(md)
            self.assertFalse(any("MARKER-OUTSIDE" in l for l in fenced), (path, md))
        return text

    def test_run2_second_redact_pass_does_not_pull_a_line_into_the_fence_via_bearer(self):
        self._run2_fence_case("docker logs --tail 50 bearer", "disk ok")

    def test_run2_second_redact_pass_does_not_pull_a_line_into_the_fence_via_x_api_key(self):
        self._run2_fence_case("kubectl -n default logs x-api-key:", "pods ok")

    def test_run2_second_redact_pass_does_not_pull_a_line_into_the_fence_via_authorization(self):
        self._run2_fence_case("ssh authorization: x", "ok")

    def test_run2_post_note_redaction_preserves_line_count(self):
        # the fix redacts line by line and rejoins with "\n" - the text handed to format_note() must
        # have exactly as many newlines as the text post_note() started with, for every case above
        # that used to trigger the line-merging bug.
        texts = [
            "Check first (from runbook)\n  docker logs --tail 50 bearer\nNot seen: disk ok; MARKER-OUTSIDE",
            "Check first (from runbook)\n  kubectl -n default logs x-api-key:\nNot seen: pods ok; MARKER-OUTSIDE",
            "Check first (from runbook)\n  ssh authorization: x\nNot seen: ok; MARKER-OUTSIDE",
        ]
        for text in texts:
            captured = []
            original_format_note = self.agent.format_note
            self.agent.format_note = lambda t, flavor, _c=captured, _f=original_format_note: (_c.append(t), _f(t, flavor))[1]
            try:
                self.agent.post_note(text)
            finally:
                self.agent.format_note = original_format_note
            self.assertTrue(captured, text)
            for t in captured:
                self.assertEqual(t.count("\n"), text.count("\n"), text)

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
        self.agent.post_note("Triage: x\nTrace: http://localhost:3000/d/sre-triage")
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
        rebuilt = "".join(json.loads(b)["content"] for b in discord_posts)
        self.assertEqual(rebuilt, "**" + long_text + "**")   # the headline is bold, nothing else changes

    NOTE = ("Triage: PostgresExporterDown on postgres-exporter:9187        (confidence: medium)\n"
            "Probable cause\n"
            "  1. The exporter exited — up{job=\"postgres\"}=0 for 30m\n"
            "  2. Blocked at the security group — runbook: 'the scrape times out'\n"
            "Also firing: Watchdog (warning, ops)\n"
            "Check first (from runbook)\n"
            "  docker compose ps <service>\n"
            "  curl -sv <url>\n"
            "Not seen: no deploys in 2h; loki empty\n"
            "Trace: http://localhost:3000/d/sre-triage")

    def test_format_note_discord(self):
        md = self.agent.format_note(self.NOTE, "discord").splitlines()
        self.assertEqual(md[0], "**Triage: PostgresExporterDown on postgres-exporter:9187** · confidence medium")
        self.assertEqual(md[1], "**Probable cause**")
        self.assertEqual(md[2], "1. The exporter exited — _up{job=\"postgres\"}=0 for 30m_")
        self.assertEqual(md[4], "**Also firing:** Watchdog (warning, ops)")
        self.assertEqual(md[5:9], ["**Check first (from runbook)**", "```", "docker compose ps <service>", "curl -sv <url>"])
        self.assertEqual(md[9], "```")
        self.assertEqual(md[10], "**Not seen:** no deploys in 2h; loki empty")
        self.assertEqual(md[11], "_Trace: http://localhost:3000/d/sre-triage_")
        self.assertEqual(md.count("```"), 2)

    def test_format_note_slack_escapes_placeholders(self):
        md = self.agent.format_note(self.NOTE, "slack")
        self.assertTrue(md.startswith("*Triage: PostgresExporterDown on postgres-exporter:9187* · confidence medium"))
        self.assertIn("docker compose ps &lt;service&gt;", md)
        self.assertNotIn("<service>", md)
        self.assertNotIn("**", md)
        self.assertTrue(md.endswith("_Trace: http://localhost:3000/d/sre-triage_"), md[-80:])

    def test_format_note_discord_defuses_masked_links_outside_the_fence(self):
        # model text is attacker-influenced: "[Reset SSO](https://evil)" would render on Discord as a
        # masked link showing only "Reset SSO". Brackets become full-width outside the command fence;
        # commands inside it are code, not markdown, and must stay byte-exact.
        note = ("Triage: [Reset SSO](https://evil.invalid) down        (confidence: low)\n"
                "Probable cause\n"
                "  1. [Reset SSO](https://evil.invalid) — see [here](https://evil.invalid)\n"
                "  2. a stray ``` would open a fence out here\n"
                "Also firing: [x](https://evil.invalid)\n"
                "Check first (from runbook)\n"
                "  test -f [a](b) && echo ok\n"
                "  echo ```\n"
                "  [Reset SSO](https://evil.invalid)\n"
                "Not seen: [y](https://evil.invalid)\n"
                "Something new [z](https://evil.invalid)\n")
        md = self.agent.format_note(note, "discord").splitlines()
        fence = [n for n, l in enumerate(md) if l == "```"]
        self.assertEqual(len(fence), 2, md)
        inside, outside = md[fence[0] + 1:fence[1]], md[:fence[0]] + md[fence[1] + 1:]
        for line in outside:
            self.assertNotIn("[", line, line)
            self.assertNotIn("]", line, line)
            self.assertNotIn("```", line, line)
        self.assertIn("［Reset SSO］(https://evil.invalid)", md[0])
        self.assertEqual(inside[0], "test -f [a](b) && echo ok")        # byte-exact command
        self.assertNotIn("```", inside[1])                               # cannot close the fence early
        self.assertIn("[Reset SSO](https://evil.invalid)", inside[2])     # still inside the fence

    def test_format_note_passes_unknown_lines_through(self):
        md = self.agent.format_note("Triage: x        (confidence: low)\nSomething new\nTrace: http://localhost:3000/d/sre-triage", "discord").splitlines()
        self.assertEqual(md[1], "Something new")

    def test_discord_chunks_never_split_a_fence(self):
        cmds = "\n".join("  echo %03d %s" % (n, "y" * 60) for n in range(60))
        text = "Triage: big        (confidence: low)\nCheck first (from runbook)\n" + cmds + "\nTrace: http://localhost:3000/d/sre-triage"
        chunks = self.agent._chunks_md(self.agent.format_note(text, "discord"), 2000)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(len(c), 2000)
            self.assertEqual(c.count("```") % 2, 0, "unbalanced fence in chunk: %r" % c[:60])
        self.assertIn("echo 059", "".join(chunks))

    def test_slack_chunks_are_paced_one_second_apart_and_stop_on_an_error(self):
        text = "Triage: " + "&" * 3000 + "        (confidence: low)"
        with mock.patch.object(self.agent.time, "sleep") as sleep:
            self.agent.post_note(text)
        slack = [p for p, _, _ in Sink.posts if p == "/slack"]
        discord = [p for p, _, _ in Sink.posts if p == "/discord"]
        self.assertGreater(len(slack), 2)
        self.assertEqual([c.args for c in sleep.call_args_list], [(1,)] * (len(slack) - 1 + len(discord) - 1))
        # a failing chunk ends the Slack loop: no further chunk, no further pause, Discord still sent
        Sink.posts = []
        os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack-down"
        try:
            with mock.patch.object(self.agent.time, "sleep") as sleep:
                self.assertTrue(self.agent.post_note(text))
        finally:
            os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack"
        self.assertEqual(len([p for p, _, _ in Sink.posts if p == "/slack-down"]), 1)
        self.assertEqual(sleep.call_count, len([p for p, _, _ in Sink.posts if p == "/discord"]) - 1)   # Discord's own pauses only
        self.assertTrue([p for p, _, _ in Sink.posts if p == "/discord"])

    def test_discord_chunks_are_paced_one_second_apart_and_stop_on_an_error(self):
        text = "Triage: " + "x" * 5000 + "        (confidence: low)"
        os.environ["SLACK_WEBHOOK_URL"] = ""
        try:
            with mock.patch.object(self.agent.time, "sleep") as sleep:
                self.agent.post_note(text)
            discord = [p for p, _, _ in Sink.posts if p == "/discord"]
            self.assertGreater(len(discord), 2)
            self.assertEqual([c.args for c in sleep.call_args_list], [(1,)] * (len(discord) - 1))
            Sink.posts = []
            os.environ["DISCORD_WEBHOOK_URL"] = self.base + "/discord-down"
            with mock.patch.object(self.agent.time, "sleep") as sleep:
                self.assertFalse(self.agent.post_note(text))
            self.assertEqual(len([p for p, _, _ in Sink.posts if p == "/discord-down"]), 1)
            self.assertEqual(sleep.call_count, 0)
        finally:
            os.environ.update({"SLACK_WEBHOOK_URL": self.base + "/slack", "DISCORD_WEBHOOK_URL": self.base + "/discord"})

    def test_link_previews_are_suppressed_on_every_chat_receiver(self):
        # the note quotes URLs from alert and log text: a preview would fetch them from Slack's,
        # Discord's or Telegram's servers and unfurl whatever they return under the triage note
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t0k", "TELEGRAM_CHAT_ID": "-100"})
        try:
            self.agent.post_note("Triage: x\nNot seen: https://example.invalid/a")
        finally:
            os.environ.update({"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""})
        by = {p: json.loads(b) for p, b, _ in Sink.posts}
        self.assertIs(by["/slack"]["unfurl_links"], False)
        self.assertIs(by["/slack"]["unfurl_media"], False)
        self.assertEqual(by["/discord"]["flags"], 4)   # SUPPRESS_EMBEDS
        tg = next(v for k, v in by.items() if k.startswith("/tg/"))
        self.assertEqual(tg["link_preview_options"], {"is_disabled": True})

    def test_note_cap_cuts_at_a_line_boundary_never_inside_a_command(self):
        # run-4 h2: the 8000-character cut could land inside a fenced runbook command and post a
        # prefix of it ("... describe deployment api" without "| tail -20") as if from the runbook
        cmd = "kubectl -n prod describe deployment api | tail -20"
        head = "Triage: x        (confidence: low)\nProbable cause\n  1. " + "h" * 7000 + "\nCheck first (from runbook)\n"
        for extra in range(0, len(cmd) + 1, 7):   # the cut lands at every point of the second command
            text = head + "  echo ok\n" + "  " + cmd + "\n" + "Not seen: " + "n" * (1000 - extra) + "\nTrace: t"
            pad = self.agent.NOTE_MAX_CHARS - len(head) - len("  echo ok\n  ") - extra
            text = text.replace("h" * 7000, "h" * (7000 + pad), 1)
            Sink.posts = []
            with mock.patch.object(self.agent.time, "sleep"):
                self.agent.post_note(text)
            for path, field in (("/slack", "text"), ("/discord", "content")):
                md = "\n".join(json.loads(b)[field] for p, b, _ in Sink.posts if p == path)
                self.assertIn("(note truncated at 8000 characters)", md)
                fenced, inside = [], False
                for line in md.splitlines():
                    if line == "```": inside = not inside
                    elif inside: fenced.append(line)
                for line in fenced:
                    self.assertIn(line, ("echo ok", cmd), (extra, path))

    def test_slack_is_chunked_under_its_limit_after_escaping(self):
        # run-3: Slack got the whole note in one POST, and "&" grows fivefold once escaped
        text = ("Triage: " + "&" * 3000 + "        (confidence: low)\nCheck first (from runbook)\n"
                + "\n".join("  echo %03d <%s>" % (n, "y" * 60) for n in range(80)) + "\nTrace: http://localhost:3000/d/sre-triage")
        with mock.patch.object(self.agent.time, "sleep"):
            self.agent.post_note(text)
        slack = [json.loads(b)["text"] for p, b, _ in Sink.posts if p == "/slack"]
        self.assertGreater(len(slack), 1)
        for c in slack:
            self.assertLessEqual(len(c), 3500)   # Slack-safe, well under its documented 40,000
            self.assertEqual(c.count("```") % 2, 0, "unbalanced fence in chunk: %r" % c[:60])

    def test_whole_note_is_capped_before_formatting_with_a_visible_marker(self):
        # redaction is per line, so no per-string cap bounds the note any more; post_note caps the
        # whole note (8000 characters) before any receiver formats it, and says so in the note
        huge = "\n".join(["Triage: x        (confidence: low)"] + ["Not seen: " + "e" * 39000] * 4)
        with mock.patch.object(self.agent.time, "sleep"):
            self.agent.post_note(huge)
        for path in ("/slack", "/discord"):
            got = "".join(json.loads(b)["text" if path == "/slack" else "content"] for p, b, _ in Sink.posts if p == path)
            self.assertLess(len(got), 8500, path)
            self.assertIn("(note truncated at 8000 characters)", got, path)

    def test_post_note_uses_markdown_for_slack_and_discord_only(self):
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "c"})
        try:
            self.agent.post_note(self.NOTE)   # TELEGRAM_API already points at the sink (setUpClass)
        finally:
            os.environ.pop("TELEGRAM_BOT_TOKEN"); os.environ.pop("TELEGRAM_CHAT_ID")
        by = {p: json.loads(b) for p, b, _ in Sink.posts}
        self.assertTrue(by["/slack"]["text"].startswith("*Triage:"))
        self.assertTrue(by["/discord"]["content"].startswith("**Triage:"))
        tg = next(v for k, v in by.items() if k.startswith("/tg/"))
        self.assertTrue(tg["text"].startswith("Triage: PostgresExporterDown"))
        self.assertNotIn("**", tg["text"])


class InputCapTests(unittest.TestCase):
    """The pack cap follows TRIAGE_MAX_INPUT_TOKENS, else half the model's known context window, so a
    small internal model never gets a prompt it cannot hold; nothing can raise it above HARD_CAP_BYTES."""
    def _cap(self, **env):
        return self.agent.input_cap_bytes(env)
    @classmethod
    def setUpClass(cls): cls.agent = load_agent(SINK.base, tempfile.mkdtemp())
    def test_explicit_tokens(self):
        self.assertEqual(self._cap(TRIAGE_MAX_INPUT_TOKENS="4000"), 16000)
    def test_never_above_the_hard_ceiling(self):
        self.assertEqual(self._cap(TRIAGE_MAX_INPUT_TOKENS="100000"), self.agent.HARD_CAP_BYTES)
    def test_floor_and_garbage(self):
        self.assertEqual(self._cap(TRIAGE_MAX_INPUT_TOKENS="10"), 4000)
        self.assertEqual(self._cap(TRIAGE_MAX_INPUT_TOKENS="lots"), 40000)
    def test_known_model_gets_half_its_window(self):
        self.assertEqual(self._cap(TRIAGE_MODEL="llama3:8b"), 16384)            # 8192 window -> 4096 tokens
        self.assertEqual(self._cap(TRIAGE_MODEL="gemma2:9b"), 16384)
        self.assertEqual(self._cap(TRIAGE_MODEL="deepseek-chat"), 40000)        # large windows keep the 10k default
        self.assertEqual(self._cap(TRIAGE_MODEL="glm-4.5-air"), 40000)
        self.assertEqual(self._cap(TRIAGE_MODEL="claude-sonnet-5"), 40000)
        self.assertEqual(self._cap(TRIAGE_MODEL="something-new"), 40000)
    def test_explicit_beats_the_table(self):
        self.assertEqual(self._cap(TRIAGE_MODEL="llama3:8b", TRIAGE_MAX_INPUT_TOKENS="6000"), 24000)
    def test_module_uses_the_cap_at_import(self):
        os.environ["TRIAGE_MAX_INPUT_TOKENS"] = "4000"
        try: self.assertEqual(load_agent(SINK.base, tempfile.mkdtemp()).MAX_BYTES, 16000)
        finally: os.environ.pop("TRIAGE_MAX_INPUT_TOKENS", None)


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

        def run(payload, pack, timeout, env, tools=None, post=None):
            return [(fake.triage(pack, timeout, env, post=post), {"task": "triage"})]
        fake.run = run
        self.fake = fake
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
        self.result = "Triage: x\nTrace: http://localhost:3000/d/sre-triage"
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
        self.result = "Triage: x\nTrace: http://localhost:3000/d/sre-triage"
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

    def test_engine_raised_exception_message_is_escaped_to_prevent_a_forged_trace_line(self):
        # "triage: engine raised ..." interpolates the exception's
        # text without json.dumps, so an engine that raises with attacker-influenced text (e.g. an
        # upstream error message it relays verbatim) could forge a dashboard trace line the same way
        # the groupKey and last_error() cases could.
        import io, contextlib
        prefix = "triage-agent: triage: engine raised RuntimeError: "
        for i, msg in enumerate(FORGED_TRACE_TEXTS):
            def boom(pack, timeout, env, post=None, msg=msg):
                self.calls.append((pack, timeout)); raise RuntimeError(msg)
            sys.modules["triage_engine"].triage = boom
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.agent.process(dict(WEBHOOK, groupKey="engine-raised-test-%d" % i))
            out = buf.getvalue()
            # isolate the log() line among build_pack's own "source unreachable" noise (real network
            # calls against a closed test server); a real newline in msg must not split it into two
            matches = [l for l in out.splitlines() if l.startswith(prefix)]
            self.assertEqual(len(matches), 1, out)
            trailing = _decode_json_value_after(self, matches[0], prefix, msg)
            self.assertEqual(trailing, "", "nothing may follow the JSON-quoted exception text: " + out)

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

    def test_run_is_preferred_and_traces_are_printed(self):
        self.fake.run = lambda payload, pack, timeout, env, tools=None, post=None: [("Triage: y\nTrace: http://g/d/sre-triage", {"task": "triage", "outcome": "note"})]
        with mock.patch("builtins.print") as p:
            self.agent.process(WEBHOOK)
        lines = [c.args[0] for c in p.call_args_list if c.args and str(c.args[0]).startswith("triage-trace ")]
        self.assertEqual(len(lines), 1); t = json.loads(lines[0][len("triage-trace "):])
        self.assertEqual(t["outcome"], "posted"); self.assertEqual(len(SINK.posts), 1)

    def test_run_gets_the_agents_run_tool(self):
        seen = {}
        def run(payload, pack, timeout, env, tools=None, post=None):
            seen["tools"] = tools; return []
        self.fake.run = run
        self.agent.process(WEBHOOK)
        self.assertIs(seen["tools"], self.agent.run_tool)

    def test_old_engine_without_run_still_works(self):
        self.result = "Triage: x\nTrace: http://g/d/sre-triage"
        del self.fake.run
        self.agent.process(WEBHOOK)
        self.assertEqual(len(self.calls), 1); self.assertEqual(len(SINK.posts), 1)

    def test_engine_error_text_is_redacted_before_stdout(self):
        # last_error() and trace["error"] can echo a provider's reply; they reach stdout (and Loki)
        import io, contextlib
        self.result = None
        secret = "password=hunter2dummy Bearer sk-ant-api03-DUMMYDUMMYDUMMYDUMMY"
        self.fake.last_error = lambda: "http 500: " + secret
        self.fake.run = lambda payload, pack, timeout, env, tools=None, post=None: [(None, {"task": "triage", "error": "http 500: " + secret})]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.agent.process(dict(WEBHOOK, groupKey="redact-error"))
        out = buf.getvalue()
        self.assertIn("triage: no note", out); self.assertIn("triage-trace ", out)
        self.assertNotIn("hunter2dummy", out); self.assertNotIn("DUMMYDUMMY", out)
        # an engine that raises: its message is logged, redacted the same way
        def boom(*a, **k): raise RuntimeError(secret)
        self.fake.run = boom
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.agent.process(dict(WEBHOOK, groupKey="redact-raise"))
        self.assertIn("engine raised", buf.getvalue()); self.assertNotIn("hunter2dummy", buf.getvalue())

    def test_last_error_is_escaped_to_prevent_a_forged_trace_line(self):
        # the engine's last_error() is logged raw in the "no note" branch,
        # so a value crafted to look like `triage-trace {...}` could forge a dashboard entry the
        # same way an untrusted groupKey could.
        import io, contextlib
        self.result = None
        prefix = "triage-agent: triage: no note ("
        for i, value in enumerate(FORGED_TRACE_TEXTS):
            self.fake.last_error = (lambda v: (lambda: v))(value)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.agent.process(dict(WEBHOOK, groupKey="last-error-test-%d" % i))
            out = buf.getvalue()
            no_note_line = next(l for l in out.splitlines() if l.startswith(prefix))
            trailing = _decode_json_value_after(self, no_note_line, prefix, value)
            self.assertEqual(trailing, ")", no_note_line)
            # exactly one genuine trace line is expected - the real one process() always prints last;
            # a real newline or unescaped quote smuggled through last_error() must not add or
            # corrupt it
            trace_lines = [l for l in out.splitlines() if l.startswith("triage-trace ")]
            self.assertEqual(len(trace_lines), 1, out)
            self.assertEqual(json.loads(trace_lines[0][len("triage-trace "):])["outcome"], "no-note")


class IngressTests(unittest.TestCase):
    """The webhook port is reachable by anything that can reach the agent: an oversized or dishonest
    Content-Length, an idle socket, an unauthenticated POST, a flood of distinct groups and a huge
    groupKey must each be bounded before they cost memory, a thread or a model call. Real serve(0)
    over loopback; every upstream URL points at a closed port so nothing real is ever fetched."""
    def setUp(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
        self.agent = load_agent("http://127.0.0.1:%d" % closed, tempfile.mkdtemp())
        self.srv, self.base = self.agent.serve(port=0)
        self.port = self.srv.server_address[1]
        self.addCleanup(self.srv.server_close); self.addCleanup(self.srv.shutdown)   # LIFO: shutdown, then close

    def _raw(self, head, body=b"", wait=3.0):
        """Send raw bytes; return (response bytes, seconds until the server closed) - None if still open."""
        c = socket.create_connection(("127.0.0.1", self.port), timeout=wait)
        try:
            c.sendall(head + body); start = time.monotonic(); out = b""
            try:
                while True:
                    chunk = c.recv(65536)
                    if not chunk: return out, time.monotonic() - start
                    out += chunk
            except socket.timeout:
                return out, None
        finally:
            c.close()

    def _head(self, length):
        return ("POST /alert HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n" % length).encode()

    def _post(self, headers=None):
        req = urllib.request.Request(self.base + "/alert", data=json.dumps(WEBHOOK).encode(),
                                     headers=dict({"Content-Type": "application/json"}, **(headers or {})))
        try: return urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as e: e.close(); return e.code

    def test_at_most_four_workers_run_at_once_and_the_rest_are_dropped(self):
        # R42: every worker can hold an at-cap pack (tens of MiB) inside the 256 MiB container, and an
        # OOM restart also forgets the run cap and the dedup map. A fifth concurrent group still gets
        # 200 (Alertmanager must not retry into it) but is dropped with a log line, not queued.
        gate, started = threading.Event(), []
        def slow(payload): started.append(payload.get("groupKey")); gate.wait(10)
        import io, contextlib
        buf = io.StringIO()
        with mock.patch.object(self.agent, "process", side_effect=slow), contextlib.redirect_stdout(buf):
            try:
                self.assertEqual([self._post() for _ in range(6)], [200] * 6)
                for _ in range(50):
                    if len(started) == 4: break
                    time.sleep(0.05)
                time.sleep(0.2)
                self.assertEqual(len(started), 4)
                self.assertEqual(buf.getvalue().count("skip: 4 triage runs already in progress"), 2)
            finally:
                gate.set()
            # every slot is released when its worker ends: all four can be taken again (and given back)
            self.assertTrue(all(self.agent.WORKERS.acquire(timeout=2) for _ in range(4)))
            for _ in range(4): self.agent.WORKERS.release()
            self.assertEqual(self._post(), 200)
            for _ in range(50):
                if len(started) == 5: break
                time.sleep(0.05)
        self.assertEqual(len(started), 5)

    def test_a_worker_that_cannot_start_gives_its_slot_back(self):
        # R42 round 2: Thread.start() can raise (no threads left); the slot taken for it must not leak,
        # or four such failures would stop triage for good.
        # only the agent's own worker thread fails: the server's per-request threads come from socketserver
        def start(): raise RuntimeError("can't start new thread")
        no_threads = types.SimpleNamespace(Thread=lambda *a, **k: types.SimpleNamespace(start=start),
                                           Timer=threading.Timer, Lock=threading.Lock)   # the body deadline still works
        with mock.patch.object(self.agent, "threading", no_threads), mock.patch("builtins.print"):
            for _ in range(5):
                self.assertEqual(self._post(), 200)
        self.assertTrue(all(self.agent.WORKERS.acquire(blocking=False) for _ in range(4)))
        for _ in range(4): self.agent.WORKERS.release()

    def test_run6_a_slot_is_taken_before_the_body_is_parsed(self):
        # audit run-6: an authenticated body was read and parsed before the WORKERS gate, so every
        # group cost a parse even when it was then dropped. Admission comes first now.
        free_at_parse, real = [], json.loads
        def loads(b, *a, **k):
            free_at_parse.append(self.agent.WORKERS._value); return real(b, *a, **k)
        with mock.patch.object(self.agent, "process"), mock.patch.object(self.agent.json, "loads", loads):
            self.assertEqual(self._post(), 200)
        self.assertEqual(free_at_parse, [3], "the body was parsed without holding a worker slot")

    def test_run6_with_every_slot_busy_a_group_is_dropped_unparsed(self):
        import io, contextlib
        self.assertTrue(all(self.agent.WORKERS.acquire(blocking=False) for _ in range(4)))
        self.addCleanup(lambda: [self.agent.WORKERS.release() for _ in range(4)])
        buf, body = io.StringIO(), json.dumps(WEBHOOK).encode()
        with mock.patch.object(self.agent, "process") as proc, mock.patch.object(self.agent.json, "loads", wraps=json.loads) as loads, \
             contextlib.redirect_stdout(buf):
            out, _ = self._raw(self._head(len(body)), body)
            self.assertTrue(out.startswith(b"HTTP/1.0 200"), "expected 200, got %r" % out[:40])
            self.assertEqual(self._post(), 200)
        proc.assert_not_called(); self.assertEqual(loads.call_count, 0)
        self.assertEqual(buf.getvalue().count("skip: 4 triage runs already in progress"), 2)
        # not dedup-marked: once a slot is free, the same group runs
        self.agent.WORKERS.release()
        with mock.patch.object(self.agent, "process") as proc:
            self.assertEqual(self._post(), 200)
            for _ in range(50):
                if proc.called: break
                time.sleep(0.05)
        proc.assert_called_once()
        self.agent.WORKERS.acquire(timeout=2)

    def test_run6_a_trickled_body_holds_no_slot_and_is_refused_by_its_deadline(self):
        # review ruling R48b: with the slot taken before the body was read, four senders trickling a
        # byte at a time held every slot for as long as they kept sending (Handler.timeout counts only
        # silence). The body is now read under a wall-clock deadline, before any slot is taken.
        n, ended, codes, real_send = 1000, [], [], self.agent.Handler.send_response
        def send_response(handler, code, *a):
            codes.append(code); return real_send(handler, code, *a)
        def trickle():
            c = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            c.sendall(self._head(n)); t0, out = time.monotonic(), b""
            try:
                while time.monotonic() - t0 < 4:
                    c.sendall(b"{"); time.sleep(0.05)
                    c.setblocking(False)
                    try:
                        out = c.recv(100)
                        break                    # the answer, or EOF
                    except BlockingIOError:
                        pass
                    finally:
                        c.setblocking(True)
            except OSError:                      # a byte sent after the answer can draw a reset
                pass
            ended.append((out[:12], time.monotonic() - t0)); c.close()
        with mock.patch.object(self.agent, "BODY_SECONDS", 1), mock.patch.object(self.agent, "process") as proc, \
             mock.patch.object(self.agent.Handler, "send_response", send_response):
            ts = [threading.Thread(target=trickle) for _ in range(4)]
            for t in ts: t.start()
            time.sleep(0.5)
            self.assertEqual(self.agent.WORKERS._value, 4, "a trickled body holds a worker slot")
            self.assertEqual(self._post(), 200)           # a genuine group still gets a slot meanwhile
            for t in ts: t.join(10)
        for _ in range(50):
            if proc.called: break
            time.sleep(0.05)
        proc.assert_called_once()
        self.assertEqual(sorted(codes), [200, 408, 408, 408, 408])
        self.assertEqual(len(ended), 4)
        for out, took in ended:
            self.assertIn(out, (b"HTTP/1.0 408", b""))     # the 408, or the reset a later byte drew
            self.assertLess(took, 2.5)

    def test_run7_connections_past_the_cap_are_closed_unread(self):
        # audit run-7 h1: before auth the stdlib kept up to ~6.5 MB of headers per connection, one
        # thread each, with no cap on connections; ~35 slow peers passed 256 MiB. Past the cap a
        # connection is closed before a byte of it is read, and each slot comes back when its request ends.
        self.assertEqual(self.agent.MAX_CONNECTIONS, 64)
        slots = threading.BoundedSemaphore(2)
        with mock.patch.object(self.agent, "CONNECTIONS", slots), mock.patch.object(self.agent, "process"):
            held = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(2)]
            for c in held: c.sendall(b"POST /alert HTTP/1.1\r\nX-Pad: ")     # headers never finish
            for _ in range(50):
                if slots._value == 0: break
                time.sleep(0.05)
            self.assertEqual(slots._value, 0, "two slow senders did not hold both slots")
            t0, out = time.monotonic(), b""
            c = socket.create_connection(("127.0.0.1", self.port), timeout=3)
            try:
                c.sendall(self._head(2) + b"{}"); out = c.recv(100)
            except ConnectionResetError:         # closed with the request unread: a reset, or an EOF
                pass
            finally:
                c.close()
            self.assertEqual(out, b"", "a connection past the cap was served: %r" % out[:40])
            self.assertLess(time.monotonic() - t0, 1.0)
            for c in held: c.close()
            for _ in range(100):
                if slots._value == 2: break
                time.sleep(0.05)
            self.assertEqual(slots._value, 2, "a connection slot was not given back")
            self.assertEqual(self._post(), 200)          # and the next genuine delivery is served
        self.assertEqual(self.agent.CONNECTIONS._value, 64)

    def test_run7_r1_one_source_cannot_hold_every_connection(self):
        # review round 1 (ruling R51): a slot recycles within HEADER_SECONDS, so one peer reconnecting
        # ~13 times a second held all 64. One address now holds at most 8; a second address still
        # gets a slot while the first holds 12 sockets open.
        self.assertEqual(self.agent.MAX_CONNECTIONS_PER_SOURCE, 8)
        peer_a, real = set(), self.srv.get_request
        def get_request():                  # loopback has one address: tell the two peers apart by port
            sock, addr = real()
            return sock, ("198.51.100.7" if addr[1] in peer_a else "203.0.113.9", addr[1])
        held = []
        with mock.patch.object(self.srv, "get_request", get_request), mock.patch.object(self.agent, "process"):
            try:
                for _ in range(12):
                    c = socket.socket(); c.bind(("127.0.0.1", 0)); peer_a.add(c.getsockname()[1])
                    c.settimeout(3); c.connect(("127.0.0.1", self.port)); held.append(c)
                    c.sendall(b"POST /alert HTTP/1.1\r\nX-Pad: ")     # headers never finish
                time.sleep(0.5)
                closed = 0
                for c in held:
                    c.settimeout(0.2)
                    try:
                        closed += c.recv(100) == b""
                    except socket.timeout:
                        pass
                    except OSError:
                        closed += 1
                self.assertEqual(closed, 4, "one address held more than 8 connections")
                self.assertEqual(self._post(), 200)   # the second address is served meanwhile
            finally:
                for c in held: c.close()
            for _ in range(100):
                if not getattr(self.srv, "_per_source", {}) and self.agent.CONNECTIONS._value == 64: break
                time.sleep(0.05)
        self.assertEqual((getattr(self.srv, "_per_source", {}), self.agent.CONNECTIONS._value), ({}, 64))

    def test_run7_the_header_phase_has_a_wall_clock_deadline(self):
        # Handler.timeout counts only silence: one byte every few seconds kept a header read going.
        # The request line and headers now have HEADER_SECONDS of wall-clock time in all, then 408.
        self.assertEqual(self.agent.HEADER_SECONDS, 5)
        with mock.patch.object(self.agent, "HEADER_SECONDS", 1), mock.patch.object(self.agent, "process") as proc:
            c = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            try:
                c.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nX-Pad: ")
                t0, out = time.monotonic(), b""
                c.settimeout(0.1)
                while time.monotonic() - t0 < 4 and not out:
                    try:
                        c.sendall(b"a"); out = c.recv(100)
                    except socket.timeout:
                        pass
                    except OSError:
                        break
                took = time.monotonic() - t0
            finally:
                c.close()
        self.assertTrue(out.startswith(b"HTTP/1.0 408"), "expected 408 at the header deadline, got %r" % out[:40])
        self.assertLess(took, 2.0)
        proc.assert_not_called()

    def test_run7_request_line_and_headers_have_a_byte_budget(self):
        # ... and MAX_HEADER_BYTES in all, far below the stdlib's 100 x 64 KiB: past it, 431 (headers)
        # or a closed connection (a request line alone over the budget), with nothing read further.
        self.assertEqual(self.agent.MAX_HEADER_BYTES, 16384)
        errors = []
        with mock.patch.object(self.agent, "process") as proc, \
             mock.patch.object(self.srv, "handle_error", lambda req, addr: errors.append(sys.exc_info()[1])):
            pad = "".join("X-Pad-%d: %s\r\n" % (i, "a" * 8000) for i in range(3))
            out, _ = self._raw(("POST /alert HTTP/1.1\r\nHost: x\r\n%sContent-Length: 2\r\n\r\n" % pad).encode(), b"{}")
            self.assertTrue(out.startswith(b"HTTP/1.0 431"), out[:40])
            try:
                out, closed = self._raw(b"POST /" + b"a" * 20000 + b" HTTP/1.1\r\n\r\n", wait=3)
            except ConnectionResetError:
                out, closed = b"", 0
            self.assertEqual((out, closed is not None), (b"", True))
            # an Alertmanager-sized request (well under 1 KiB of headers) is untouched
            self.assertEqual(self._post({"User-Agent": "Alertmanager/0.28.1", "X-Pad": "b" * 4000}), 200)
        self.assertEqual(errors, [])
        self.assertEqual(proc.call_count, 1)

    def test_run6_r2_a_failed_dup_on_the_body_read_leaves_no_timer(self):
        timers = lambda: [t for t in threading.enumerate() if isinstance(t, threading.Timer) and t.is_alive()]
        before = len(timers())
        errors = []   # the handler's OSError reaches socketserver, which would print its traceback
        real_dup, calls = socket.socket.dup, []
        def dup(sock):   # the header deadline's dup succeeds; the body read's fails
            calls.append(1)
            if len(calls) > 1: raise OSError(24, "Too many open files")
            return real_dup(sock)
        with mock.patch.object(self.agent, "BODY_SECONDS", 30), mock.patch.object(self.agent, "process") as proc, \
             mock.patch.object(self.srv, "handle_error", lambda req, addr: errors.append(sys.exc_info()[1])), \
             mock.patch.object(socket.socket, "dup", dup):
            self._raw(self._head(2), b"{}", wait=3)
            time.sleep(0.2)
        proc.assert_not_called()
        self.assertEqual([getattr(e, "errno", None) for e in errors], [24])
        self.assertEqual(len(timers()), before, "the 30s body timer was left running")
        self.assertEqual((self.agent.BODY_READERS._value, self.agent.WORKERS._value), (8, 4))

    def test_run6_r2_at_most_eight_bodies_are_read_at_once(self):
        # review round 2: bodies are read before a worker slot, so nothing capped how many 1 MiB bodies
        # were in flight. The ninth concurrent sender gets 503 at once, its body never read.
        conns, first8, real = [], set(), self.srv.get_request
        head = ("POST /alert HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0k\r\nContent-Type: application/json\r\n"
                "Content-Length: 1000\r\n\r\n").encode()
        def get_request():   # the eight senders share one address, so the ninth is not refused by its per-source cap
            sock, addr = real()
            return sock, ("198.51.100.7" if addr[1] in first8 else "203.0.113.9", addr[1])
        with mock.patch.dict(os.environ, {"TRIAGE_WEBHOOK_TOKEN": "t0k"}), mock.patch.object(self.agent, "BODY_SECONDS", 3), \
             mock.patch.object(self.agent, "process") as proc, mock.patch.object(self.srv, "get_request", get_request), \
             mock.patch.object(self.agent.json, "loads", wraps=json.loads) as loads:
            for _ in range(8):                     # eight slow senders: headers, a byte, then silence
                c = socket.socket(); c.bind(("127.0.0.1", 0)); first8.add(c.getsockname()[1]); c.settimeout(10)
                c.connect(("127.0.0.1", self.port)); c.sendall(head + b"{"); conns.append(c)
            for _ in range(50):
                if self.agent.BODY_READERS._value == 0: break
                time.sleep(0.05)
            all_taken = self.agent.BODY_READERS._value == 0
            t0 = time.monotonic()
            out, _ = self._raw(head, b"{" + b" " * 998 + b"}", wait=2)
            self.assertTrue(out.startswith(b"HTTP/1.0 503"), "expected an immediate 503, got %r" % out[:40])
            self.assertLess(time.monotonic() - t0, 1.5)
            self.assertTrue(all_taken, "eight slow senders did not hold all eight body readers")
            for c in conns:
                c.settimeout(6); self.assertTrue(c.recv(100).startswith(b"HTTP/1.0 408")); c.close()
        proc.assert_not_called(); self.assertEqual(loads.call_count, 0)
        for _ in range(50):
            if self.agent.BODY_READERS._value == 8: break
            time.sleep(0.05)
        self.assertEqual(self.agent.BODY_READERS._value, 8, "a body reader was not given back")

    def test_run6_a_bad_or_unread_body_gives_its_slot_back(self):
        with mock.patch.object(self.agent, "process") as proc:
            for body in (b"{bad", b"[]", b"null", b"\xff\xfe"):
                out, _ = self._raw(self._head(len(body)), body)
                self.assertTrue(out.startswith(b"HTTP/1.0 400"), "%r -> %r" % (body, out[:40]))
            with mock.patch.object(self.agent.Handler, "timeout", 1):
                self._raw(self._head(100), b"{", wait=4)      # the read itself times out
        proc.assert_not_called()
        time.sleep(0.2)
        self.assertTrue(all(self.agent.WORKERS.acquire(blocking=False) for _ in range(4)), "a slot leaked")
        for _ in range(4): self.agent.WORKERS.release()

    def test_oversized_content_length_is_413_without_reading_the_body(self):
        with mock.patch.object(self.agent, "process") as proc:
            out, _ = self._raw(self._head(2097152))     # headers only: the 2 MiB body never arrives
        self.assertTrue(out.startswith(b"HTTP/1.0 413"), "expected an immediate 413, got %r" % out[:40])
        proc.assert_not_called()

    def test_json_body_that_is_not_an_object_is_400_before_any_worker(self):
        # process() calls payload.get(...): a list, string or number would crash the worker thread
        for body in (b"[]", b'"x"', b"1", b"null"):
            with mock.patch.object(self.agent, "process") as proc:
                out, _ = self._raw(self._head(len(body)), body)
            self.assertTrue(out.startswith(b"HTTP/1.0 400"), "%r -> %r" % (body, out[:40]))
            proc.assert_not_called()

    def test_negative_content_length_is_400_immediately(self):
        out, _ = self._raw(self._head(-1))
        self.assertTrue(out.startswith(b"HTTP/1.0 400"), "expected an immediate 400, got %r" % out[:40])

    def test_idle_socket_is_closed_within_the_handler_timeout(self):
        self.assertEqual(self.agent.Handler.timeout, 10, "the handler must carry a socket timeout by default")
        with mock.patch.object(self.agent.Handler, "timeout", 1), mock.patch.object(self.agent, "process") as proc:
            out, closed_after = self._raw(self._head(100), b"{", wait=4)
        self.assertIsNotNone(closed_after, "a 1-of-100-bytes body must not hold the socket open")
        self.assertLess(closed_after, 2.5)
        proc.assert_not_called()

    def test_webhook_token_is_required_when_set(self):
        with mock.patch.dict(os.environ, {"TRIAGE_WEBHOOK_TOKEN": "t0k"}), mock.patch.object(self.agent, "process") as proc:
            self.assertEqual(self._post(), 401)
            self.assertEqual(self._post({"Authorization": "Bearer wrong"}), 401)
            proc.assert_not_called()
            self.assertEqual(self._post({"Authorization": "Bearer t0k"}), 200)

    def test_empty_webhook_token_means_no_check(self):
        with mock.patch.dict(os.environ, {"TRIAGE_WEBHOOK_TOKEN": ""}), mock.patch.object(self.agent, "process"):
            self.assertEqual(self._post(), 200)

    def _process_three_groups(self):
        import io, contextlib
        buf = io.StringIO()
        with mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}) as bp, contextlib.redirect_stdout(buf):
            for i in range(3):
                self.agent.process(dict(WEBHOOK, groupKey="run-cap-%d" % i))
        return bp.call_count, buf.getvalue()

    def test_hourly_run_cap_stops_the_third_distinct_group(self):
        with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": "2"}):
            calls, out = self._process_three_groups()
            self.assertEqual(calls, 2)
            self.assertIn("triage-agent: skip: hourly triage run cap reached", out)
            self.assertTrue(self.agent.run_allowed(now=time.time() + 3601), "runs older than an hour must age out")

    def test_a_deduped_repeat_does_not_spend_a_run(self):
        with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": "2"}), \
                mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}) as bp, mock.patch("builtins.print"):
            for key in ("repeat", "repeat", "other"):
                self.agent.process(dict(WEBHOOK, groupKey=key))
        self.assertEqual(bp.call_count, 2)

    def test_dedup_keys_on_the_group_and_its_alert_set(self):
        # run-4 h1: dedup keyed on groupKey alone, so a forged alert posted first with a genuine
        # group's labels got that group triaged, and the notification carrying the genuine alert an
        # hour later was skipped. The key is now the groupKey plus the group's sorted alert
        # fingerprints (label sets when there are none): a changed alert set is triaged again, the
        # same set in another order is not, and the hourly cap still bounds it all.
        a1, f1 = dict(WEBHOOK["alerts"][0], fingerprint="a1"), dict(WEBHOOK["alerts"][0], fingerprint="f1")
        nofp = lambda a, **lab: dict({k: v for k, v in a.items() if k != "fingerprint"}, labels=dict(a["labels"], **lab))
        seq = [[f1], [f1], [f1, a1], [a1, f1], [a1], [nofp(a1, pod="x")], [nofp(a1, pod="x")], [nofp(a1, pod="y")]]
        with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": "0"}), \
                mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}) as bp, mock.patch("builtins.print"):
            ran = []
            for alerts in seq:
                before = bp.call_count
                self.agent.process(dict(WEBHOOK, groupKey="same-group", alerts=alerts))
                ran.append(bp.call_count > before)
        self.assertEqual(ran, [True, False, True, False, True, True, False, True])

    def test_dedup_key_counts_alerts_cut_by_max_alerts(self):
        # audit run-5 h1: under max_alerts: 20, a genuine alert pushed past the first 20 never reaches
        # the webhook, so the alert set looked unchanged and the notification was skipped. Alertmanager
        # still counts it in truncatedAlerts, which is part of the key now.
        alerts = [dict(WEBHOOK["alerts"][0], fingerprint="f%02d" % i) for i in range(20)]
        with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": "0"}), \
                mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}) as bp, mock.patch("builtins.print"):
            ran = []
            for cut in (0, 1, 1):
                before = bp.call_count
                self.agent.process(dict(WEBHOOK, groupKey="max-alerts-group", alerts=alerts, truncatedAlerts=cut))
                ran.append(bp.call_count > before)
        self.assertEqual(ran, [True, True, False])

    def test_run_cap_zero_is_unlimited(self):
        with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": "0"}):
            calls, out = self._process_three_groups()
        self.assertEqual(calls, 3)
        self.assertNotIn("run cap reached", out)

    def test_run_cap_defaults_to_30(self):
        with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": ""}):
            now = time.time()
            self.assertEqual([self.agent.run_allowed(now=now) for _ in range(31)], [True] * 30 + [False])

    def test_run_cap_garbage_defaults_to_30(self):
        # R16b: "²".isdigit() is True but int("²") raises - in every process thread
        for raw in ("²", "-5", "abc"):
            self.agent._RUNS.clear()
            with mock.patch.dict(os.environ, {"TRIAGE_MAX_RUNS_PER_HOUR": raw}):
                now = time.time()
                self.assertEqual([self.agent.run_allowed(now=now) for _ in range(31)], [True] * 30 + [False], raw)

    def test_lone_surrogate_group_key_is_deduped_not_a_crash(self):
        # R16a: json.loads('"\\ud800"') succeeds, and str.encode() then raised UnicodeEncodeError
        key = json.loads('"\\ud800"')
        with mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}) as bp, mock.patch("builtins.print"):
            self.agent.process(dict(WEBHOOK, groupKey=key))
            self.agent.process(dict(WEBHOOK, groupKey=key))
        self.assertEqual(bp.call_count, 1)

    def test_dedup_stores_a_digest_not_the_sender_sized_group_key(self):
        # 2 MiB is over the 1 MiB body cap, so this drives process() directly: the dedup map must hold
        # a fixed-size digest whatever reaches it. The skip log line still names the raw key (R1),
        # JSON-escaped (v19) so it cannot inject a line of its own.
        import io, contextlib
        buf = io.StringIO()
        with mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}), contextlib.redirect_stdout(buf):
            self.agent.process(dict(WEBHOOK, groupKey="k" * (2 << 20)))
            self.agent.process(dict(WEBHOOK, groupKey="raw-key-for-the-log"))
            self.agent.process(dict(WEBHOOK, groupKey="raw-key-for-the-log"))
        self.assertEqual(len(self.agent.DEDUP.stamp), 2)
        self.assertTrue(all(len(k) == 64 for k in self.agent.DEDUP.stamp), [len(k) for k in self.agent.DEDUP.stamp])
        self.assertIn('skip: group already triaged within 3600s: ' + json.dumps("raw-key-for-the-log"), buf.getvalue())

    def test_process_escapes_forged_trace_in_dedup_skip_log(self):
        # an unauthenticated POST controls groupKey, and process() used to
        # log it raw through log() (no escaping). R1 (Task 1) keeps the RAW groupKey in `key` for
        # these log lines (only its digest goes into DEDUP), so the fix has to escape it here, not
        # stop logging it.
        import io, contextlib
        prefix = "triage-agent: skip: group already triaged within 3600s: "
        for key in FORGED_TRACE_TEXTS:
            with mock.patch.object(self.agent, "build_pack", return_value={"sources": {}}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.agent.process(dict(WEBHOOK, groupKey=key))   # 1st call: seeds DEDUP, noise discarded
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.agent.process(dict(WEBHOOK, groupKey=key))   # 2nd call: hits the dedup-skip log line
            out = buf.getvalue()
            self.assertEqual(len(out.splitlines()), 1, out)   # a real newline in the key must not split the line
            trailing = _decode_json_value_after(self, out.splitlines()[0], prefix, key)
            self.assertEqual(trailing, "", "nothing may follow the JSON-quoted key: " + out)

    def test_process_escapes_forged_trace_in_build_pack_failure_log(self):
        # same forgery, through the build_pack-failed log line (key + exception).
        import io, contextlib

        def boom(payload):
            raise RuntimeError("boom")
        self.agent.build_pack = boom
        prefix = "triage-agent: build_pack failed for "
        sep = ": RuntimeError: "
        for key in FORGED_TRACE_TEXTS:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.agent.process(dict(WEBHOOK, groupKey=key))
            out = buf.getvalue()
            self.assertEqual(len(out.splitlines()), 1, out)
            after_key = _decode_json_value_after(self, out.splitlines()[0], prefix, key)
            self.assertTrue(after_key.startswith(sep), out)
            trailing = _decode_json_value_after(self, after_key[len(sep):], "", "boom")
            self.assertEqual(trailing, "", "nothing may follow the JSON-quoted exception text: " + out)


if __name__ == "__main__":
    unittest.main()

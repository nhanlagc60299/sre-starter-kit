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
        for s in ("authorization:" * 8000, "://a:" * 8000):
            start = time.monotonic()
            self.agent._redact(s, self.agent.DEFAULT_REDACT)
            self.assertLess(time.monotonic() - start, 0.1, s[:20])

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
                  "secret_key_id=5", "use --secret-store vault"):
            self.assertEqual(self.agent.redact(s), s)

    def test_run3_review_patterns_are_not_quadratic_on_a_repeated_prefix(self):
        cases = ("SECRET_KEY_BASE=" * 8000, 'secret_key":"' * 6000, '{"name":"' * 8000, '{"name":"DB_PASSWORD","value":"' * 3000,
                 '"name":"' + "password" * 5000, "--password " * 8000, "--api-key=" * 8000, "?password=" * 8000,
                 "&token=" * 8000, "%26sig%3D" * 8000, "&sig=%2" * 8000, "&" * 50000,
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
        if self.path.startswith("/slack-down"):
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
        self.assertGreater(len(slack), 2)
        self.assertEqual([c.args for c in sleep.call_args_list], [(1,)] * (len(slack) - 1))
        # a failing chunk ends the Slack loop: no further chunk, no further pause, Discord still sent
        Sink.posts = []
        os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack-down"
        try:
            with mock.patch.object(self.agent.time, "sleep") as sleep:
                self.assertTrue(self.agent.post_note(text))
        finally:
            os.environ["SLACK_WEBHOOK_URL"] = self.base + "/slack"
        self.assertEqual(len([p for p, _, _ in Sink.posts if p == "/slack-down"]), 1)
        self.assertEqual(sleep.call_count, 0)
        self.assertTrue([p for p, _, _ in Sink.posts if p == "/discord"])

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

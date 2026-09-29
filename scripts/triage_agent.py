#!/usr/bin/env python3
"""triage-agent: receives Alertmanager webhooks, gathers a context pack from the kit's own services,
redacts it, and either prints it (dry run, the default) or hands it to triage_engine (Pro) which asks
the Anthropic Messages API with your own key, and posts the returned note. Standard library only, on
purpose: anyone can read this file end to end and know exactly what leaves their network. Only GETs
against the kit's services."""
import base64, hashlib, heapq, hmac, http.client, itertools, json, os, re, socket, threading, time, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import triage_engine            # Pro ships scripts/triage_engine.py next to this file; free does not
except ImportError:
    triage_engine = None

SCHEMA_VERSION = 1
MAX_BYTES = 40000          # ~10k tokens; TRIAGE_MAX_INPUT_TOKENS overrides below (test code may lower this)
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
SLACK_CHUNK_CHARS = 3500     # per Slack post, after its &/</> escaping; Slack documents 40,000 as its limit
NOTE_MAX_CHARS = 8000        # the whole note, cut before any receiver formats it (a real note is ~1-2k)
FENCE_OPEN, FENCE_CLOSE = "```\n", "\n```"   # a code fence; format_note() puts only the runbook
                                              # commands inside one. Telegram gets no parse_mode, so
                                              # it never sees a fence - see post_note()'s telegram().
FENCE_CHARS = len(FENCE_OPEN) + len(FENCE_CLOSE)
ENV = os.environ.get
MAX_BODY = 1 << 20         # bytes; a webhook body over this is refused with 413 before any of it is read
MAX_UPSTREAM_BYTES = 8 << 20   # bytes read from one upstream response; past it, the response is refused
                               # unparsed (a model-chosen {__name__=~".+"} over 180m could be any size)
# The pack is what the model reads: cap it in tokens so an internal model with a small context window
# never gets a prompt it cannot hold. 4 bytes per token is conservative for ASCII JSON; the floor keeps
# a runbook and one rule in the pack; HARD_CAP_BYTES stays the never-exceed ceiling.
# Known context windows by model-name prefix (tokens). When TRIAGE_MAX_INPUT_TOKENS is unset, the pack
# gets at most half the window so the system prompt and the answer always fit; unknown models keep the
# 10k default. Vendors' own limits at the time of writing - a wrong entry only shrinks the pack.
CONTEXT_WINDOWS = [("claude-", 200000), ("gpt-5", 400000), ("gpt-4.1", 1000000), ("gpt-4o", 128000), ("o3", 200000), ("o4", 200000),
                   ("deepseek-reasoner", 128000), ("deepseek-chat", 128000), ("deepseek-v3", 128000), ("deepseek-r1", 128000),
                   ("glm-4.5", 128000), ("glm-4.6", 200000), ("glm-4-", 128000), ("glm-4", 128000), ("glm-z1", 128000),
                   ("qwen3", 128000), ("qwen2.5", 32768), ("llama-3.1", 128000), ("llama-3.3", 128000), ("llama3.1", 128000),
                   ("llama3", 8192), ("llama-3", 8192), ("mistral", 32768), ("mixtral", 32768), ("gemma", 8192), ("phi", 16000)]


def input_cap_bytes(env=None):
    """Bytes of pack the model may read: TRIAGE_MAX_INPUT_TOKENS, else half the model's known context
    window, else 10k tokens; 4 bytes per token is conservative for ASCII JSON; floored so a runbook
    and one rule always fit, ceilinged at HARD_CAP_BYTES, the never-exceed limit."""
    env = env or os.environ
    cap = env.get("TRIAGE_MAX_INPUT_TOKENS", "")
    tokens = int(cap) if cap.isdigit() and int(cap) > 0 else 0
    if not tokens:
        model = (env.get("TRIAGE_MODEL") or "").lower()
        window = next((w for prefix, w in CONTEXT_WINDOWS if model.startswith(prefix)), 0)
        tokens = min(10000, window // 2) if window else 10000
    return min(HARD_CAP_BYTES, max(4000, tokens * 4))


MAX_BYTES = input_cap_bytes()
# Discord (behind Cloudflare) rejects the default "Python-urllib/3.x" User-Agent with 403 error 1010,
# so every note to a Discord webhook was lost until the first live dogfood on 2026-09-19. Slack and
# Telegram do not care, but one identity on every outbound request is cheaper than remembering which.
USER_AGENT = "sre-starter-kit-triage-agent/1 (+https://github.com/nhanlagc60299/sre-starter-kit)"
TELEGRAM_API = "https://api.telegram.org/bot%s/sendMessage"
# Value matcher excludes whitespace/quote/comma/semicolon/close-paren so it stops at the end of a
# quoted JSON value or a comma-separated field instead of swallowing whatever follows.
_REDACT_VALUE = r'[^\s"\',;)]+'
# The secret-bearing field names the keyword rules below look for.
_KEYWORDS = (r"password|passphrase|passwd|pwd|(?<![A-Za-z0-9])pass|secret[_-]?key(?:[_-]?base)?|secret|token"
             r"|api[_-]?key|access[_-]?key"
             r"|private[_-]?key|client[_-]?secret|account[_-]?key|subscription[_-]?key|signature")
DEFAULT_REDACT = [
    # PEM first: the keyword rule below would otherwise eat "private_key=-----BEGIN" and leave the
    # body. The body class (base64, whitespace, a literal "\n" from a JSON log) stops at "-", so the
    # optional END group never makes it backtrack; a truncated key with no END still loses its body.
    (r"-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----[A-Za-z0-9+/=\s\\]{0,8192}(?:-----END [A-Z ]{0,32}PRIVATE KEY-----)?",
     "[private-key-redacted]"),
    # A whole PEM file base64-encoded once more (a Kubernetes Secret's data, a CI variable):
    # "LS0tLS1CRUdJTi" is base64 of "-----BEGIN". Bounded like the rule above.
    (r"LS0tLS1CRUdJTi[A-Za-z0-9+/]{0,8192}={0,2}", "[pem-redacted]"),
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
    #
    # The separator allows up to three backslashes before each quote (\"password\": ..., and the
    # doubly escaped \\\"password\\\": of JSON inside JSON inside JSON), and "=>" (Ruby hashes) as
    # well as ":"/"=". A value that opens with a quote runs to its own closing quote, stepping over
    # backslash escapes, so a ";", "," or escaped quote inside it no longer leaves a tail in the clear;
    # an unquoted value runs to whitespace, whatever it contains (over-redaction is the accepted
    # price), except that a query parameter (a name ending in the keyword, right after "?" or "&",
    # like ?password= or &X-Amz-Signature=) stops at the next "&" so the parameters after it survive;
    # that name prefix is lazy and bounded to 64 characters. "pass" alone is anchored on its left so
    # bypass=/compass= stay intact; the other keywords keep the old unanchored rule. Every value
    # branch is the last element and the quoted one's two alternatives share no character, so they
    # cannot backtrack. [ \t]*, not \s, so it can never cross a "\n" the way the bearer/
    # authorization/x-api-key patterns below do (post_note() redacts line by line precisely because
    # those three still can). Unbounded, not {0,16}: a value emitted with more than 16 spaces/tabs of
    # padding around the separator (a fixed-width log format, `column -t`) must still be redacted;
    # measured linear, since it only ever backtracks over the run of spaces actually present, not a
    # fixed worst case, and a run of spaces has none of the fixed keyword letters to restart a match at.
    (r'(?i)(?:([?&])([\w.-]{0,64}?))?(' + _KEYWORDS + r')(\\{0,3}["\']?[ \t]*(?:=>|[:=])[ \t]*\\{0,3}(["\'])?)(?(5)(?:\\.|(?!\5)[^\\\n])*|(?(1)[^\s&]+|\S+))',
     r"\1\2\3\4[redacted]"),
    # A name/value pair whose name says what the value is: a Kubernetes env entry, a parameter list
    # ({"name":"DB_PASSWORD","value":"..."}), also JSON-escaped (up to three backslashes before each
    # quote, like the keyword rule). The name contains password/passwd/secret/token, or ends in a
    # whole "key" segment (API_KEY, SECRET_KEY, ACCESS_KEY) - so MONKEY_COUNT, KEYCLOAK_URL and
    # CACHE_KEY_PREFIX keep their values. The value is the keyword rule's quoted body, stepping over
    # backslash escapes; it is the last element and its alternatives share no character. Anchored on
    # the literal "name" key, every other class bounded.
    (r'(?i)(\\{0,3}"name\\{0,3}"\s{0,16}:\s{0,16}\\{0,3}"'
     r'(?:[\w.-]{0,64}(?:password|passwd|secret|token)[\w.-]{0,64}|(?:[\w.-]{0,64}[_.-])?key)'
     r'\\{0,3}"\s{0,16},\s{0,16}\\{0,3}"value\\{0,3}"\s{0,16}:\s{0,16}\\{0,3}")(?:\\.|[^"\\\n])*',
     r"\1[redacted]"),
    # A PEM body that lost its -----BEGIN/END----- header/footer, or never had one in this log line -
    # "MII" is the DER SEQUENCE tag every RSA/EC/PKCS8 key or cert starts with once base64-encoded.
    # The rows after it follow across whitespace or a literal "\n"/"\r" (a JSON-escaped key on one
    # log line), and only real PEM rows count (audit run-4): exactly 64 characters, or 76 (MIME and
    # GNU base64's wrap, audit run-5) with no ".eyJ" after it (that is a JWT's header segment, which
    # the JWT rule below must see whole, audit run-6; a bare "." after a real last row, as in
    # "...row. retrying", still ends the row, audit run-7), or a final row of 4-76 with its "="
    # padding that ends the line or its value (a quote, comma, brace, bracket or a "." that is not
    # ".eyJ" after it: a key inside JSON or a YAML flow sequence, or the end of a sentence), in real
    # base64 shape (whole 4-character groups, then "xx==" or "xxx="). Any row may end the text itself
    # (loki_lines cuts a line at 300 characters, mid-row). One last row, padded or not, may also end
    # at whitespace with more text after it: taken once, outside the repeat, so at most one following word of that shape is over-redacted. A field name after the key ("databasePassword:",
    # "storageAccountKey=", "appPassword= x") is neither. These two rules run AFTER the keyword and
    # name/value rules (R42): a keyword's value is already "[redacted]", which no base64 row can eat,
    # and before that swap "password=" in front of a quote read as a padded final row. A keyword-named
    # field holding a PEM (private_key: MII...) loses its first row to the keyword rule, so the rule
    # also starts right after a "[redacted]" when a full 64-character row follows it. The
    # separator and the row share no character, each row's end is fixed by a bounded lookahead, and
    # nothing after the repeat can fail, so it never backtracks. The trailing "={0,2}" is the first
    # row's own padding.
    (r"(?:\bMII[A-Za-z0-9+/]{20,4096}|(?<=\[redacted\])(?=(?:\\[nr]|\s){1,8}[A-Za-z0-9+/]{64}(?:[A-Za-z0-9+/]{12})?(?![A-Za-z0-9+/=]|\.eyJ)))"
     r"(?:(?:\\[nr]|\s){1,8}(?:[A-Za-z0-9+/]{64}(?:[A-Za-z0-9+/]{12})?(?![A-Za-z0-9+/=]|\.eyJ)"
     r"|(?=[A-Za-z0-9+/=]{4,76}[ \t]{0,8}(?:\\[nr]|[\r\n\"',}\]]|\.(?!eyJ)|$))(?:[A-Za-z0-9+/]{4}){0,19}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])"
     r"|[A-Za-z0-9+/]{1,76}={0,2}\Z)){0,256}"
     r"(?:(?:\\[nr]|\s){1,8}(?:(?:[A-Za-z0-9+/]{4}){1,19}|(?:[A-Za-z0-9+/]{4}){0,18}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))(?=\s))?={0,2}",
     "[pem-redacted]"),
    # A lone base64 body line with no "MII" prefix of its own - a later line of a multi-line PEM once
    # the first has already matched above, or a body pasted without its first line. Exactly 64 base64
    # characters (PEM's own wrap width) containing at least one uppercase letter: that requirement is
    # what keeps a 64-character lowercase hex digest (sha256, common in ordinary logs) out of this.
    # Indentation (a YAML block) and a CRLF line end are allowed around it, and the indent is kept.
    (r"(?m)^([ \t]{0,64})(?=[^\n]{0,63}[A-Z])[A-Za-z0-9+/]{64}\r?$", r"\1[pem-redacted]"),
    # A secret passed as a command-line flag with spaces or tabs (--password x); "--password=x" is
    # also the keyword rule's. The flag must end at the separator, so --password-file/--token-ttl
    # stay intact.
    (r"(?i)(--(?:password|passwd|token|secret|api-key)[ \t=]+)\S+", r"\1[redacted]"),
    # The same keywords as an XML element name: <password>value</password>, <db_pass>value</db_pass>.
    (r"(?i)(<[\w.:-]{0,64}(?:" + _KEYWORDS + r")>)[^<]*", r"\1[redacted]"),
    # Same two keywords, but no ":"/"=" at all - `aws configure set aws_secret_access_key <value>`
    # and the matching session-token flag separate keyword and value with whitespace only. Restricted
    # to these two AWS-specific names on purpose: a whitespace separator on the bare password/secret/
    # token keywords above would redact ordinary prose ("password reset failed for user bob"). The
    # value itself is restricted to a secret-shaped run (base64-alphabet, 16+ chars) rather than
    # _REDACT_VALUE's "any non-whitespace run": _REDACT_VALUE alone would also redact "not set" or
    # "expired for role deploy" as if they were the secret. It is the last element (nothing follows
    # it to backtrack against), so {16,} is unbounded on the high end like the URL-password and
    # Negotiate-token values below, not capped.
    (r"(?i)(aws_secret_access_key|aws_session_token)([ \t]{1,16})[A-Za-z0-9/+=]{16,}", r"\1\2[redacted]"),
    (r"(?i)bearer\s+\S+", "Bearer [redacted]"),
    # Every quantifier from here on is bounded, except a last element a real credential can outgrow
    # (a Negotiate token runs to KBs): nothing follows it to backtrack for, and a bound there leaves
    # the credential's tail in the clear. The two below were "\S+\s+\S+" and "[^/\s:]+:[^@\s]+@": on
    # their own prefix repeated with no terminator ("authorization:" * 8000) each backtracked O(n^2) -
    # seconds of GIL on one webhook. Only the quantifiers changed; the classes stay, because narrowing
    # the URL one (say, excluding "/") stops redacting pa/ss passwords. The URL password bound is 1024,
    # not less: "@" follows it, so it cannot be unbounded, and a longer password is not redacted at all.
    (r"(?i)(?<![A-Za-z0-9])authorization:\s*\S{1,512}\s+\S+", "Authorization: [redacted]"),
    # quoted/escaped/"="-separated Authorization and Cookie values: "Authorization":"Basic ..." in a
    # JSON header dump, Cookie: a=1; b=2. The value runs to the closing quote or end of line. The
    # lookahead leaves a bare header the rule above already redacted (and whatever follows it) alone.
    (r"(?i)(?<![A-Za-z0-9])(authorization|cookie)(\\?[\"']?\s{0,16}[:=]\s{0,16}\\?[\"']?)(?!\s{0,16}\[redacted\])[^\"'\n]+",
     r"\1\2[redacted]"),
    (r"(?i)https?://hooks\.(?:slack\.com|discord(?:app)?\.com)/" + _REDACT_VALUE, "[webhook-url-redacted]"),
    # the DISCORD_WEBHOOK_URL form .env.example documents, and the Telegram bot token in its API URL
    (r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[^\s\"',;)]{1,512}", "[webhook-url-redacted]"),
    (r"(?i)api\.telegram\.org/bot[^/\s]{1,256}", "api.telegram.org/bot[redacted]"),
    (r"://[^/\s:]{1,256}:[^@\s]{1,1024}@", "://[redacted]@"),  # user:pass@ in URLs - must run before
    (r"://:[^@\s]{1,1024}@", "://[redacted]@"),               # the email pattern, or "user:pass@host"
                                                              # reads as an email and eats the hostname;
                                                              # the second is redis://:pass@ (no user)
    (r"(?i)x-api-key:\s*\S+", "x-api-key: [redacted]"),
    (r"sk-ant-[A-Za-z0-9_-]+", "[anthropic-key-redacted]"),
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[aws-key-redacted]"),
    (r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|xox[abprs]-[A-Za-z0-9-]{1,255}|sk-[A-Za-z0-9_-]{16,255}|sk_live_[A-Za-z0-9]{1,255})",
     "[token-redacted]"),
    # lookbehind, not \b: "-" is not \w, so "eyJ-eyJ-..." would give \b a start at every "eyJ" and each
    # would rescan the rest of the run. A literal "\n"/"\r"/"\t" in front (a JSON-escaped log line, the
    # PEM rule's own row separator) also starts one, though its "n" is \w (audit run-6).
    (r"(?:(?<![\w-])|(?<=\\[nrt]))eyJ[\w-]{1,4096}\.eyJ[\w-]{1,8192}\.[\w-]{0,2048}", "[jwt-redacted]"),
    # Signed-URL / SAS / STS query parameters: any parameter named *sig or *signature (Azure SAS
    # "sig=", AWS "X-Amz-Signature=", S3 SigV2 and CloudFront "Signature=", GCS "X-Goog-Signature="),
    # "X-Amz-Security-Token=", and a bare API key passed as "key=" (Google Maps and others) - the
    # separator before the keyword is a literal "?"/"&", its URL encodings "%3F"/"%26" (a signed URL
    # nested in a redirect parameter, where "=" is "%3D" too), or one of the
    # two shapes a "&" is commonly escaped into before it ever reaches this log line: the six literal
    # characters backslash-u-0-0-2-6 (Go's encoding/json HTML-escapes "&" by default) and "&amp;"
    # (HTML/XML entity encoding). Requiring that leading separator (in any of its forms) is what
    # keeps "keyboard=1" from matching the "key" alternative - "key" must be the whole parameter
    # name, not a prefix of it. The value excludes
    # "&"/"#" so it stops at the next parameter or fragment, but is otherwise unbounded: it is the
    # last element (nothing follows it to backtrack against), same as the URL-password and
    # Negotiate-token values above, not capped at some fixed length. It also stops at "%26", the next
    # parameter of a signed URL nested URL-encoded inside another one.
    (r"(?i)((?:[?&]|\\u0026|&amp;|%26|%3F)(?:[\w-]{0,64}sig(?:nature)?|x-amz-security-token|key)(?:=|%3D))(?:(?!%26)[^&\s\"'#])+", r"\1[redacted]"),
    # bounded quantifiers: an unbounded [\w.+-]+@[\w-]+\.[\w.-]+ backtracks O(n^2) on a long line with
    # an "@" but no "." after it (an attacker-controlled log line, easily tens of KB)
    (r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+", "[email]"),
]


def log(msg):
    """print() with the message's raw \\r/\\n escaped so it can never split into more than one
    stdout line - a second line could start with `triage-trace {`, which the AI Triage Grafana
    dashboard's scraper would mistake for a genuine trace. Untrusted
    values are additionally wrapped in json.dumps at the call site; do NOT also escape backslash
    here. json.dumps already turns every `"` into `\\"` and every `\\` into `\\\\`; re-escaping those
    backslashes a second time here would turn a `\\"` into `\\\\"`, which a JSON parser reads as an
    escaped backslash followed by an UNESCAPED quote - closing the string early and leaving the rest
    of the value as unquoted trailing text. A raw \\r/\\n is the only
    thing that can still split a line once the untrusted value has already been through json.dumps,
    since json.dumps itself turns any real \\r/\\n in the value into the two literal characters
    \\\\r/\\\\n - never an actual control character."""
    print("triage-agent: " + msg.replace("\r", "\\r").replace("\n", "\\n"), flush=True)


class Budget:
    """Monotonic deadline shared across every upstream call a single build_pack makes."""
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def remaining(self):
        return self.deadline - time.monotonic()


_TOO_LARGE = object()
# One upstream body is decoded and parsed at a time, process-wide (audit run-5): an 8 MiB body of
# attacker-shaped alert labels costs 109 MiB while it is a str plus a parse tree. Measured with the
# audit's section H (4 workers, attacker-shaped 8 MiB alert lists): 351 MiB VmHWM without this lock,
# against the 256 MiB limit. The network read happens before it, outside it, bounded by the call's
# own wall-clock deadline (_Deadline; audit run-6, review ruling R48): a socket timeout counts only
# silence between two recvs, so an upstream trickling a body, a header line or a chunk-size line held
# the lock for as long as it kept sending. The wait for the lock comes out of the same deadline, so
# a worker that waits too long counts the source as unreachable and build_pack keeps to its deadline.
_UPSTREAM = threading.Lock()
READ_CHUNK = 65536


class _Deadline:
    """A wall-clock bound on blocking socket reads. At `seconds` it shuts down every socket given to
    add(), and one added later at once: a read blocked on it returns EOF and its caller fails. It
    keeps a dup() of each socket, not the socket itself, so the owner's object is untouched and a TLS
    wrap made after add() (which detaches the original object) is still cut. cancel() stops the timer
    and closes the dups. `how` is SHUT_RDWR for an upstream, SHUT_RD where a reply must still go out."""
    def __init__(self, seconds, how=socket.SHUT_RDWR):
        self.how, self.socks, self.fired, self.lock = how, [], False, threading.Lock()
        self.timer = threading.Timer(max(0.0, seconds), self._fire)
        self.timer.daemon = True
        self.timer.start()

    def add(self, sock):
        d = sock.dup()
        with self.lock:
            self.socks.append(d)
            if self.fired:
                self._shut(d)
        return sock

    def _shut(self, s):
        try:
            s.shutdown(self.how)
        except OSError:
            pass

    def _fire(self):
        with self.lock:
            self.fired = True
            for s in self.socks:
                self._shut(s)

    def cancel(self):
        self.timer.cancel()
        with self.lock:
            for s in self.socks:
                s.close()
            self.socks = []


_WATCH = threading.local()   # .deadline: the _Deadline of the get_json call running on this thread


def _watched(cls):
    """An http.client connection class whose sockets join this thread's _Deadline as soon as TCP
    connects, before any TLS handshake or header byte is read. It swaps the connection's
    _create_connection, the attribute HTTPConnection.connect() opens its socket through (private,
    but the same since Python 3.4; HTTPSConnection.connect() goes through it too)."""
    def make(*a, **k):
        conn = cls(*a, **k)
        create = conn._create_connection
        def connect(*x, **y):
            sock, d = create(*x, **y), getattr(_WATCH, "deadline", None)
            try:
                return d.add(sock) if d else sock
            except BaseException:          # dup() can fail (EMFILE): the socket must not leak
                sock.close()
                raise
        conn._create_connection = connect
        return conn
    return make


class SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect to another origin is refused, not followed: urllib copies every request header to
    the new URL, so the Grafana Basic header (or the engine's API key) would go wherever a 302 points
    (audit run-6). A redirect within the same scheme, host and port is followed as before."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        def origin(u):
            p = urllib.parse.urlsplit(u)
            return p.scheme.lower(), (p.hostname or "").lower(), p.port or {"http": 80, "https": 443}.get(p.scheme.lower())
        if origin(req.full_url) != origin(urllib.parse.urljoin(req.full_url, newurl)):
            fp.close()                     # its body is never read; the error carries none
            raise urllib.error.HTTPError(req.full_url, code, "redirect to another origin refused", headers, None)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _WatchedHTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_watched(http.client.HTTPConnection), req)


class _WatchedHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_watched(http.client.HTTPSConnection), req, context=self._context)


_OPENER = urllib.request.build_opener(SameOriginRedirects, _WatchedHTTP, _WatchedHTTPS)


def get_json(url, headers=None, timeout=SOURCE_TIMEOUT):
    """GET and parse JSON; None on any failure, _TOO_LARGE for a body over MAX_UPSTREAM_BYTES, which
    is never parsed: at most one byte past the cap is ever read. The whole call, network, lock wait
    and parse, keeps to `timeout` of wall-clock time. Never raises: every source is optional."""
    try:
        req = urllib.request.Request(url, headers={**(headers or {}), "User-Agent": USER_AGENT})
        deadline = time.monotonic() + timeout
        _WATCH.deadline = guard = _Deadline(timeout)
        try:
            with _OPENER.open(req, timeout=timeout) as r:
                raw = bytearray()
                while len(raw) <= MAX_UPSTREAM_BYTES:
                    chunk = r.read1(min(READ_CHUNK, MAX_UPSTREAM_BYTES + 1 - len(raw)))   # one socket read
                    if not chunk:
                        break
                    raw += chunk
        finally:
            guard.cancel()
            _WATCH.deadline = None
        if len(raw) > MAX_UPSTREAM_BYTES:
            log("source response over %d bytes, not parsed: %s" % (MAX_UPSTREAM_BYTES, url.split("?")[0]))
            return _TOO_LARGE
        # A body the guard cut (a close-delimited one reads as a normal end) is refused, never parsed.
        # guard.fired says so directly: the Timer's clock and time.monotonic() are not the same clock
        # everywhere, so "no time left" alone could miss a cut that came early.
        left = deadline - time.monotonic()
        if guard.fired or left <= 0 or not _UPSTREAM.acquire(timeout=left):
            raise TimeoutError("no time left to parse: another upstream body is being parsed")
        try:
            text, raw = raw.decode(), None   # the bytes go before the parse tree is built
            return json.loads(text)
        finally:
            _UPSTREAM.release()
    except Exception as e:  # noqa: BLE001 - a dead upstream must not kill the triage
        if isinstance(e, urllib.error.HTTPError):
            e.close()
        log("source unreachable %s: %s" % (url.split("?")[0], e.__class__.__name__))
        return None


def fetch_json(budget, url, headers=None):
    """get_json against the shared deadline -> (data, "reached"), or (None, "unreachable") without a
    call once the budget is spent, or (None, "too-large"). Callers pass any status but "reached" on."""
    remaining = budget.remaining()
    if remaining <= 0:
        return None, "unreachable"
    d = get_json(url, headers, timeout=min(SOURCE_TIMEOUT, remaining))
    if d is _TOO_LARGE:
        return None, "too-large"
    return (None, "unreachable") if d is None else (d, "reached")


def combine(*statuses):
    """Merge the statuses of every call made against one logical endpoint (e.g. two /api/v1/query calls).
    'unreachable' wins even if another call to the same endpoint succeeded: a partial failure must not
    be reported as a clean "ok", or a consumer trusting sources[...] == "ok" would miss it."""
    statuses = [s for s in statuses if s]
    for pref in ("unreachable", "too-large", "ok", "empty"):
        if pref in statuses:
            return pref
    return "skipped"


def prom_url(path, **params):
    return ENV("PROMETHEUS_URL", "http://prometheus:9090") + path + ("?" + urllib.parse.urlencode(params) if params else "")


# What a fetcher keeps of a parsed upstream body is a bounded copy, never a reference into it (audit
# run-6): 30 kept alert-label dicts of ~25k short labels each held an 8 MiB body's worth of objects in
# every worker, outside the parse lock - 393-396 MiB VmHWM for 4 workers against the 256 MiB limit.
MAX_LABELS = 64          # per alert or series; the labels a reader needs first are kept first
MAX_FIELD_CHARS = 300    # per label name, label value or other scalar, like loki_lines' line cut
MAX_REFS = 10            # inhibitedBy, silencedBy, a deploy's tags
RULE_QUERY_CHARS = 4000  # a rule's PromQL is sent back to Prometheus, so it gets a longer cut
# A cut must never leave a secret's prefix that no pattern matches any more (audit run-7: a ghp_ token
# straddling the 300th character kept 9-19 of its characters, where the whole value was redacted
# before). So a value longer than its cut is redacted over its first n + CUT_REDACT_WINDOW characters
# and then cut. The window's own end is a cut too, and a secret redacted earlier in it shrinks, which
# pulls text from that end into the first n (review round 1: "password=" + 2315 characters, then a
# token, kept 19 of its characters). So nothing within CUT_REDACT_MARGIN of the window's end is ever
# kept: the margin is longer than any bounded pattern's reach (a URL's "://" + 256 + ":" + 1024 + "@"
# is the longest), and an unbounded one redacts whatever of a secret the window holds. Without a
# shrink the margin costs nothing (2048 - 1536 > 0); after a large one the value is shorter than n.
# One window at a time, so the copy is bounded like the cut.
CUT_REDACT_WINDOW = 2048
CUT_REDACT_MARGIN = 1536
_KEY_LABELS = ("__name__", "alertname", "severity", "instance", "job", "service", "namespace")


def _cut(v, n=MAX_FIELD_CHARS):
    """A scalar from an upstream body, as a new bounded value: a string cut to n (redacted first when
    it is longer, see CUT_REDACT_WINDOW), a number or None as it is."""
    if v is None or isinstance(v, (bool, int, float)):
        return v
    s = v if isinstance(v, str) else str(v)
    if len(s) <= n:
        return s
    r = redact(s[:n + CUT_REDACT_WINDOW])
    return r[:n] if len(s) <= n + CUT_REDACT_WINDOW else r[:min(n, max(0, len(r) - CUT_REDACT_MARGIN))]


def _labels(d):
    """At most MAX_LABELS labels, the _KEY_LABELS first, every name and value cut. A name that names a
    secret is tested whole, before its cut can drop the keyword it ends in (audit run-7)."""
    if not isinstance(d, dict):
        return {}
    keys = [k for k in _KEY_LABELS if k in d]
    keys += itertools.islice((k for k in d if k not in _KEY_LABELS), MAX_LABELS - len(keys))
    return {_cut(k): "[redacted]" if isinstance(k, str) and _SECRET_KEY.search(k) else _cut(d[k]) for k in keys}


def _refs(v):
    return [_cut(x) for x in v[:MAX_REFS]] if isinstance(v, list) else []


def rule_for(name, budget):
    d, st = fetch_json(budget, prom_url("/api/v1/rules", type="alert"))
    if st != "reached":
        return None, st
    if not isinstance(d, dict):        # an upstream returning the wrong shape is "empty", not a crash
        return None, "empty"
    for g in d.get("data", {}).get("groups", []):
        for r in g.get("rules", []):
            if r.get("name") == name:
                return {"query": _cut(r.get("query"), RULE_QUERY_CHARS), "health": _cut(r.get("health")), "group": _cut(g.get("name"))}, "ok"
    return None, "empty"


def series_now(expr, budget, limit=20):
    if not expr:
        return None, "skipped"
    d, st = fetch_json(budget, prom_url("/api/v1/query", query=expr))
    if st != "reached":
        return None, st
    if not isinstance(d, dict):
        return None, "empty"
    result = d.get("data", {}).get("result", [])[:limit]
    return [{"metric": _labels(x.get("metric", {})), "value": _cut(x["value"][1])} for x in result], ("ok" if result else "empty")


def series_range(expr, budget, limit=20, minutes=30):
    """query_range over the last `minutes`, step chosen so a series has ~60 points at most."""
    if not expr:
        return None, "skipped"
    now = time.time()
    step = max(60, minutes * 60 // 60)
    d, st = fetch_json(budget, prom_url("/api/v1/query_range", query=expr, start=now - minutes * 60, end=now, step=step))
    if st != "reached":
        return None, st
    if not isinstance(d, dict):
        return None, "empty"
    result = d.get("data", {}).get("result", [])[:limit]
    out = []
    for x in result:
        vals = [v[1] for v in x.get("values", [])]
        nums = [float(v) for v in vals if v not in ("NaN", "+Inf", "-Inf")]
        out.append({"metric": _labels(x.get("metric", {})), "points": len(vals),
                    "min": ("%g" % min(nums)) if nums else None, "max": ("%g" % max(nums)) if nums else None,
                    "first": _cut(vals[0]) if vals else None, "last": _cut(vals[-1]) if vals else None})
    return out, ("ok" if out else "empty")


def series_30m(expr, budget, limit=20):
    return series_range(expr, budget, limit, 30)


def loki_lines(query, budget, minutes=15, limit=50):
    """query_range on Loki, newest first, each line cut at 300 chars."""
    if not query:
        return [], "skipped"
    now_ns = time.time_ns()
    url = ENV("LOKI_URL", "http://loki:3100") + "/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": query, "start": now_ns - minutes * 60 * 10**9, "end": now_ns, "limit": limit, "direction": "backward"})
    d, st = fetch_json(budget, url, {"X-Scope-OrgID": "fake"})
    if st != "reached":
        return [], st
    if not isinstance(d, dict):
        return [], "empty"
    # the newest `limit`, without a list of every line the body holds (Loki's own limit is advisory here)
    lines = heapq.nlargest(limit, ({"ts": _cut(ts), "line": _cut(line)} for s in d.get("data", {}).get("result", [])
                                   for ts, line in s.get("values", [])), key=lambda x: x["ts"])
    return lines, ("ok" if lines else "empty")


def _q(value):
    """A label value as the inside of a PromQL/LogQL double-quoted string: backslash first, then quote."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def loki_errors(service, budget, limit=50):
    if not service:
        return [], "skipped"
    return loki_lines('{service="%s"} |~ "(?i)(error|exception|fatal|panic|traceback)"' % _q(service), budget, 15, limit)


def firing_alerts(budget, limit=30):
    d, st = fetch_json(budget, ENV("ALERTMANAGER_URL", "http://alertmanager:9093") + "/api/v2/alerts?active=true&silenced=true&inhibited=true")
    if st != "reached":
        return [], st
    if not isinstance(d, list):        # e.g. an error body like {"error": "..."} instead of the alert list
        return [], "empty"
    out = [{"labels": _labels(a.get("labels", {})), "startsAt": _cut(a.get("startsAt")), "state": _cut(a.get("status", {}).get("state")),
            "inhibitedBy": _refs(a.get("status", {}).get("inhibitedBy", [])), "silencedBy": _refs(a.get("status", {}).get("silencedBy", []))}
           for a in d[:limit]]
    return out, ("ok" if out else "empty")


def deploys(budget, limit=10, minutes=120):
    now_ms = int(time.time() * 1000)
    url = ENV("GRAFANA_URL", "http://grafana:3000") + "/api/annotations?" + urllib.parse.urlencode(
        {"tags": "deploy", "from": now_ms - minutes * 60 * 1000, "to": now_ms, "limit": limit})
    pw = ENV("GRAFANA_ADMIN_PASSWORD", "")
    hdr = {"Authorization": "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()} if pw else {}
    d, st = fetch_json(budget, url, hdr)
    if st != "reached":
        return [], st
    if not isinstance(d, list):
        return [], "empty"
    out = [{"time": _cut(a.get("time")), "tags": _refs(a.get("tags", [])), "text": _cut(a.get("text", ""))} for a in d[:limit]]
    return out, ("ok" if out else "empty")


def cap_lines(text, n=RUNBOOK_MAX_LINES):
    """Runbooks can run long; cap what leaves the box regardless of where it came from. Bounded on
    both axes: a line-count cap alone still lets one absurdly long unwrapped line (or a line with a
    pathological run of redact()-bait characters) through, so also hard-cap total characters."""
    lines = text.splitlines()
    capped = text if len(lines) <= n else "\n".join(lines[:n])
    return capped if len(capped) <= HARD_CAP_BYTES else capped[:HARD_CAP_BYTES]


def runbook(name):
    """Pro mounts runbooks/<Alert>.md; free has the matching ### section of docs/ALERTS.md. No network call, no budget.
    The name is sanitised here, not by each caller: build_pack passes an alert's own label value."""
    name = re.sub(r"[^A-Za-z0-9_]", "", str(name))[:80]
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


# A dict key that names a secret (a Prometheus or alert label called password, db_token, API_KEY):
# the patterns only ever see the value, never the key above it, so the value goes whole. The key must
# end in the keyword, like the keyword rule's separator requirement: max_tokens keeps its value.
_SECRET_KEY = re.compile(r"(?i)(?:" + _KEYWORDS + r")$")


def _blank(obj):
    """Everything under a secret-named key: every leaf replaced, whatever its type (audit run-5)."""
    if isinstance(obj, list):
        return [_blank(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _blank(v) for k, v in obj.items()}
    return "[redacted]"


def _redact(obj, pats):
    if isinstance(obj, str):
        obj = obj[:HARD_CAP_BYTES]   # one string bigger than the whole pack budget is never useful context
        for pat, rep in pats:
            obj = re.sub(pat, rep, obj)
        return obj
    if isinstance(obj, list):
        return [_redact(x, pats) for x in obj]
    if isinstance(obj, dict):
        return {k: _blank(v) if isinstance(k, str) and _SECRET_KEY.search(k) else _redact(v, pats)
                for k, v in obj.items()}
    return obj


# --- Tools: the Pro engine's way back into this box while it thinks (spec 3.1). The same fetchers
# build_pack uses, behind the same redaction, each result capped. Read-only by construction: no tool
# writes anything, and no argument ever reaches a shell - `expr`/`selector` go into a query string.
TOOL_MAX_BYTES = 6000   # per result, after redaction; the engine caps the whole conversation separately
TOOL_TIMEOUT = 5        # seconds per tool call, taken out of the run's remaining budget


def _int(args, key, default, cap):
    try:
        v = int(args.get(key, default))
    except (TypeError, ValueError):
        v = default
    return max(1, min(v, cap))


TOOLS = {
    "prom_query": lambda a, b: series_now(str(a.get("expr", ""))[:2000], b),
    "prom_range": lambda a, b: series_range(str(a.get("expr", ""))[:2000], b, minutes=_int(a, "minutes", 30, 180)),
    "loki_query": lambda a, b: loki_lines(str(a.get("selector", ""))[:2000], b, minutes=_int(a, "minutes", 15, 180), limit=_int(a, "limit", 50, 50)),
    "alerts":     lambda a, b: firing_alerts(b),
    "deploys":    lambda a, b: deploys(b, minutes=_int(a, "minutes", 120, 1440)),
    "runbook":    lambda a, b: runbook(a.get("alert", "")),
}
# loki_query: a stream selector followed only by line filters. Any other pipeline stage (| json,
# logfmt, line_format, label_format, regexp, pattern, unpack, ...) reshapes a line before redact()
# sees it - `| json | line_format "{{.password}}"` hands back a bare secret with no keyword left.
# The two string forms share no character with what follows them, so this cannot backtrack.
_LQ_STR = r'(?:"(?:[^"\\\n]|\\.)*"|`[^`]*`)'
_LQ_MATCHER = r'\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:=~|!~|!=|=)\s*' + _LQ_STR + r'\s*'
LOKI_SELECTOR = re.compile(r'\{' + _LQ_MATCHER + r'(?:,' + _LQ_MATCHER + r')*\}(?:\s*(?:\|=|!=|\|~|!~)\s*' + _LQ_STR + r')*')


def _refused(name, args):
    """Why a tool call's arguments are refused, or None. Checked before any network call."""
    if name == "loki_query" and not LOKI_SELECTOR.fullmatch(str(args.get("selector", ""))[:2000].strip()):
        return ("loki_query takes a stream selector {label=\"value\", ...} followed only by line filters "
                "(|= != |~ !~ with a quoted string); parsers, formatters and every other pipeline stage are refused")
    if name in ("prom_query", "prom_range") and re.search(r"(?i)label_(?:replace|join)", str(args.get("expr", ""))):
        return "label_replace and label_join are refused"
    return None


def run_tool(name, args, seconds):
    """One engine tool call -> (result, status). Unknown tool -> (None, "unknown"); non-dict args ->
    (None, "skipped"); no budget left -> (None, "unreachable") without a network call; a refused
    argument -> ({"error": why}, "refused"), also without one; a response over MAX_UPSTREAM_BYTES ->
    (None, "too-large"). The result is
    redacted like the pack and, past TOOL_MAX_BYTES of JSON, replaced by a marked sample."""
    fn = TOOLS.get(name)
    if fn is None:
        return None, "unknown"
    if not isinstance(args, dict):
        return None, "skipped"
    if seconds <= 0:
        return None, "unreachable"
    why = _refused(name, args)
    if why:
        return {"error": why}, "refused"
    result, status = fn(args, Budget(min(TOOL_TIMEOUT, seconds)))
    result = redact(result)
    s = json.dumps(result)
    if len(s) > TOOL_MAX_BYTES:
        result = {"truncated": True, "sample": s[:TOOL_MAX_BYTES]}
    return result, status


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
    pack["up"], up_status = series_now(('up{instance="%s"}' % _q(inst)) if inst else None, budget)
    pack["logs"], loki_status = loki_errors(labels.get("service") or labels.get("job"), budget)
    pack["firing"], am_status = firing_alerts(budget)
    pack["deploys"], grafana_status = deploys(budget)
    pack["runbook"], runbook_status = runbook(name)

    # a response over MAX_UPSTREAM_BYTES fails its source the way a dead one does
    pack["sources"] = {k: "unreachable" if v == "too-large" else v for k, v in {
        "alertmanager": am_status,
        "rules": rules_status,
        "query": combine(now_status, up_status),
        "query_range": range_status,
        "loki": loki_status,
        "grafana": grafana_status,
        "runbook": runbook_status,
    }.items()}
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
_RUNS, _RUNS_LOCK = [], threading.Lock()


def run_allowed(now=None):
    """Aggregate budget: at most TRIAGE_MAX_RUNS_PER_HOUR triage runs in any rolling hour (empty or
    garbage = 30, 0 = unlimited), so a flood of distinct groups cannot buy unbounded model calls."""
    raw = ENV("TRIAGE_MAX_RUNS_PER_HOUR", "")
    try:
        limit = int(raw)       # not str.isdigit(): "²".isdigit() is True and int("²") raises
    except ValueError:
        limit = 30
    if limit < 0:
        limit = 30
    if limit == 0:
        return True
    now = now or time.time()
    with _RUNS_LOCK:
        _RUNS[:] = [t for t in _RUNS if now - t < 3600]
        if len(_RUNS) >= limit:
            return False
        _RUNS.append(now)
        return True


def post_json(url, body, headers=None, timeout=45):
    """POST JSON to a receiver. The whole call keeps to `timeout` of wall-clock time, like get_json
    (audit run-7): a socket timeout counts only silence, so a receiver trickling its reply held a
    worker for as long as it kept sending. A reply the deadline cut raises TimeoutError."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {}), "User-Agent": USER_AGENT})
    _WATCH.deadline = guard = _Deadline(timeout)
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            status, reply = r.status, r.read(65536)   # a receiver's reply is never used
    finally:
        guard.cancel()
        _WATCH.deadline = None
    if guard.fired:
        raise TimeoutError("receiver reply cut at the %ss deadline" % timeout)
    return status, reply.decode("utf-8", "replace")


def _chunks(text, size):
    """Split plain text into <=size pieces so a long note still reaches a receiver (Telegram: 4096)
    instead of being rejected. Breaks at line boundaries, like _chunks_md, so no runbook command
    straddles two messages (audit run-5); only a single line longer than `size` is sliced."""
    chunks = []
    for line in text.split("\n"):
        for piece in (line[i:i + size] for i in range(0, max(len(line), 1), size)):
            if chunks and len(chunks[-1]) + 1 + len(piece) <= size:
                chunks[-1] += "\n" + piece
            else:
                chunks.append(piece)
    return [c for c in chunks if c] or [""]


def _fenced(chunk):
    """Wrap a chunk in a code fence. Kept for chunks that are not a triage note (see format_note)."""
    return FENCE_OPEN + chunk + FENCE_CLOSE


def format_note(text, flavor):
    """Turn the engine's fixed-shape plain note into Slack mrkdwn or Discord markdown: bold section
    heads, italic evidence, only the runbook commands in a code fence. One monospace block for the
    whole note read as a wall of text on Discord (owner feedback, 2026-09-19). The shape is what
    triage_engine.render() emits; a line that matches no known shape is kept as one plain line
    (whitespace trimmed, blank lines dropped), so a note from a newer engine degrades to plain
    lines, never to a lost post. Telegram and email
    keep the plain text: Telegram gets no parse_mode (an unescaped "_" would 400 the post)."""
    # three backticks anywhere in a line would close the command fence early (or open one outside
    # it), putting the lines after it back into live markdown. Only a hostile line has them.
    unfence = lambda t: re.sub(r"`{3,}", lambda m: "\u200b".join(m.group()), t)
    if flavor == "slack":
        b = lambda t: "*%s*" % t
        # Slack reads <, > and & as markup (links, mentions, entities): a runbook's `<service>`
        # placeholder would vanish into a link. Escape them everywhere, fence included.
        esc = lambda t: unfence(t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        cmd = esc
    else:
        b = lambda t: "**%s**" % t
        # Discord renders [label](url) as a masked link, so model text could show "Reset SSO" over
        # any URL. Full-width brackets outside the fence; commands inside it are code, not markdown,
        # and stay byte-exact so they can be copied and run.
        esc = lambda t: unfence(t).replace("[", "\uff3b").replace("]", "\uff3d")
        cmd = unfence
    i = lambda t: "_%s_" % t
    out, in_cmds = [], False
    for line in text.splitlines():
        st = line.strip()
        if not st:
            continue
        if in_cmds and line.startswith("  "):
            out.append(cmd(st)); continue
        if in_cmds:
            out.append("```"); in_cmds = False
        if st.startswith("Triage: "):
            m = re.match(r"^(Triage: .*?)\s+\(confidence: (\w+)\)$", st)
            out.append(b(esc(m.group(1))) + " · confidence " + m.group(2) if m else b(esc(st)))
        elif st == "Probable cause":
            out.append(b(st))
        elif re.match(r"^\d+\. ", st):
            head, sep, ev = st.partition(" — ")
            out.append(esc(head) + (" — " + i(esc(ev)) if sep else ""))
        elif st.startswith("Also firing: ") or st.startswith("Not seen: "):
            k, _, v = st.partition(": ")
            out.append(b(k + ":") + " " + esc(v))
        elif st == "Check first (from runbook)":
            out.append(b(st)); out.append("```"); in_cmds = True
        elif st.startswith("Trace: "):
            out.append(i(esc(st)))
        else:
            out.append(esc(st))
    if in_cmds:
        out.append("```")
    return "\n".join(out)


def _chunks_md(text, size):
    """Split formatted markdown at line boundaries, keeping every chunk under `size` and every code
    fence balanced: a fence cut in half would turn the rest of the message into monospace on
    Discord. A single line longer than `size` is sliced like _chunks does."""
    chunks, cur, in_fence = [], "", False
    def flush():
        nonlocal cur
        if cur: chunks.append(cur.rstrip("\n")); cur = ""
    for line in text.split("\n"):
        pieces = [line[i:i + size - 8] for i in range(0, len(line), size - 8)] or [""]
        for piece in pieces:
            add = piece + "\n"
            if len(cur) + len(add) + (4 if in_fence else 0) > size:
                if in_fence: cur += "```"
                flush()
                if in_fence: cur = "```\n"
            cur += add
            if piece.startswith("```"): in_fence = not in_fence
    flush()
    return chunks or [""]


def post_note(text):
    """Same channels Alertmanager uses, read from the same .env. Failures are logged, never retried
    into the alert channel: a noisy triage is worse than a missing one. Each receiver is attempted
    independently so one failing (or unconfigured) receiver never stops the others. Returns True if
    at least one receiver accepted the note."""
    # second pass: the model may quote anything the pack's redaction missed. Line by line, not
    # redact(text) over the whole note in one shot - a pattern whose \s crosses a "\n" (bearer,
    # authorization, x-api-key) drops that newline in its replacement, which used to merge the line
    # after a guarded check_first command into format_note()'s code fence.
    text = "\n".join(redact(l) for l in text.split("\n"))
    # redact() caps each line, not the note: bound the whole of it here, after redaction (so a cut can
    # never split a secret the patterns would have caught) and before any receiver formats it.
    # The cut is at the last line break before the cap, so a fenced runbook command is posted whole
    # or not at all, never as a prefix of itself; only a first line longer than the cap (the
    # headline, never a command) is cut mid-line.
    if len(text) > NOTE_MAX_CHARS:
        cut = text.rfind("\n", 0, NOTE_MAX_CHARS + 1)
        text = text[:cut if cut > 0 else NOTE_MAX_CHARS] + "\n(note truncated at %d characters)" % NOTE_MAX_CHARS
    oks = []
    def attempt(name, fn):
        try:
            fn(); log("posted to " + name); oks.append(True)
        except Exception as e:  # noqa: BLE001
            if isinstance(e, urllib.error.HTTPError):
                e.close()                                  # a receiver's error reply is never read
            log("post to %s failed: %s" % (name, e.__class__.__name__)); oks.append(False)
    if ENV("SLACK_WEBHOOK_URL"):
        def slack():
            # chunked like Discord, measured after escaping ("&" grows to "&amp;"); fences balanced.
            # One post per second, Slack's incoming-webhook rate. A failing chunk raises out of the
            # loop, so nothing after it is sent and attempt() logs it.
            for i, chunk in enumerate(_chunks_md(format_note(text, "slack"), SLACK_CHUNK_CHARS)):
                if i:
                    time.sleep(1)
                # no link or media unfurls: the note quotes URLs from alert and log text
                post_json(ENV("SLACK_WEBHOOK_URL"), {"text": chunk, "unfurl_links": False, "unfurl_media": False}, timeout=10)
        attempt("slack", slack)
    if ENV("DISCORD_WEBHOOK_URL"):
        def discord():
            # chunks break at line boundaries with balanced fences; if a chunk's POST fails, the loop
            # stops there and attempt() logs it - whatever already sent stays sent (a half note
            # beats none), nothing further is attempted. Paced like Slack, one post per second.
            # flags 4 is SUPPRESS_EMBEDS: no link previews of URLs the note quotes.
            for i, chunk in enumerate(_chunks_md(format_note(text, "discord"), DISCORD_CHUNK_CHARS)):
                if i:
                    time.sleep(1)
                post_json(ENV("DISCORD_WEBHOOK_URL"),
                          {"content": chunk, "allowed_mentions": {"parse": []}, "flags": 4}, timeout=10)
        attempt("discord", discord)
    if ENV("TELEGRAM_BOT_TOKEN") and ENV("TELEGRAM_CHAT_ID"):
        def telegram():
            # no fence and no parse_mode: unfenced because Telegram would render the fence as three
            # literal backtick lines instead of a code block, and parse_mode is deliberately not
            # used - an unescaped "_"/"*" in model text would make Telegram 400 the whole request
            # and lose the note entirely, which is worse than plain text.
            for chunk in _chunks(text, TELEGRAM_CHUNK_CHARS):
                post_json(TELEGRAM_API % ENV("TELEGRAM_BOT_TOKEN"),
                          {"chat_id": ENV("TELEGRAM_CHAT_ID"), "text": chunk,
                           "link_preview_options": {"is_disabled": True}}, timeout=10)
        attempt("telegram", telegram)
    if ENV("ALERT_EMAIL_TO") and ENV("SMTP_HOST"):
        def mail():
            import smtplib, ssl
            from email.message import EmailMessage
            m = EmailMessage()
            m["Subject"] = text.splitlines()[0][:120] if text else "Triage note"
            m["From"] = ENV("SMTP_FROM", ""); m["To"] = ENV("ALERT_EMAIL_TO"); m.set_content(text)
            host, _, port = ENV("SMTP_HOST").partition(":")
            with smtplib.SMTP(host, int(port or 587), timeout=10) as s:
                try:
                    # ssl.create_default_context() verifies the server certificate and hostname;
                    # starttls() with no context is an unverified context on CPython >= 3.12, which
                    # would hand the SMTP login to an on-path attacker.
                    s.starttls(context=ssl.create_default_context())
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
    return any(oks)


def _dedup_digest(payload, key):
    """The group plus the set of alerts in it (sorted fingerprints, or label sets where an alert has
    none) and how many alerts max_alerts cut from it. Keyed on the group alone, a forged alert posted
    first with a genuine group's labels got the group triaged and the genuine alert's notification
    skipped for an hour (audit run-4); now a changed alert set is triaged again, within the hourly run
    cap - including a genuine alert pushed past the first 20, which only truncatedAlerts shows (audit
    run-5). The dedup map outlives the request by an hour: it holds a fixed-size digest, never the
    sender-sized key."""
    alerts = payload.get("alerts")
    members = sorted(str(a.get("fingerprint") or json.dumps(a.get("labels"), sort_keys=True)) if isinstance(a, dict)
                     else json.dumps(a, sort_keys=True) for a in (alerts if isinstance(alerts, list) else []))
    return hashlib.sha256(json.dumps([key, members, payload.get("truncatedAlerts")]).encode("utf-8", "surrogatepass")).hexdigest()


def process(payload):
    key = payload.get("groupKey") or json.dumps(payload.get("groupLabels", {}), sort_keys=True)
    if DEDUP.seen(_dedup_digest(payload, key)):
        log("skip: group already triaged within %ds: %s" % (DEDUP_SECONDS, json.dumps(key))); return
    if not run_allowed():
        log("skip: hourly triage run cap reached"); return
    budget = Budget(TOTAL_TRIAGE_BUDGET)
    try:
        pack = build_pack(payload)
    except Exception as e:  # noqa: BLE001 - an upstream returning garbage must not kill this thread
        # DEDUP.seen() above already marked this key seen; on failure we deliberately leave that mark
        # in place rather than undo it, so a repeatedly-firing alert is skipped for DEDUP_SECONDS
        # instead of hammering a broken upstream on every Alertmanager repeat.
        log("build_pack failed for %s: %s: %s" % (json.dumps(key), e.__class__.__name__, json.dumps(redact(str(e))))); return
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
    run = getattr(triage_engine, "run", None)
    try:
        results = run(payload, pack, remaining, os.environ, tools=run_tool) if run else [(triage_engine.triage(pack, remaining, os.environ), {"task": "triage"})]
    except Exception as e:  # noqa: BLE001 - an engine bug must not kill this worker thread
        log("triage: engine raised %s: %s" % (e.__class__.__name__, json.dumps(redact(str(e))))); return
    for text, trace in results:
        if text:
            ok = post_note(text)
            trace["outcome"] = "posted" if ok else "post-failed"
        else:
            trace["outcome"] = "no-note"
            log("triage: no note (%s)" % json.dumps(redact(str(getattr(triage_engine, "last_error", lambda: "")()))))
        if trace.get("error"):   # it can quote a provider's reply; stdout is shipped to Loki
            trace["error"] = redact(str(trace["error"]))
        print("triage-trace " + json.dumps(trace, sort_keys=True), flush=True)


# At most this many process() workers at once, inside the container's 256 MiB: an OOM restart would
# also forget the hourly run cap and the dedup map. One attacker-shaped 8 MiB alert list costs 109 MiB
# while it is parsed, so get_json parses one body at a time (each worker may hold its own raw bytes,
# up to 8 MiB, while it waits) and every fetcher keeps only a bounded copy of what it parsed. VmHWM,
# 4 workers: 165 MiB, 351 MiB without the lock (audit run-5 section H, worst of 60 trials in three
# runs; see _UPSTREAM), and 143 MiB for 30 alerts of ~25k short labels each, 405 MiB while their
# labels were kept by reference (audit run-6, worst of 12; see MAX_LABELS). A group that arrives
# while every slot is busy is dropped with a log line, not queued: it is not marked triaged, so
# Alertmanager's next notification for it can still be triaged.
MAX_WORKERS = 4
WORKERS = threading.BoundedSemaphore(MAX_WORKERS)
# Webhook bodies are read before a worker slot is taken (so a slow sender cannot hold one), which left
# the number read at once unbounded. At most this many, each at most MAX_BODY: 8 MiB of body bytes in
# flight at once. A POST past it gets 503 with its body unread; Alertmanager retries it.
MAX_BODY_READERS = 8
BODY_READERS = threading.BoundedSemaphore(MAX_BODY_READERS)
# Before auth, the stdlib kept up to 100 header lines of 64 KiB per connection, one thread each, with
# no cap on connections and only an idle timeout: about 35 slow unauthenticated connections passed
# 256 MiB, and the OOM restart forgot the hourly run cap (audit run-7). Now every phase before auth is
# bounded by construction: at most MAX_CONNECTIONS requests in flight (one past it is closed unread),
# the request line and headers within HEADER_SECONDS of wall-clock time and MAX_HEADER_BYTES in all
# (past either, 408 or 431 and the connection closes). Alertmanager's webhook sends well under 1 KiB
# of headers. Measured: 64 connections each holding its full header budget add 3.1 MiB (0.05 MiB
# each, a thread and its deadline timer included), on top of the 165 MiB and the 8 MiB of bodies
# above: 176 MiB worst case, under the 192 MiB design bar (audit run-7, three runs, 100 peers each).
# One source address may hold at most MAX_CONNECTIONS_PER_SOURCE of them (review round 1, ruling
# R51): each slot recycles within HEADER_SECONDS, so one peer reconnecting ~13 times a second could
# otherwise hold all 64 and starve Alertmanager. 8, like the body readers: Alertmanager is one
# address, and past 8 at once its POSTs would wait for a body reader anyway; it retries a refused one.
MAX_CONNECTIONS = 64
MAX_CONNECTIONS_PER_SOURCE = 8
CONNECTIONS = threading.BoundedSemaphore(MAX_CONNECTIONS)
HEADER_SECONDS = 5
MAX_HEADER_BYTES = 16384


def _work(payload):
    try:
        process(payload)
    finally:
        WORKERS.release()


BODY_SECONDS = 5   # wall-clock seconds to read one webhook body; a 1 MiB body on a live link takes far less


class _HeaderBudget:
    """The request line and headers are read through this: MAX_HEADER_BYTES in all, then
    HTTPException, which parse_request answers with 431. The body is read from the socket file."""
    def __init__(self, f, left):
        self.f, self.left = f, left

    def readline(self, limit=-1):
        line = self.f.readline(self.left + 1 if limit < 0 else min(limit, self.left + 1))
        self.left -= len(line)
        if self.left < 0:
            raise http.client.HTTPException("request line and headers over %d bytes" % MAX_HEADER_BYTES)
        return line

    def __getattr__(self, name):
        return getattr(self.f, name)


class Handler(BaseHTTPRequestHandler):
    timeout = 10   # seconds of socket idle before the connection is dropped; a stalled sender cannot pin a thread

    def setup(self):
        super().setup()
        self._hdr = _Deadline(HEADER_SECONDS, socket.SHUT_RD)   # SHUT_RD, so a 408 still goes out
        try:
            self._hdr.add(self.connection)
        except BaseException:
            self._hdr.cancel()
            raise
        self.rfile = _HeaderBudget(self.rfile, MAX_HEADER_BYTES)

    def handle(self):
        try:
            super().handle()
        except http.client.HTTPException:   # a request line over the budget: nothing to answer, close
            pass

    def parse_request(self):
        try:
            ok = super().parse_request()
        finally:
            self._hdr.cancel()
            self.rfile = getattr(self.rfile, "f", self.rfile)
        if ok and self._hdr.fired:          # the deadline cut the headers: never act on part of them
            self.send_response(408); self.end_headers()
            return False
        return ok

    def finish(self):
        self._hdr.cancel()
        super().finish()

    def do_GET(self):
        self.send_response(200 if self.path == "/healthz" else 404); self.end_headers()

    def do_POST(self):
        if self.path != "/alert":
            self.send_response(404); self.end_headers(); return
        tok = ENV("TRIAGE_WEBHOOK_TOKEN", "")    # empty = no check, the pre-token behaviour
        if tok and not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + tok).encode()):
            self.send_response(401); self.end_headers(); return
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:                # refused before a single body byte is read
            self.send_response(413 if n > MAX_BODY else 400); self.end_headers(); return
        # The body's bytes are read under a wall-clock deadline, holding no worker slot: Handler.timeout
        # counts only silence, so a sender trickling a byte at a time kept the read going, and with
        # the slot taken first four such senders held every slot (audit run-6, ruling R48b).
        # SHUT_RD, so the 408 still goes out.
        # At most BODY_READERS bodies are read at once (review round 2): past that, 503 unread.
        if not BODY_READERS.acquire(blocking=False):
            self.send_response(503); self.end_headers(); return
        try:
            guard = _Deadline(BODY_SECONDS, socket.SHUT_RD)
            try:
                guard.add(self.connection)
                body = self.rfile.read(n)
            finally:
                guard.cancel()
        finally:
            BODY_READERS.release()
        if len(body) < n:
            self.send_response(408 if guard.fired else 400); self.end_headers(); return
        # Only then a slot, and no parse without one: with every slot busy the group gets 200
        # (Alertmanager retries on non-2xx) and is dropped unparsed, not dedup-marked, so its next
        # notification can still be triaged. Every other path gives the slot back.
        if not WORKERS.acquire(blocking=False):
            log("skip: %d triage runs already in progress" % MAX_WORKERS)
            self.send_response(200); self.end_headers(); return
        handed, status = False, 400
        try:
            try:
                payload = json.loads(body.decode() or "{}")
            except ValueError:
                payload = None
            if isinstance(payload, dict):                 # process() reads it as an object
                status = 200                              # Alertmanager retries on non-2xx; never make it wait
                try:
                    threading.Thread(target=_work, args=(payload,), daemon=True).start(); handed = True
                except Exception as e:  # noqa: BLE001 - no thread, no worker: the slot goes back below
                    log("triage worker could not start: %s" % e.__class__.__name__)
        finally:
            if not handed:                                # before any answer, so none outruns it
                WORKERS.release()
        self.send_response(status); self.end_headers()

    def log_message(self, *a): pass


class Server(ThreadingHTTPServer):
    """ThreadingHTTPServer with at most MAX_CONNECTIONS requests in flight, and at most
    MAX_CONNECTIONS_PER_SOURCE from one address: one past either is closed before a byte of it is
    read, and its slots come back when its request finishes."""
    def __init__(self, *a, **k):
        self._lock = threading.Lock()
        self._slots = {}                    # id(request) -> (the semaphore it took, its address)
        self._per_source = {}               # address -> requests in flight
        super().__init__(*a, **k)

    def process_request(self, request, client_address):
        slots, src = CONNECTIONS, client_address[0] if isinstance(client_address, tuple) else client_address
        with self._lock:
            ok = self._per_source.get(src, 0) < MAX_CONNECTIONS_PER_SOURCE and slots.acquire(blocking=False)
            if ok:
                self._per_source[src] = self._per_source.get(src, 0) + 1
                self._slots[id(request)] = (slots, src)
        if not ok:
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:               # no thread: the slots go back here
            self._release(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(request)

    def _release(self, request):
        with self._lock:
            slots, src = self._slots.pop(id(request))
            if self._per_source[src] > 1:
                self._per_source[src] -= 1
            else:
                del self._per_source[src]
        slots.release()


def serve(port=9096):
    srv = Server(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


if __name__ == "__main__":
    log("listening on :9096, dry_run=%s" % ENV("TRIAGE_DRY_RUN", "true"))
    Server(("0.0.0.0", 9096), Handler).serve_forever()

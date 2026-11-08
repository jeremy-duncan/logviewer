#!/usr/bin/env python3
"""
logviewer: read-only web interface for the *.log files on a syslog server.

Standard library only (Python 3.10+). No third-party packages.

Usage:
    logviewer.py [--config FILE] serve
    logviewer.py [--config FILE] adduser NAME
    logviewer.py [--config FILE] deluser NAME
    logviewer.py [--config FILE] check

What it does:
  * Finds every file ending in .log under the configured directory.
  * Shows the newest lines across the selected files, newest first.
  * Live mode streams new lines as they are written (Server-Sent Events).
  * Search is field based. Each line is parsed into fields (timestamp, host,
    program, pid, severity, facility, message, plus any key=value pairs found
    in the message), and the query can target any of them.
  * Dual stack: listens on IPv6 and IPv4 by default. TLS and HTTP Basic
    authentication (PBKDF2-SHA256 password hashes) are built in.
"""

import argparse
import base64
import calendar
import configparser
import errno
import getpass
import hashlib
import heapq
import hmac
import http.server
import itertools
import json
import os
import re
import secrets
import socket
import socketserver
import ssl
import stat
import sys
import threading
import time
import traceback
import urllib.parse

VERSION = "1.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DEFAULT_CONFIG = "/etc/logviewer/logviewer.conf"

MAX_LINE = 8192            # bytes kept per log line
BLOCK = 65536              # reverse-read block size
MAX_FILES = 5000
PBKDF2_ITERATIONS = 600000
MIN_PASSWORD_LEN = 15
AUTH_CACHE_SECONDS = 600
LOCKOUT_FAILURES = 5
LOCKOUT_SECONDS = 300
STREAM_POLL_SECONDS = 1.0
STREAM_PING_SECONDS = 15.0
STREAM_MAX_PER_POLL = 500

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
              "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console",
              "solaris-cron", "local0", "local1", "local2", "local3", "local4",
              "local5", "local6", "local7"]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path, explicit):
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict({
        "server": {"listen": "::", "port": "8443", "tls_cert": "", "tls_key": "",
                   "allow_plain_http": "no"},
        "logs": {"directory": "/var/log", "recursive": "yes", "include_names": ""},
        "auth": {"users_file": "/etc/logviewer/users"},
        "limits": {"max_results": "2000", "max_scan_lines": "5000000",
                   "search_timeout": "15", "max_streams": "20"},
    })
    if os.path.exists(path):
        cp.read(path)
    elif explicit:
        sys.exit("Config file not found: %s" % path)
    return cp


# ---------------------------------------------------------------------------
# Password storage and user database
# ---------------------------------------------------------------------------

def hash_password(password, iterations=PBKDF2_ITERATIONS):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password, stored):
    try:
        scheme, iters, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        want = base64.b64decode(hash_b64)
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(got, want)
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password(secrets.token_hex(8))


def read_users_file(path):
    users = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                name, stored = line.split(":", 1)
                users[name] = stored
    except FileNotFoundError:
        pass
    return users


def write_users_file(path, users):
    tmp = path + ".tmp"
    try:
        st = os.stat(path)
        mode, uid, gid = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o640, None, None
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for name in sorted(users):
            fh.write("%s:%s\n" % (name, users[name]))
    if uid is not None and os.geteuid() == 0:
        os.chown(tmp, uid, gid)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class Users:
    """Users file, reloaded automatically when it changes on disk."""

    def __init__(self, path):
        self.path = path
        self.mtime = None
        self.users = {}
        self.lock = threading.Lock()

    def get(self, name):
        with self.lock:
            try:
                mtime = os.stat(self.path).st_mtime_ns
            except OSError:
                self.users, self.mtime = {}, None
                return None
            if mtime != self.mtime:
                self.users = read_users_file(self.path)
                self.mtime = mtime
            return self.users.get(name)

    def count(self):
        self.get("")
        return len(self.users)


# ---------------------------------------------------------------------------
# Log file discovery
# ---------------------------------------------------------------------------

class LogIndex:
    def __init__(self, root, recursive, include_names):
        self.root = os.path.realpath(root)
        self.recursive = recursive
        self.include = set(n.strip().lstrip("/") for n in include_names.split(",") if n.strip())
        self.lock = threading.Lock()
        self.cache = {}
        self.stamp = 0.0

    def files(self):
        with self.lock:
            if time.monotonic() - self.stamp > 3.0:
                self.cache = self._scan()
                self.stamp = time.monotonic()
            return self.cache

    def _scan(self):
        out = {}
        root = self.root
        for dirpath, dirnames, filenames in os.walk(root):
            if not self.recursive:
                dirnames[:] = []
            dirnames.sort()
            for name in sorted(filenames):
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                if not (name.lower().endswith(".log") or rel in self.include):
                    continue
                real = os.path.realpath(path)
                if not (real == root or real.startswith(root + os.sep)):
                    continue  # symlink pointing outside the log directory
                try:
                    st = os.stat(real)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                out[rel] = {"id": rel, "path": real, "size": st.st_size,
                            "mtime": st.st_mtime, "readable": os.access(real, os.R_OK)}
                if len(out) >= MAX_FILES:
                    return out
        return out


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

RE_PRI = re.compile(r"^<(\d{1,3})>")
RE_5424 = re.compile(
    r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$", re.S)
RE_ISO = re.compile(
    r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?) (.*)$", re.S)
RE_BSD = re.compile(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) (.*)$", re.S)
RE_TAG = re.compile(r"^([^\s\[\]:]{1,64})(?:\[(\d+)\])?: ?(.*)$", re.S)
RE_KV = re.compile(r"""(?<![\w.\-])([A-Za-z_][\w.\-]{0,63})=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;]+)""")
RE_ISO_PARTS = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?(Z|[+-]\d\d:?\d\d)?$")


def parse_iso(stamp):
    m = RE_ISO_PARTS.match(stamp)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 62):
        return None
    frac, tz = m.group(7), m.group(8)
    try:
        if tz is None:
            ts = time.mktime((y, mo, d, h, mi, s, 0, 0, -1))
        else:
            off = 0
            if tz != "Z":
                digits = tz[1:].replace(":", "")
                off = (int(digits[:2]) * 3600 + int(digits[2:]) * 60) * (1 if tz[0] == "+" else -1)
            ts = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) - off
    except (ValueError, OverflowError):
        return None
    if frac:
        ts += float("0." + frac)
    return ts


def parse_bsd(mon, day, hms, now):
    m = MONTHS.get(mon)
    if not m:
        return None
    h, mi, s = (int(x) for x in hms.split(":"))
    year = time.localtime(now).tm_year
    try:
        ts = time.mktime((year, m, int(day), h, mi, s, 0, 0, -1))
        if ts > now + 86400:  # no year in the line: a future date means last year
            ts = time.mktime((year - 1, m, int(day), h, mi, s, 0, 0, -1))
    except (ValueError, OverflowError):
        return None
    return ts


def add_kv(fields, text):
    count = 0
    for m in RE_KV.finditer(text):
        key = m.group(1).lower()
        if key in fields:
            continue
        val = m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        fields[key] = val
        count += 1
        if count >= 60:
            break


def split_tag(fields, rest):
    m = RE_TAG.match(rest)
    if not m:
        return rest
    fields["program"] = m.group(1)
    if m.group(2):
        fields["pid"] = m.group(2)
    return m.group(3)


def parse_line(raw, file_id, now):
    """Return {'ts': epoch or None, 'f': {field: value}, 'raw': line}."""
    f = {"file": file_id}
    ts = None
    sd = None
    s = raw
    m = RE_PRI.match(s)
    if m:
        pri = int(m.group(1))
        if pri < 192:
            f["facility"] = FACILITIES[pri >> 3]
            f["severity"] = SEVERITIES[pri & 7]
        s = s[m.end():]
    m = RE_5424.match(s)
    if m:
        stamp, host, app, procid, msgid, sd, msg = m.groups()
        ts = parse_iso(stamp)
        f["timestamp"] = stamp
        for key, val in (("host", host), ("program", app), ("pid", procid), ("msgid", msgid)):
            if val != "-":
                f[key] = val
        if sd == "-":
            sd = None
        else:
            f["sd"] = sd
        msg = msg or ""
    else:
        m = RE_ISO.match(s)
        if m:
            stamp, rest = m.groups()
            ts = parse_iso(stamp)
            f["timestamp"] = stamp
            if "T" in stamp:  # rsyslog high-precision format: host and tag follow
                parts = rest.split(" ", 1)
                f["host"] = parts[0]
                msg = split_tag(f, parts[1]) if len(parts) > 1 else ""
            else:             # plain "date time text" application log
                msg = rest
        else:
            m = RE_BSD.match(s)
            if m:
                mon, day, hms, host, rest = m.groups()
                ts = parse_bsd(mon, day, hms, now)
                f["timestamp"] = s[:m.start(4)].strip()
                f["host"] = host
                msg = split_tag(f, rest)
            else:
                msg = s
    msg = msg.strip().lstrip("\ufeff")
    if msg:
        f["message"] = msg
        if "=" in msg:
            add_kv(f, msg)
    if sd:
        add_kv(f, sd)
    return {"ts": ts, "f": f, "raw": raw}


# ---------------------------------------------------------------------------
# Query language
#
#   text            substring anywhere in the line (case-insensitive)
#   field:text      field contains text
#   field=text      field equals text; * and ? are wildcards; field=* means "has field"
#   field~regex     field matches regular expression
#   -term           negation
#   "quoted text"   values with spaces
#   a b             AND        a OR b    OR between groups of ANDed terms
# ---------------------------------------------------------------------------

class QueryError(ValueError):
    pass


_TOKEN = re.compile(r"""
    (?P<neg>-)?
    (?:
        (?P<ip6>(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*)(?=\s|$)
      | (?P<field>[A-Za-z_][\w.\-]*)(?P<op>:(?!:)|[=~])(?P<fval>"(?:[^"\\]|\\.)*"|[^\s"]*)
      | (?P<quoted>"(?:[^"\\]|\\.)*")
      | (?P<bare>[^\s"]+)
    )
""", re.X)

DERIVED_FIELDS = {"file", "severity", "facility"}   # not present as text in the raw line


def _unquote(tok, regex=False):
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        if regex:   # keep backslashes (\d, \.) and only unescape the quote character
            return tok[1:-1].replace('\\"', '"')
        return re.sub(r"\\(.)", r"\1", tok[1:-1])
    return tok


class Term:
    __slots__ = ("neg", "op", "field", "value", "rx")

    def __init__(self, neg, op, field, value):
        self.neg, self.op, self.field = neg, op, field
        self.rx = None
        if op == "~":
            if len(value) > 200:
                raise QueryError("Regular expression is longer than 200 characters.")
            try:
                self.rx = re.compile(value, re.I)
            except re.error as exc:
                raise QueryError("Invalid regular expression: %s" % exc)
            self.value = value
        elif op == "=" and value != "*" and ("*" in value or "?" in value):
            pat = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c)
                          for c in value.lower())
            self.rx = re.compile("^" + pat + "$", re.S)
            self.op = "w"
            self.value = value.lower()
        else:
            self.value = value.lower()

    def test(self, fields, low):
        if self.field is None:
            return self.value in low
        fv = fields.get(self.field)
        if fv is None:
            return False
        if self.op == "~":
            return self.rx.search(fv) is not None
        if self.value == "*":
            return True
        fl = fv.lower()
        if self.op == ":":
            return self.value in fl
        if self.op == "w":
            return self.rx.match(fl) is not None
        return fl == self.value

    def prefilter_text(self):
        """Text that must appear (lowercased) in the raw line, or None."""
        if self.neg or self.op in ("~", "w") or not self.value or self.value == "*":
            return None
        if self.field in DERIVED_FIELDS:
            return None
        return self.value


class Query:
    def __init__(self, groups):
        self.groups = groups
        self.prefilters = [[t for t in (x.prefilter_text() for x in g) if t] for g in groups]
        self.match_all_prefilter = any(not p for p in self.prefilters)

    @classmethod
    def parse(cls, text):
        groups = [[]]
        pos, n = 0, len(text)
        while True:
            while pos < n and text[pos].isspace():
                pos += 1
            if pos >= n:
                break
            m = _TOKEN.match(text, pos)
            if not m or m.end() == pos:
                raise QueryError("Unbalanced quote or invalid term near: %s" % text[pos:pos + 24])
            pos = m.end()
            neg = m.group("neg") is not None
            if m.group("field"):
                value = _unquote(m.group("fval"), m.group("op") == "~")
                if value == "":
                    if text[pos:pos + 1] == '"':
                        raise QueryError("Unterminated quote after %s%s" % (m.group("field"), m.group("op")))
                    raise QueryError("Missing value after %s%s" % (m.group("field"), m.group("op")))
                term = Term(neg, m.group("op"), m.group("field").lower(), value)
            elif m.group("ip6"):
                term = Term(neg, ":", None, m.group("ip6"))
            elif m.group("quoted"):
                term = Term(neg, ":", None, _unquote(m.group("quoted")))
            else:
                bare = m.group("bare")
                if bare == "OR" and not neg:
                    if not groups[-1]:
                        raise QueryError("OR needs a term on both sides.")
                    groups.append([])
                    continue
                term = Term(neg, ":", None, bare)
            groups[-1].append(term)
        if len(groups) > 1 and not groups[-1]:
            raise QueryError("OR needs a term on both sides.")
        return cls(groups)

    def prefilter(self, low):
        if self.match_all_prefilter:
            return True
        for g in self.prefilters:
            if all(s in low for s in g):
                return True
        return False

    def matches(self, fields, low):
        for g in self.groups:
            ok = True
            for t in g:
                if t.test(fields, low) == t.neg:
                    ok = False
                    break
            if ok:
                return True
        return False


# ---------------------------------------------------------------------------
# Reading and searching files
# ---------------------------------------------------------------------------

def decode_line(b):
    return b[:MAX_LINE].decode("utf-8", "replace").rstrip("\r")


def reverse_lines(path):
    """Yield the lines of a file from the end to the start."""
    try:
        fh = open(path, "rb")
    except OSError:
        return
    with fh:
        try:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            tail = b""
            while pos > 0:
                step = BLOCK if pos >= BLOCK else pos
                pos -= step
                fh.seek(pos)
                parts = (fh.read(step) + tail).split(b"\n")
                tail = parts[0]
                for i in range(len(parts) - 1, 0, -1):
                    if parts[i]:
                        line = decode_line(parts[i])
                        if line:
                            yield line
            if tail:
                line = decode_line(tail)
                if line:
                    yield line
        except OSError:
            return


def scan_file(file_id, path, query, since, until, max_lines, deadline, stats, now):
    """Yield matching records from one file, newest first."""
    try:
        last_ts = os.stat(path).st_mtime
    except OSError:
        return
    need_ts = since is not None or until is not None
    scanned = 0
    older = 0
    try:
        for raw in reverse_lines(path):
            scanned += 1
            if scanned > max_lines:
                stats["truncated"] = True
                return
            if not scanned & 4095 and time.monotonic() > deadline:
                stats["truncated"] = True
                return
            low = raw.lower()
            passes = query.prefilter(low)
            if not passes and not need_ts:
                continue
            rec = parse_line(raw, file_id, now)
            ts = rec["ts"]
            if ts is None:
                ts = last_ts
            else:
                last_ts = ts
            rec["ts"] = ts
            if since is not None and ts < since:
                older += 1
                if older >= 2000:
                    return
                continue
            older = 0
            if until is not None and ts > until:
                continue
            if passes and query.matches(rec["f"], low):
                yield rec
    finally:
        stats["scanned"] += scanned


def run_search(files, query, since, until, limit, max_lines, timeout):
    stats = {"scanned": 0, "truncated": False}
    now = time.time()
    deadline = time.monotonic() + timeout
    per_file = max(200000, max_lines // max(1, len(files)))
    gens = [scan_file(fid, path, query, since, until, per_file, deadline, stats, now)
            for fid, path in files]
    try:
        records = list(itertools.islice(heapq.merge(*gens, key=lambda r: -r["ts"]), limit))
    finally:
        for g in gens:
            g.close()
    return records, stats


NO_VALUES = {"message", "timestamp", "sd"}


def sample_fields(files):
    """Summarize the fields seen in the most recent lines of the selected files."""
    now = time.time()
    names = {}
    total = 0
    for fid, path in files:
        gen = reverse_lines(path)
        for raw in itertools.islice(gen, 200):
            rec = parse_line(raw, fid, now)
            total += 1
            for k, v in rec["f"].items():
                entry = names.setdefault(k, [0, {}])
                entry[0] += 1
                if k in NO_VALUES:
                    continue
                vals = entry[1]
                v = v[:80]
                if v in vals:
                    vals[v] += 1
                elif len(vals) < 300:
                    vals[v] = 1
        gen.close()
        if total >= 6000:
            break
    out = []
    for k, (count, vals) in names.items():
        top = sorted(vals.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        out.append({"name": k, "count": count, "values": [[v, c] for v, c in top]})
    out.sort(key=lambda e: (-e["count"], e["name"]))
    return out[:60], total


def record_json(rec):
    return {"t": rec["ts"], "f": rec["f"], "raw": rec["raw"]}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.index = LogIndex(cfg["logs"]["directory"], cfg.getboolean("logs", "recursive"),
                              cfg["logs"]["include_names"])
        self.users = Users(cfg["auth"]["users_file"])
        self.max_results = cfg.getint("limits", "max_results")
        self.max_scan = cfg.getint("limits", "max_scan_lines")
        self.timeout = cfg.getfloat("limits", "search_timeout")
        self.streams = threading.BoundedSemaphore(cfg.getint("limits", "max_streams"))
        self.tls = False
        self.hostname = socket.gethostname()
        self.static = {}
        for route, (name, ctype) in STATIC_ROUTES.items():
            with open(os.path.join(STATIC_DIR, name), "rb") as fh:
                self.static[route] = (fh.read(), ctype)
        self.auth_key = secrets.token_bytes(32)
        self.auth_cache = {}
        self.fails = {}
        self.lock = threading.Lock()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, addr, handler, app, ssl_ctx=None):
        self.app = app
        self.ssl_ctx = ssl_ctx
        self.address_family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        super().__init__(addr, handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # dual stack
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = self.server_address[1]

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.ssl_ctx:
            sock = self.ssl_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, socket.timeout, BrokenPipeError)):
            return
        sys.stderr.write("error handling request from %s: %s\n" % (client_address[0], exc))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30
    user = None

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(self.timeout)
            self.request.do_handshake()
        super().setup()

    def version_string(self):
        return "logviewer"

    def log_request(self, code="-", size="-"):
        path = urllib.parse.urlsplit(self.path).path
        sys.stderr.write("%s user=%s %s %s %s\n" % (
            self.client_address[0], self.user or "-", self.command, path, code))

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

    # -- responses ---------------------------------------------------------

    def common_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if self.server.app.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def send_body(self, status, body, ctype, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.common_headers()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status=200, extra=None):
        self.send_body(status, json.dumps(obj, separators=(",", ":")).encode("utf-8"),
                       "application/json; charset=utf-8", extra)

    def send_error_json(self, status, message, extra=None):
        self.send_json({"error": message}, status, extra)

    # -- authentication ----------------------------------------------------

    def authenticate(self):
        app = self.server.app
        ip = self.client_address[0]
        now = time.time()
        with app.lock:
            rec = app.fails.get(ip)
            if rec and rec[1] > now:
                wait = str(int(rec[1] - now) + 1)
                locked = True
            else:
                locked = False
        if locked:
            self.send_error_json(429, "Too many failed sign-ins. Try again later.",
                                 {"Retry-After": wait})
            return False
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            digest = hmac.new(app.auth_key, header.encode("utf-8"), hashlib.sha256).digest()
            with app.lock:
                cached = app.auth_cache.get(digest)
            if cached and cached[1] > now:
                self.user = cached[0]
                return True
            try:
                name, password = base64.b64decode(header[6:], validate=True).decode("utf-8").split(":", 1)
            except (ValueError, UnicodeDecodeError):
                name = password = None
            if name is not None:
                stored = app.users.get(name)
                ok = verify_password(password, stored if stored else DUMMY_HASH) and bool(stored)
                if ok:
                    with app.lock:
                        app.fails.pop(ip, None)
                        if len(app.auth_cache) > 1000:
                            app.auth_cache = {k: v for k, v in app.auth_cache.items() if v[1] > now}
                        app.auth_cache[digest] = (name, now + AUTH_CACHE_SECONDS)
                    self.user = name
                    return True
                sys.stderr.write("%s failed sign-in for user %s\n" % (ip, json.dumps(name[:64])))
                with app.lock:
                    count, window = app.fails.get(ip, (0, now))
                    if now - window > LOCKOUT_SECONDS:
                        count, window = 0, now
                    count += 1
                    if count >= LOCKOUT_FAILURES:
                        app.fails[ip] = (0, now + LOCKOUT_SECONDS)   # (count, locked until)
                    else:
                        app.fails[ip] = (count, window)
        self.send_error_json(401, "Authentication required.",
                             {"WWW-Authenticate": 'Basic realm="logviewer", charset="UTF-8"'})
        return False

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        try:
            if not self.authenticate():
                return
            url = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(url.query)
            app = self.server.app
            if url.path in app.static:
                body, ctype = app.static[url.path]
                self.send_body(200, body, ctype)
            elif url.path == "/api/files":
                self.api_files()
            elif url.path == "/api/search":
                self.api_search(params)
            elif url.path == "/api/fields":
                self.api_fields(params)
            elif url.path == "/api/stream":
                self.api_stream(params)
            else:
                self.send_error_json(404, "Not found.")
        except (BrokenPipeError, ConnectionError, socket.timeout, ssl.SSLError):
            self.close_connection = True
        except QueryError as exc:
            self.send_error_json(400, str(exc))
        except Exception:
            traceback.print_exc()
            self.send_error_json(500, "Internal error. See the service log.")

    def method_not_allowed(self):
        self.send_error_json(405, "Method not allowed.", {"Allow": "GET"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = method_not_allowed

    # -- helpers -----------------------------------------------------------

    def select_files(self, params):
        index = self.server.app.index.files()
        wanted = params.get("file", [])
        if wanted:
            chosen = [(i, index[i]["path"]) for i in wanted if i in index and index[i]["readable"]]
        else:
            chosen = [(i, v["path"]) for i, v in index.items() if v["readable"]]
        if not chosen:
            raise QueryError("No readable log files are selected.")
        return chosen

    def parse_query(self, params):
        return Query.parse(params.get("q", [""])[0])

    # -- API ---------------------------------------------------------------

    def api_files(self):
        app = self.server.app
        files = [{"id": v["id"], "size": v["size"], "mtime": v["mtime"], "readable": v["readable"]}
                 for v in app.index.files().values()]
        self.send_json({"host": app.hostname, "directory": app.index.root, "files": files,
                        "now": time.time()})

    def api_search(self, params):
        app = self.server.app
        query = self.parse_query(params)
        files = self.select_files(params)
        try:
            limit = max(1, min(int(params.get("limit", ["500"])[0]), app.max_results))
            last = int(params["last"][0]) if "last" in params else None
            since = float(params["since"][0]) if "since" in params else None
            until = float(params["until"][0]) if "until" in params else None
        except ValueError:
            raise QueryError("limit, last, since and until must be numbers.")
        if last:
            since = time.time() - last
        sys.stderr.write("%s user=%s search q=%s files=%d\n" % (
            self.client_address[0], self.user, json.dumps(params.get("q", [""])[0][:300]), len(files)))
        started = time.monotonic()
        records, stats = run_search(files, query, since, until, limit, app.max_scan, app.timeout)
        self.send_json({
            "records": [record_json(r) for r in records],
            "files": len(files),
            "scanned": stats["scanned"],
            "truncated": stats["truncated"],
            "limit_reached": len(records) >= limit,
            "elapsed": round(time.monotonic() - started, 3),
        })

    def api_fields(self, params):
        fields, total = sample_fields(self.select_files(params))
        self.send_json({"fields": fields, "sampled_lines": total})

    def api_stream(self, params):
        app = self.server.app
        query = self.parse_query(params)
        selected = self.select_files(params)
        follow_all = not params.get("file")
        if not app.streams.acquire(blocking=False):
            self.send_error_json(429, "Too many live streams are open.")
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.common_headers()
            self.end_headers()
            self.close_connection = True
            self.wfile.write(b"retry: 3000\n\n")
            sys.stderr.write("%s user=%s live q=%s files=%d\n" % (
                self.client_address[0], self.user, json.dumps(params.get("q", [""])[0][:300]),
                len(selected)))
            self.stream_loop(app, query, selected, follow_all)
        except (BrokenPipeError, ConnectionError, socket.timeout, ssl.SSLError, OSError):
            pass
        finally:
            app.streams.release()

    def stream_loop(self, app, query, selected, follow_all):
        state = {}

        def track(fid, path, from_start):
            try:
                st = os.stat(path)
            except OSError:
                return
            state[fid] = {"path": path, "ino": (st.st_dev, st.st_ino),
                          "pos": 0 if from_start else st.st_size, "buf": b""}

        for fid, path in selected:
            track(fid, path, False)
        last_ping = last_scan = time.monotonic()
        while True:
            now_m = time.monotonic()
            if follow_all and now_m - last_scan > 10:
                last_scan = now_m
                for fid, v in app.index.files().items():
                    if fid not in state and v["readable"]:
                        track(fid, v["path"], True)   # new file: everything in it is new
            batch = []
            now = time.time()
            for fid, s in list(state.items()):
                try:
                    st = os.stat(s["path"])
                except OSError:
                    continue
                if (st.st_dev, st.st_ino) != s["ino"] or st.st_size < s["pos"]:
                    s["ino"], s["pos"], s["buf"] = (st.st_dev, st.st_ino), 0, b""  # rotated
                if st.st_size <= s["pos"]:
                    continue
                try:
                    with open(s["path"], "rb") as fh:
                        fh.seek(s["pos"])
                        data = fh.read(min(st.st_size - s["pos"], 1 << 20))
                except OSError:
                    continue
                s["pos"] += len(data)
                lines = (s["buf"] + data).split(b"\n")
                s["buf"] = lines.pop()
                if len(s["buf"]) > 65536:
                    lines.append(s["buf"])
                    s["buf"] = b""
                for b in lines:
                    raw = decode_line(b)
                    if not raw:
                        continue
                    low = raw.lower()
                    if not query.prefilter(low):
                        continue
                    rec = parse_line(raw, fid, now)
                    if rec["ts"] is None:
                        rec["ts"] = now
                    if query.matches(rec["f"], low):
                        batch.append(rec)
            if batch:
                skipped = max(0, len(batch) - STREAM_MAX_PER_POLL)
                if skipped:
                    self.wfile.write(("event: skipped\ndata: %d\n\n" % skipped).encode())
                    batch = batch[-STREAM_MAX_PER_POLL:]
                out = b"".join(b"data: " + json.dumps(record_json(r), separators=(",", ":")).encode("utf-8")
                               + b"\n\n" for r in batch)
                self.wfile.write(out)
                last_ping = time.monotonic()
            elif time.monotonic() - last_ping > STREAM_PING_SECONDS:
                self.wfile.write(b": ping\n\n")
                last_ping = time.monotonic()
            time.sleep(STREAM_POLL_SECONDS)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_serve(cfg):
    app = App(cfg)
    if app.users.count() == 0:
        sys.exit("No users defined in %s. Create one with: logviewer.py adduser NAME"
                 % cfg["auth"]["users_file"])
    ctx = None
    cert, key = cfg["server"]["tls_cert"].strip(), cfg["server"]["tls_key"].strip()
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        app.tls = True
    elif not cfg.getboolean("server", "allow_plain_http"):
        sys.exit("tls_cert and tls_key are not set. Passwords would cross the network in the "
                 "clear. Set them, or set allow_plain_http = yes if TLS is terminated elsewhere.")
    host = cfg["server"]["listen"].strip() or "::"
    port = cfg.getint("server", "port")
    try:
        server = Server((host, port), Handler, app, ctx)
    except OSError as exc:
        if host != "::" or exc.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            raise
        sys.stderr.write("IPv6 is not available on this host; falling back to IPv4 only.\n")
        host = "0.0.0.0"
        server = Server((host, port), Handler, app, ctx)
    sys.stderr.write("logviewer %s listening on [%s]:%d (%s), logs in %s\n" % (
        VERSION, host, port, "https" if ctx else "http", app.index.root))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def cmd_adduser(cfg, name):
    if not re.match(r"^[A-Za-z0-9_.@-]{1,64}$", name):
        sys.exit("User names may contain letters, digits and . _ @ - (max 64 characters).")
    path = cfg["auth"]["users_file"]
    pw = getpass.getpass("Password for %s: " % name)
    if len(pw) < MIN_PASSWORD_LEN:
        sys.exit("Password must be at least %d characters." % MIN_PASSWORD_LEN)
    if getpass.getpass("Repeat password: ") != pw:
        sys.exit("Passwords do not match.")
    users = read_users_file(path)
    users[name] = hash_password(pw)
    write_users_file(path, users)
    print("Saved user %s in %s" % (name, path))


def cmd_deluser(cfg, name):
    path = cfg["auth"]["users_file"]
    users = read_users_file(path)
    if name not in users:
        sys.exit("No such user: %s" % name)
    del users[name]
    write_users_file(path, users)
    print("Removed user %s from %s" % (name, path))


def cmd_check(cfg):
    index = LogIndex(cfg["logs"]["directory"], cfg.getboolean("logs", "recursive"),
                     cfg["logs"]["include_names"])
    files = index.files()
    print("Directory: %s" % index.root)
    print("Running as uid=%d gid=%d" % (os.getuid(), os.getgid()))
    unreadable = 0
    for fid, v in files.items():
        flag = "ok" if v["readable"] else "NO READ ACCESS"
        unreadable += 0 if v["readable"] else 1
        print("%-16s %12d bytes  %s" % (flag, v["size"], fid))
    print("%d files found, %d not readable by this user." % (len(files), unreadable))


def main():
    ap = argparse.ArgumentParser(description="Web interface for *.log files.")
    ap.add_argument("--config", default=None, help="config file (default %s)" % DEFAULT_CONFIG)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the web server")
    sub.add_parser("check", help="list the log files this user can see")
    p = sub.add_parser("adduser", help="add a user or change a password")
    p.add_argument("name")
    p = sub.add_parser("deluser", help="remove a user")
    p.add_argument("name")
    args = ap.parse_args()
    cfg = load_config(args.config or DEFAULT_CONFIG, args.config is not None)
    if args.command == "serve":
        cmd_serve(cfg)
    elif args.command == "check":
        cmd_check(cfg)
    elif args.command == "adduser":
        cmd_adduser(cfg, args.name)
    elif args.command == "deluser":
        cmd_deluser(cfg, args.name)


if __name__ == "__main__":
    main()

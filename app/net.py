"""Shared HTTP helpers for Compass.

Every outbound request goes through this module so that timeouts, TLS
settings, short-lived response caching and per-provider rate limits are
applied consistently. Standard library only (certifi is used if present).
"""
import hashlib
import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "Compass/1.0 (threat-intelligence; +local)"

_ctx_lock = threading.Lock()
_ctx = None


def ssl_context():
    global _ctx
    with _ctx_lock:
        if _ctx is None:
            try:
                import certifi  # optional
                _ctx = ssl.create_default_context(cafile=certifi.where())
            except Exception:
                _ctx = ssl.create_default_context()
        return _ctx


class HTTPStatusError(Exception):
    def __init__(self, code, reason="", body=""):
        super().__init__(f"HTTP {code}: {reason}".strip())
        self.code = code
        self.reason = reason
        self.body = body


class RateLimited(Exception):
    pass


# ---------------------------------------------------------------- memo cache
_MEMO_TTL = 15 * 60
_MEMO_MAX = 600
_memo = {}
_memo_lock = threading.Lock()


def _memo_key(method, url, headers, body):
    h = hashlib.sha256()
    h.update(method.encode())
    h.update(url.encode())
    for k in sorted((headers or {}).keys()):
        h.update(k.lower().encode())
        h.update(str(headers[k]).encode())
    if body:
        h.update(body if isinstance(body, bytes) else str(body).encode())
    return h.hexdigest()


def _memo_get(key):
    with _memo_lock:
        item = _memo.get(key)
        if not item:
            return None
        if time.time() - item[0] > _MEMO_TTL:
            _memo.pop(key, None)
            return None
        return item[1]


def _memo_put(key, value):
    with _memo_lock:
        if len(_memo) >= _MEMO_MAX:
            oldest = sorted(_memo.items(), key=lambda kv: kv[1][0])[: _MEMO_MAX // 5]
            for k, _ in oldest:
                _memo.pop(k, None)
        _memo[key] = (time.time(), value)


# -------------------------------------------------------------- rate limiter
class RateLimiter:
    """Sliding-window limiter: at most `limit` calls per `window` seconds."""

    def __init__(self, limit, window=60.0):
        self.limit = max(1, int(limit))
        self.window = float(window)
        self.calls = []
        self.lock = threading.Lock()

    def acquire(self, max_wait=20.0):
        deadline = time.time() + max_wait
        while True:
            with self.lock:
                now = time.time()
                self.calls = [t for t in self.calls if now - t < self.window]
                if len(self.calls) < self.limit:
                    self.calls.append(now)
                    return True
                wait = self.window - (now - self.calls[0]) + 0.05
            if time.time() + wait > deadline:
                return False
            time.sleep(min(wait, 1.0))


_limiters = {}
_limiters_lock = threading.Lock()


def limiter(name, limit, window=60.0):
    with _limiters_lock:
        if name not in _limiters:
            _limiters[name] = RateLimiter(limit, window)
        return _limiters[name]


# ------------------------------------------------------------------- request
def request(url, headers=None, timeout=15, method="GET", body=None, memo=True, limit=None, max_bytes=25 * 1024 * 1024,
            truncate_ok=False):
    """Perform an HTTP request and return the raw response bytes.

    `limit` is an optional RateLimiter that must grant a slot before the
    request is sent. Successful GET responses are memoised for 15 minutes so
    the same lookup made by two parts of an investigation costs one request.
    """
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    if isinstance(body, str):
        body = body.encode("utf-8")
    key = _memo_key(method, url, hdrs, body) if memo and method == "GET" else None
    if key:
        cached = _memo_get(key)
        if cached is not None:
            return cached
    if limit is not None and not limit.acquire():
        raise RateLimited("Provider rate limit reached; try again in a minute.")
    req = urllib.request.Request(url, headers=hdrs, method=method, data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
            raw = r.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        try:
            text = e.read(4096).decode("utf-8", "replace")
        except Exception:
            text = ""
        if e.code == 429:
            raise RateLimited("Provider returned HTTP 429 (quota or rate limit exceeded).")
        raise HTTPStatusError(e.code, e.reason or "", text)
    if len(raw) > max_bytes:
        if not truncate_ok:
            raise RuntimeError(f"Response larger than {max_bytes // (1024 * 1024)} MB; too much data to process.")
        raw = raw[:max_bytes]
    if key:
        _memo_put(key, raw)
    return raw


def get_json(url, headers=None, timeout=15, **kw):
    hdrs = {"Accept": "application/json"}
    hdrs.update(headers or {})
    raw = request(url, headers=hdrs, timeout=timeout, **kw)
    return json.loads(raw.decode("utf-8", "replace"))


def get_text(url, headers=None, timeout=15, **kw):
    return request(url, headers=headers, timeout=timeout, **kw).decode("utf-8", "replace")


def post_form_json(url, fields, headers=None, timeout=15, **kw):
    hdrs = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    hdrs.update(headers or {})
    body = urllib.parse.urlencode(fields).encode("utf-8")
    raw = request(url, headers=hdrs, timeout=timeout, method="POST", body=body, memo=False, **kw)
    return json.loads(raw.decode("utf-8", "replace"))


def describe_error(exc):
    """Short, analyst-friendly error text."""
    if isinstance(exc, RateLimited):
        return str(exc)
    if isinstance(exc, HTTPStatusError):
        if exc.code in (401, 403):
            return f"HTTP {exc.code}: access denied (check the API key or plan)."
        if exc.code == 404:
            return "No record found."
        return str(exc)
    text = str(exc) or exc.__class__.__name__
    if "timed out" in text.lower():
        return "Timed out waiting for the provider."
    if "getaddrinfo" in text.lower() or "name or service not known" in text.lower():
        return "Could not connect (DNS or network error)."
    return text[:300]

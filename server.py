import json
import mimetypes
import os
import re
import socket
import sys
import threading
import time
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import base64

from app import accounts, config, cve, emailheaders, engine, history, jobs, webhistory
from app.accounts import AuthError

VERSION = "1.0"
EMAIL_MAX_BYTES = 25 * 1024 * 1024

# Windows' registry can map .js to text/plain, which browsers refuse to run
# under X-Content-Type-Options: nosniff. Pin the types we serve.
for _ext, _type in ((".js", "application/javascript"), (".css", "text/css"), (".html", "text/html"),
                    (".svg", "image/svg+xml"), (".woff2", "font/woff2"), (".json", "application/json")):
    mimetypes.add_type(_type, _ext)
ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
HOST = os.environ.get("COMPASS_HOST", "0.0.0.0")
PORT = int(os.environ.get("COMPASS_PORT", os.environ.get("THREAT_INTEL_PORT", "8765")))
COOKIE = "compass_session"
CSRF_HEADER = "X-Compass-CSRF"
MUST_CHANGE_ALLOWED = {"/api/me", "/api/auth/password", "/api/auth/logout", "/api/auth/state"}

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


class HTTPError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status = status
        self.extra = extra


class Handler(BaseHTTPRequestHandler):
    server_version = f"Compass/{VERSION}"
    sys_version = ""

    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.address_string()} - {fmt % args}")

    # ----------------------------------------------------------- responses
    def _headers(self, code, content_type, length, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def _json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self._headers(code, "application/json; charset=utf-8", len(body), extra)
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _set_cookie(self, token, max_age):
        c = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
        return [("Set-Cookie", c)]

    # ------------------------------------------------------------- request
    def _body(self, max_bytes=2 * 1024 * 1024):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > max_bytes:
            raise HTTPError(413, "Request body too large.")
        if not length:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            raise HTTPError(400, "Invalid JSON body.")
        if not isinstance(data, dict):
            raise HTTPError(400, "Invalid JSON body.")
        return data

    def _token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = SimpleCookie()
            c.load(raw)
            m = c.get(COOKIE)
            return m.value if m else None
        except Exception:
            return None

    def _session(self):
        if not hasattr(self, "_sess_cache"):
            self._sess_cache = accounts.get_session(self._token())
        return self._sess_cache

    def _require(self, path, method, admin=False):
        sess = self._session()
        if not sess:
            raise HTTPError(401, "Please sign in.", login=True)
        if method in ("POST", "DELETE"):
            sent = self.headers.get(CSRF_HEADER, "")
            if not sent or sent != sess["csrf"]:
                raise HTTPError(403, "Security token missing or expired. Reload the page.")
        if sess["user"]["must_change"] and path not in MUST_CHANGE_ALLOWED:
            raise HTTPError(403, "You must change your password before continuing.", must_change=True)
        if admin and sess["user"]["role"] != "admin":
            raise HTTPError(403, "Only administrators can do this.")
        return sess

    def _require_public_post(self):
        # A custom header cannot be sent cross-site without a CORS preflight,
        # which this server never approves - so login/setup cannot be forged.
        if not self.headers.get(CSRF_HEADER):
            raise HTTPError(403, "Missing security header.")

    # ------------------------------------------------------------ dispatch
    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
        try:
            if path.startswith("/api/"):
                return self._api(method, path, qs)
            if method != "GET":
                raise HTTPError(405, "Method not allowed.")
            return self._page(path)
        except HTTPError as e:
            if path.startswith("/api/"):
                return self._json(e.status, dict({"ok": False, "error": str(e)}, **e.extra))
            body = str(e).encode()
            self._headers(e.status, "text/plain; charset=utf-8", len(body))
            self.wfile.write(body)
        except AuthError as e:
            return self._json(e.status, {"ok": False, "error": str(e)})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._json(500, {"ok": False, "error": f"Internal error: {e}"})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    # --------------------------------------------------------------- pages
    def _page(self, path):
        if path in ("/", "/index.html"):
            sess = self._session()
            if not sess:
                return self._redirect("/login")
            if sess["user"]["must_change"]:
                return self._redirect("/login?change=1")
            return self._static("/index.html")
        if path in ("/login", "/login.html"):
            return self._static("/login.html")
        return self._static(path)

    def _static(self, path):
        rel = Path(path.lstrip("/"))
        if ".." in rel.parts:
            raise HTTPError(403, "Forbidden")
        target = (WEB / rel).resolve()
        if not str(target).startswith(str(WEB.resolve())) or not target.is_file():
            raise HTTPError(404, "Not found")
        data = target.read_bytes()
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._headers(200, ctype, len(data))
        self.wfile.write(data)

    # ----------------------------------------------------------------- API
    def _api(self, method, path, qs):
        ip = self.client_address[0]

        # -------- public endpoints
        if path == "/api/health" and method == "GET":
            return self._json(200, {"ok": True, "name": "Compass", "version": VERSION})
        if path == "/api/auth/state" and method == "GET":
            sess = self._session()
            return self._json(200, {"setup_required": not accounts.users_exist(),
                                    "authenticated": bool(sess),
                                    "user": sess["user"] if sess else None,
                                    "csrf": sess["csrf"] if sess else None,
                                    "version": VERSION})
        if path == "/api/auth/setup" and method == "POST":
            self._require_public_post()
            body = self._body()
            with _setup_lock:
                if accounts.users_exist():
                    raise HTTPError(409, "Compass is already set up. Sign in instead.")
                user = accounts.create_user(body.get("username"), body.get("password"), role="admin",
                                            display_name=body.get("display_name", ""))
            accounts.touch_login(user["id"])
            token, csrf = accounts.create_session(user["id"], ip)
            return self._json(200, {"ok": True, "user": user, "csrf": csrf},
                              extra=self._set_cookie(token, accounts.SESSION_SECONDS))
        if path == "/api/auth/login" and method == "POST":
            self._require_public_post()
            body = self._body()
            user = accounts.authenticate(body.get("username"), body.get("password"), ip)
            token, csrf = accounts.create_session(user["id"], ip)
            return self._json(200, {"ok": True, "user": user, "csrf": csrf},
                              extra=self._set_cookie(token, accounts.SESSION_SECONDS))

        # -------- signed-in endpoints
        if path == "/api/auth/logout" and method == "POST":
            self._require(path, method)
            accounts.delete_session(self._token())
            return self._json(200, {"ok": True}, extra=self._set_cookie("", 0))

        sess = self._require(path, method)
        user = sess["user"]
        uid = user["id"]

        if path == "/api/me" and method == "GET":
            return self._json(200, {"user": user, "csrf": sess["csrf"], "version": VERSION, "lan_ip": local_ip(),
                                    "port": PORT, "history": history.counts(uid)})
        if path == "/api/auth/password" and method == "POST":
            body = self._body()
            updated = accounts.change_password(uid, body.get("current_password"), body.get("new_password"),
                                               keep_token_hash=sess["token_hash"])
            return self._json(200, {"ok": True, "user": updated})

        # -------- investigations
        if path == "/api/investigate" and method == "POST":
            body = self._body()
            value = str(body.get("ioc") or "").strip()
            if not value:
                raise HTTPError(400, "Enter an IP, domain, URL or hash.")
            if len(value) > 2048:
                raise HTTPError(400, "Input is too long.")
            payload = {"ioc": value, "active": bool(body.get("active")), "refresh": bool(body.get("refresh"))}
            file_info = body.get("file") if isinstance(body.get("file"), dict) else None
            if file_info:
                file_info = {"name": str(file_info.get("name", ""))[:255], "size": int(file_info.get("size") or 0),
                             "hashes": {"md5": value.lower()}, "ioc": value.lower(), "type": "file"}

            def work(job):
                result = engine.investigate(payload, emit=job.emit)
                if file_info:
                    result["file"] = file_info
                return result

            def save(job):
                r = job.result or {}
                if (r.get("ioc") or {}).get("type") in (None, "unknown"):
                    return
                name = r["ioc"].get("normalized") or value
                title = f"{file_info['name']} ({name})" if file_info else name
                history.add(uid, "Investigation", title, name, (r.get("threat_assessment") or {}).get("verdict"),
                            r.get("message"), r)

            job = jobs.start(uid, "investigation", value, work, on_done=save)
            return self._json(202, {"ok": True, "job_id": job.id})

        m = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]{8,40})", path)
        if m and method == "GET":
            job = jobs.get(m.group(1), uid)
            if not job:
                raise HTTPError(404, "Job not found.")
            return self._json(200, job.snapshot())

        # -------- website history (Wayback Machine)
        if path == "/api/webhistory" and method == "GET":
            target = (qs.get("target", [""])[0] or "").strip()[:2048]
            if not target:
                raise HTTPError(400, "Enter a domain or URL.")
            try:
                return self._json(200, webhistory.lookup(target))
            except ValueError as e:
                raise HTTPError(400, str(e))

        # -------- email header analysis
        if path == "/api/email/analyze" and method == "POST":
            body = self._body(max_bytes=EMAIL_MAX_BYTES)
            text = body.get("headers")
            b64 = body.get("eml_b64")
            name = str(body.get("name") or "")[:255]
            if b64:
                try:
                    raw = base64.b64decode(str(b64), validate=False)
                except Exception:
                    raise HTTPError(400, "The uploaded file could not be read.")
                source = "eml"
            elif text and str(text).strip():
                raw = str(text).encode("utf-8", "replace")
                source = "paste"
            else:
                raise HTTPError(400, "Paste the email headers or upload an .eml file.")
            if len(raw) > 18 * 1024 * 1024:
                raise HTTPError(413, "That email is larger than 18 MB.")
            try:
                result = emailheaders.analyze(raw, source=source)
            except ValueError as e:
                raise HTTPError(400, str(e))
            result["file_name"] = name or None
            f = result["fields"]
            title = (f.get("subject") or "(no subject)")[:120]
            sender = ((f.get("from") or {}).get("address") or "")
            history.add(uid, "Email", f"{title} | {sender}" if sender else title, (f.get("message_id") or "")[:400],
                        result["verdict"], result["headline"], result)
            return self._json(200, result)

        if path == "/api/cve/search" and method == "GET":
            query = (qs.get("q", [""])[0] or "").strip()[:200]
            cve_id = (qs.get("cve", [""])[0] or "").strip()[:40]
            sort = (qs.get("sort", ["relevance"])[0] or "relevance")
            try:
                limit = int(qs.get("limit", ["25"])[0])
            except ValueError:
                limit = 25
            try:
                data = cve.search(query=query, sort=sort, limit=limit, cve_id=cve_id)
            except Exception as e:
                raise HTTPError(502, f"CVE search failed: {e}")
            label = cve_id or query or "Latest 30 days"
            history.add(uid, "CVE", label, label, None, f"{data.get('count', 0)} result(s)", data)
            return self._json(200, data)

        # -------- personal history
        if path == "/api/history":
            type_ = qs.get("type", [None])[0]
            if type_ and type_ not in history.TYPES:
                raise HTTPError(400, "Unknown history type.")
            if method == "GET":
                return self._json(200, {"items": history.list_for(uid, type_), "counts": history.counts(uid)})
            if method == "DELETE":
                n = history.delete_all(uid, type_)
                return self._json(200, {"ok": True, "deleted": n})
        m = re.fullmatch(r"/api/history/(\d+)", path)
        if m:
            item_id = int(m.group(1))
            if method == "GET":
                item = history.get(uid, item_id)
                if not item:
                    raise HTTPError(404, "Record not found.")
                return self._json(200, item)
            if method == "DELETE":
                if not history.delete(uid, item_id):
                    raise HTTPError(404, "Record not found.")
                return self._json(200, {"ok": True})

        # -------- provider keys
        if path == "/api/settings/providers" and method == "GET":
            return self._json(200, config.provider_status())
        m = re.fullmatch(r"/api/settings/providers/([a-z0-9_]+)", path)
        if m:
            self._require(path, method, admin=True)
            name = m.group(1)
            if method == "POST":
                body = self._body()
                try:
                    config.set_key(name, body.get("api_key", ""))
                except (ValueError, RuntimeError, OSError) as e:
                    raise HTTPError(400, str(e))
                return self._json(200, {"ok": True, "status": config.provider_status().get(name)})
            if method == "DELETE":
                try:
                    config.delete_key(name)
                except ValueError as e:
                    raise HTTPError(400, str(e))
                return self._json(200, {"ok": True})

        # -------- user administration
        if path.startswith("/api/admin/"):
            self._require(path, method, admin=True)
            if path == "/api/admin/users" and method == "GET":
                return self._json(200, {"users": accounts.list_users()})
            if path == "/api/admin/users" and method == "POST":
                body = self._body()
                password = body.get("password") or ""
                generated = not password
                if generated:
                    password = accounts.generate_password()
                created = accounts.create_user(body.get("username"), password, role=body.get("role", "analyst"),
                                               display_name=body.get("display_name", ""), must_change=True)
                return self._json(200, {"ok": True, "user": created, "temp_password": password if generated else None})
            if path == "/api/admin/users/bulk" and method == "POST":
                body = self._body()
                names = [n.strip() for n in re.split(r"[\s,;]+", str(body.get("usernames") or "")) if n.strip()]
                if not names:
                    raise HTTPError(400, "Enter at least one username.")
                if len(names) > 300:
                    raise HTTPError(400, "Add at most 300 users at a time.")
                out = []
                for n in dict.fromkeys(names):
                    pw = accounts.generate_password()
                    try:
                        accounts.create_user(n, pw, role=body.get("role", "analyst"), must_change=True)
                        out.append({"username": n, "password": pw, "ok": True})
                    except AuthError as e:
                        out.append({"username": n, "ok": False, "error": str(e)})
                return self._json(200, {"ok": True, "results": out})
            m = re.fullmatch(r"/api/admin/users/(\d+)", path)
            if m:
                target = int(m.group(1))
                if method == "DELETE":
                    accounts.delete_user(target, uid)
                    return self._json(200, {"ok": True})
                if method == "POST":
                    body = self._body()
                    action = body.get("action")
                    if action == "reset_password":
                        return self._json(200, {"ok": True, "temp_password": accounts.reset_password(target)})
                    if action == "update":
                        active = body.get("active")
                        updated = accounts.update_user(target, uid, role=body.get("role"),
                                                       active=None if active is None else bool(active),
                                                       display_name=body.get("display_name"))
                        return self._json(200, {"ok": True, "user": updated})
                    raise HTTPError(400, "Unknown action.")
        raise HTTPError(404, "Not found.")


_setup_lock = threading.Lock()


class Server(ThreadingHTTPServer):
    daemon_threads = True


def _log_to_file_if_windowless():
    """Compass.exe runs the server with pythonw, which has no console. Send all
    output (requests, errors, tracebacks) to data/compass.log instead."""
    if sys.stdout is not None and not os.environ.get("COMPASS_LAUNCHER"):
        return
    log_dir = ROOT / "data"
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / "compass.log"
    try:
        if path.exists() and path.stat().st_size > 5 * 1024 * 1024:
            old = log_dir / "compass.log.1"
            if old.exists():
                old.unlink()
            path.rename(old)
    except OSError:
        pass
    f = open(path, "a", encoding="utf-8", buffering=1, errors="replace")
    sys.stdout = sys.stderr = f
    print(f"\n----- {time.strftime('%Y-%m-%d %H:%M:%S')} Compass {VERSION} starting -----")


def main():
    _log_to_file_if_windowless()
    print("=" * 56)
    print(f" Compass {VERSION} - Threat Intelligence & Discovery")
    print("=" * 56)
    print(f" Local URL : http://127.0.0.1:{PORT}")
    print(f" LAN URL   : http://{local_ip()}:{PORT}")
    print(f" Listening : {HOST}:{PORT}")
    print()
    if not accounts.users_exist():
        print(" First run: open the Local URL to create the administrator account.")
        print()
    print("Every user must sign in. Keep the server on a trusted LAN/VLAN and")
    print("do NOT port-forward it to the Internet.")
    print()
    server = Server((HOST, PORT), Handler)
    if not os.environ.get("COMPASS_NO_BROWSER"):
        threading.Timer(0.8, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

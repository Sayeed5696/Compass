"""User accounts, password hashing, sessions and login throttling."""
import hashlib
import hmac
import re
import secrets
import threading
import time

from .db import connect

PBKDF2_ITERATIONS = 310_000
SESSION_SECONDS = 12 * 3600
MAX_FAILS = 5
FAIL_WINDOW = 10 * 60
LOCK_SECONDS = 5 * 60
ROLES = ("admin", "analyst")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


class AuthError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------- passwords
def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algo, iters, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))


def generate_password():
    raw = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(10))
    return raw[:5] + "-" + raw[5:]


def check_username(username):
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise AuthError("Usernames are 3-32 characters: letters, numbers, dot, dash or underscore.")
    return username


def check_password(password, username=""):
    password = password or ""
    if len(password) < 8:
        raise AuthError("Passwords must be at least 8 characters.")
    if len(password) > 128:
        raise AuthError("Passwords must be at most 128 characters.")
    if username and password.lower() == username.lower():
        raise AuthError("The password cannot be the same as the username.")
    return password


def _public(row):
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"] or row["username"],
        "role": row["role"],
        "active": bool(row["active"]),
        "must_change": bool(row["must_change"]),
        "created_at": row["created_at"],
        "last_login": row["last_login"],
    }


# ------------------------------------------------------------------ users
def users_exist():
    with connect() as con:
        return con.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def create_user(username, password, role="analyst", display_name="", must_change=False):
    username = check_username(username)
    check_password(password, username)
    if role not in ROLES:
        raise AuthError("Unknown role.")
    with connect() as con:
        if con.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise AuthError(f"The username '{username}' is already taken.", 409)
        cur = con.execute(
            "INSERT INTO users (username, display_name, password_hash, role, active, must_change, created_at) VALUES (?,?,?,?,1,?,?)",
            (username, (display_name or "").strip()[:64], hash_password(password), role, 1 if must_change else 0, time.time()))
        row = con.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _public(row)


def touch_login(user_id):
    with connect() as con:
        con.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user_id))


def get_user(user_id):
    with connect() as con:
        return _public(con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def list_users():
    with connect() as con:
        rows = con.execute("SELECT * FROM users ORDER BY role = 'admin' DESC, username COLLATE NOCASE").fetchall()
    return [_public(r) for r in rows]


def _admin_count(con, exclude_id=None):
    q = "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1"
    args = ()
    if exclude_id is not None:
        q += " AND id != ?"
        args = (exclude_id,)
    return con.execute(q, args).fetchone()[0]


def update_user(user_id, actor_id, role=None, active=None, display_name=None):
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.", 404)
        demoting = (role is not None and role != "admin") or (active is False)
        if row["role"] == "admin" and demoting and _admin_count(con, exclude_id=user_id) == 0:
            raise AuthError("Compass needs at least one active administrator.")
        if user_id == actor_id and active is False:
            raise AuthError("You cannot disable your own account.")
        if role is not None:
            if role not in ROLES:
                raise AuthError("Unknown role.")
            con.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if active is not None:
            con.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))
            if not active:
                con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        if display_name is not None:
            con.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name.strip()[:64], user_id))
        return _public(con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def reset_password(user_id):
    """Admin reset: returns a one-time password the user must change at next sign-in."""
    temp = generate_password()
    with connect() as con:
        if not con.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
            raise AuthError("User not found.", 404)
        con.execute("UPDATE users SET password_hash = ?, must_change = 1 WHERE id = ?", (hash_password(temp), user_id))
        con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return temp


def delete_user(user_id, actor_id):
    if user_id == actor_id:
        raise AuthError("You cannot delete your own account.")
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.", 404)
        if row["role"] == "admin" and _admin_count(con, exclude_id=user_id) == 0:
            raise AuthError("Compass needs at least one active administrator.")
        con.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM users WHERE id = ?", (user_id,))


def change_password(user_id, current, new, keep_token_hash=None):
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row or not verify_password(current or "", row["password_hash"]):
            raise AuthError("The current password is incorrect.", 403)
        check_password(new, row["username"])
        if verify_password(new, row["password_hash"]):
            raise AuthError("Choose a password different from the current one.")
        con.execute("UPDATE users SET password_hash = ?, must_change = 0 WHERE id = ?", (hash_password(new), user_id))
        # Sign out every other session for this account.
        con.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, keep_token_hash or ""))
        return _public(con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


# --------------------------------------------------------------- throttle
_fails = {}
_fails_lock = threading.Lock()


def _throttle_keys(username, ip):
    return [("user", (username or "").lower(), ip), ("ip", "", ip)]


def _check_throttle(username, ip):
    now = time.time()
    with _fails_lock:
        for key in _throttle_keys(username, ip):
            limit = MAX_FAILS if key[0] == "user" else MAX_FAILS * 4
            hits = [t for t in _fails.get(key, []) if now - t < FAIL_WINDOW]
            _fails[key] = hits
            if len(hits) >= limit:
                wait = int(LOCK_SECONDS - (now - hits[-1]))
                if wait > 0:
                    mins = max(1, (wait + 59) // 60)
                    raise AuthError(f"Too many failed sign-in attempts. Try again in {mins} minute{'s' if mins != 1 else ''}.", 429)


def _record_fail(username, ip):
    with _fails_lock:
        for key in _throttle_keys(username, ip):
            _fails.setdefault(key, []).append(time.time())


def _clear_fails(username, ip):
    with _fails_lock:
        _fails.pop(("user", (username or "").lower(), ip), None)


def authenticate(username, password, ip):
    username = (username or "").strip()
    _check_throttle(username, ip)
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        verify_password(password or "", _DUMMY_HASH)  # same work either way
        _record_fail(username, ip)
        raise AuthError("Incorrect username or password.", 401)
    if not verify_password(password or "", row["password_hash"]):
        _record_fail(username, ip)
        raise AuthError("Incorrect username or password.", 401)
    if not row["active"]:
        raise AuthError("This account is disabled. Contact your Compass administrator.", 403)
    _clear_fails(username, ip)
    with connect() as con:
        con.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), row["id"]))
    return _public(row)


# ---------------------------------------------------------------- sessions
def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id, ip=""):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = time.time()
    with connect() as con:
        con.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        con.execute("INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, ip) VALUES (?,?,?,?,?,?)",
                    (_token_hash(token), user_id, csrf, now, now + SESSION_SECONDS, ip))
    return token, csrf


def get_session(token):
    if not token or len(token) > 200:
        return None
    th = _token_hash(token)
    with connect() as con:
        row = con.execute(
            "SELECT s.token_hash, s.csrf, s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (th,)).fetchone()
        if not row:
            return None
        if row["expires_at"] < time.time() or not row["active"]:
            con.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
            return None
    user = _public(row)
    return {"user": user, "csrf": row["csrf"], "token_hash": th, "expires_at": row["expires_at"]}


def delete_session(token):
    if not token:
        return
    with connect() as con:
        con.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))

"""Per-user search history. Every query is filtered by user_id, so one user
can never list, open or delete another user's records."""
import json
import time

from .db import connect

KEEP_PER_TYPE = 300
TYPES = ("Investigation", "Email", "Lookalike", "CVE")


def add(user_id, type_, title, query, verdict, summary, snapshot):
    if type_ not in TYPES:
        raise ValueError("Unknown history type")
    with connect() as con:
        cur = con.execute(
            "INSERT INTO history (user_id, type, title, query, verdict, summary, snapshot, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (user_id, type_, title[:300], (query or "")[:500], verdict, (summary or "")[:500],
             json.dumps(snapshot, ensure_ascii=False, default=str), time.time()))
        con.execute(
            "DELETE FROM history WHERE user_id = ? AND type = ? AND id NOT IN "
            "(SELECT id FROM history WHERE user_id = ? AND type = ? ORDER BY created_at DESC LIMIT ?)",
            (user_id, type_, user_id, type_, KEEP_PER_TYPE))
        return cur.lastrowid


def list_for(user_id, type_=None):
    q = "SELECT id, type, title, query, verdict, summary, created_at, length(snapshot) AS size FROM history WHERE user_id = ?"
    args = [user_id]
    if type_:
        q += " AND type = ?"
        args.append(type_)
    q += " ORDER BY created_at DESC LIMIT 1000"
    with connect() as con:
        return [dict(r) for r in con.execute(q, args).fetchall()]


def get(user_id, item_id):
    with connect() as con:
        row = con.execute("SELECT * FROM history WHERE id = ? AND user_id = ?", (item_id, user_id)).fetchone()
    if not row:
        return None
    out = dict(row)
    out.pop("user_id", None)
    out["snapshot"] = json.loads(out["snapshot"])
    return out


def delete(user_id, item_id):
    with connect() as con:
        return con.execute("DELETE FROM history WHERE id = ? AND user_id = ?", (item_id, user_id)).rowcount


def delete_all(user_id, type_=None):
    with connect() as con:
        if type_:
            return con.execute("DELETE FROM history WHERE user_id = ? AND type = ?", (user_id, type_)).rowcount
        return con.execute("DELETE FROM history WHERE user_id = ?", (user_id,)).rowcount


def counts(user_id):
    with connect() as con:
        rows = con.execute("SELECT type, COUNT(*) AS n FROM history WHERE user_id = ? GROUP BY type", (user_id,)).fetchall()
    out = {t: 0 for t in TYPES}
    out.update({r["type"]: r["n"] for r in rows})
    return out

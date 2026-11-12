"""Website history from the Internet Archive's Wayback Machine.

Passive: Compass only talks to web.archive.org, never to the site itself.
Returns the first and latest capture, captures per year, and the list of
captures where the page content actually changed (adjacent duplicates are
collapsed by content digest). For redirect captures Compass asks the archive
where the redirect pointed, which often reveals a related domain.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import net
from .ioc import detect_ioc

CDX = "https://web.archive.org/cdx/search/cdx?"
MAX_VERSIONS = 1500
MAX_DAYS = 10000
MAX_REDIRECT_LOOKUPS = 15
IST = timezone(timedelta(hours=5, minutes=30))


def _target(value):
    ioc = detect_ioc(value)
    if ioc["type"] == "domain":
        return ioc["normalized"], ioc["normalized"] + "/"
    if ioc["type"] == "url":
        url = ioc["normalized"]
        p = urllib.parse.urlsplit(url)
        path = p.path or "/"
        return ioc["hostname"], f"{p.hostname}{(':' + str(p.port)) if p.port else ''}{path}" + (f"?{p.query}" if p.query else "")
    raise ValueError("Website history needs a domain or URL.")


def _cdx(params, timeout=40):
    url = CDX + urllib.parse.urlencode(params)
    raw = net.get_text(url, timeout=timeout, max_bytes=12 * 1024 * 1024, truncate_ok=False)
    raw = raw.strip()
    if not raw:
        return []
    rows = json.loads(raw)
    if rows and isinstance(rows[0], list) and rows[0] and rows[0][0] in ("timestamp", "urlkey"):
        head = rows[0]
        return [dict(zip(head, r)) for r in rows[1:]]
    return []


def _when(ts):
    try:
        dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None, None
    return dt.isoformat().replace("+00:00", "Z"), dt.astimezone(IST).strftime("%d %b %Y, %H:%M IST")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _redirect_target(ts, original):
    """Ask the archive where an archived redirect pointed (archive only, never the site)."""
    url = f"https://web.archive.org/web/{ts}id_/{original}"
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=net.ssl_context()))
    req = urllib.request.Request(url, headers={"User-Agent": net.USER_AGENT}, method="HEAD")
    try:
        with opener.open(req, timeout=15) as r:
            loc = r.headers.get("Location")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") if e.headers else None
    except Exception:
        return None
    if not loc:
        return None
    # Archive locations look like https://web.archive.org/web/<ts>id_/<original-target>
    marker = "id_/"
    if "web.archive.org/web/" in loc and marker in loc:
        loc = loc.split(marker, 1)[1]
    if loc.startswith("/web/"):
        parts = loc.split("/", 3)
        loc = parts[3] if len(parts) > 3 else loc
    return loc[:500]


def lookup(value):
    host, url = _target(value)
    started = time.time()
    errors = []

    # Distinct versions: adjacent captures with identical content are collapsed.
    versions = []
    truncated = False
    try:
        # Negative limit = the most recent captures.
        rows = _cdx({"url": url, "output": "json", "fl": "timestamp,original,statuscode,digest,mimetype,length",
                     "collapse": "digest", "filter": "!mimetype:warc/revisit", "limit": str(-(MAX_VERSIONS + 1))})
        rows.sort(key=lambda r: r.get("timestamp", ""))
        if len(rows) > MAX_VERSIONS:
            truncated = True
            rows = rows[-MAX_VERSIONS:]
        prev_len = None
        for r in rows:
            iso, ist = _when(r.get("timestamp", ""))
            if not iso:
                continue
            code = r.get("statuscode") or "-"
            try:
                size = int(r.get("length") or 0)
            except ValueError:
                size = 0
            kind = "change"
            if code.startswith("3"):
                kind = "redirect"
            elif code.startswith("4") or code.startswith("5"):
                kind = "gone"
            versions.append({"ts": r["timestamp"], "utc": iso, "ist": ist, "year": int(r["timestamp"][:4]),
                             "status": code, "kind": kind, "mime": r.get("mimetype") or "",
                             "size": size, "size_delta": (size - prev_len) if (prev_len is not None and size) else None,
                             "digest": r.get("digest") or "", "original": r.get("original") or url,
                             "snapshot": f"https://web.archive.org/web/{r['timestamp']}/{r.get('original') or url}"})
            if size:
                prev_len = size
    except Exception as e:
        errors.append("Version list: " + net.describe_error(e))

    # Days with at least one capture, per year (bounded query).
    years = {}
    first = last = None
    try:
        days = _cdx({"url": url, "output": "json", "fl": "timestamp", "collapse": "timestamp:8", "limit": str(MAX_DAYS)})
        if len(days) >= MAX_DAYS:  # very old, busy site: make sure the latest capture is known
            tail = _cdx({"url": url, "output": "json", "fl": "timestamp", "limit": "-1"})
            if tail:
                days.append(tail[-1])
        for d in days:
            ts = d.get("timestamp", "")
            if len(ts) >= 8:
                years[int(ts[:4])] = years.get(int(ts[:4]), 0) + 1
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
    except Exception as e:
        errors.append("Capture counts: " + net.describe_error(e))

    if versions:
        first = min([first] + [versions[0]["ts"]]) if first else versions[0]["ts"]
        last = max([last] + [versions[-1]["ts"]]) if last else versions[-1]["ts"]

    # Where did archived redirects point? (most recent first, bounded)
    redirects = [v for v in versions if v["kind"] == "redirect"][-MAX_REDIRECT_LOOKUPS:]
    if redirects:
        with ThreadPoolExecutor(max_workers=5) as pool:
            for v, target in zip(redirects, pool.map(lambda x: _redirect_target(x["ts"], x["original"]), redirects)):
                if target:
                    v["redirect_to"] = target
                    try:
                        th = (urllib.parse.urlsplit(target).hostname or "").lower()
                    except ValueError:
                        th = ""
                    v["redirect_host"] = th
                    v["offsite"] = bool(th) and th != host and not th.endswith("." + host) and not host.endswith("." + th)

    if errors and not versions and not years:
        status = "failed"
    elif not versions and not years:
        status = "empty"
    else:
        status = "partial" if errors else "done"

    f_iso, f_ist = _when(first) if first else (None, None)
    l_iso, l_ist = _when(last) if last else (None, None)
    versions.reverse()  # newest first
    return {
        "target": host,
        "url": url,
        "status": status,
        "errors": errors,
        "first": {"utc": f_iso, "ist": f_ist} if first else None,
        "latest": {"utc": l_iso, "ist": l_ist} if last else None,
        "days_captured": sum(years.values()),
        "years": [{"year": y, "days": years[y]} for y in sorted(years)],
        "versions": versions,
        "version_count": len(versions),
        "truncated": truncated,
        "redirects_offsite": sum(1 for v in versions if v.get("offsite")),
        "duration_s": round(time.time() - started, 1),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

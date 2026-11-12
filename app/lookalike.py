"""Lookalike-domain finder.

Generates misspellings and look-alike versions of a domain (typos, look-alike
characters including Cyrillic letters, other endings, added words, hyphens),
then checks which are registered (DNS + RDAP) and live today (DNS).

Passive by default: only DNS-over-HTTPS resolvers, RDAP and RIPEstat are
queried. With active checks Compass also fetches the home page title of live
lookalikes, so those sites can see the server's IP address.
"""
import ipaddress
import re
import secrets
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import net
from .discovery import classify_network, doh, resolve_a, ripestat
from .psl import public_suffix, registrable_domain

MAX_VARIANTS = 300
MAX_RDAP = 60
MAX_ENRICH = 40
MAX_TITLES = 30

TECHNIQUES = {
    "typo": "Typos",
    "homoglyph": "Look-alike characters",
    "tld": "Other endings",
    "words": "Added words",
    "hyphen": "Hyphens",
}

KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
    "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn", "k": "jilm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t", "6": "57y", "7": "68u", "8": "79i", "9": "80o", "0": "9p",
}
ASCII_LOOKALIKE = {"l": ["1", "i"], "i": ["1", "l"], "o": ["0"], "0": ["o"], "1": ["l", "i"], "m": ["rn"], "w": ["vv"],
                   "e": ["3"], "a": ["4"], "s": ["5"], "g": ["q"], "q": ["g"], "b": ["d"], "d": ["b", "cl"], "u": ["v"], "v": ["u"]}
ASCII_PAIRS = {"rn": "m", "vv": "w", "cl": "d"}
UNICODE_LOOKALIKE = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ", "h": "һ"}
CONFUSABLE_TO_ASCII = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
                       "һ": "h", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ⅼ": "l", "ο": "o", "α": "a", "ν": "v", "κ": "k", "τ": "t"}
OTHER_ENDINGS = ["com", "in", "co.in", "net", "org", "net.in", "org.in", "online", "site", "top", "xyz", "info", "live",
                 "shop", "app", "co", "cc", "vip", "icu", "click", "link", "support", "help", "services"]
WORDS = ["login", "secure", "kyc", "verify", "update", "online", "support", "help", "care", "refund", "pay", "account",
         "customer", "netbanking", "service", "official", "india", "app"]

# Well-known domains that are often imitated in Indian fraud cases (used by
# email analysis to flag lookalike sender domains).
BRANDS = [
    "sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "pnbindia.in",
    "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in", "indianbank.in", "idfcfirstbank.com", "yesbank.in",
    "rbi.org.in", "npci.org.in", "incometax.gov.in", "gst.gov.in", "uidai.gov.in", "epfindia.gov.in", "india.gov.in",
    "nic.in", "gov.in", "cybercrime.gov.in", "parivahan.gov.in", "echallan.parivahan.gov.in", "indiapost.gov.in",
    "irctc.co.in", "paytm.com", "phonepe.com", "amazon.in", "amazon.com", "flipkart.com", "google.com", "gmail.com",
    "microsoft.com", "outlook.com", "apple.com", "paypal.com", "facebook.com", "instagram.com", "whatsapp.com",
    "linkedin.com", "netflix.com", "airtel.in", "jio.com", "bsnl.co.in", "lic.in", "licindia.in",
]


def _ldh(label):
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)) and (label[2:4] != "--" or label.startswith("xn--"))


def _to_ascii(label):
    if label.isascii():
        return label
    try:
        return label.encode("idna").decode("ascii")
    except Exception:
        return None


def _from_ascii(label):
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            return label
    return label


def split_domain(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    apex = registrable_domain(domain)
    suffix = public_suffix(apex)
    if not apex or not suffix or apex == suffix:
        raise ValueError(f"{domain or 'That'} is not a registrable domain (for example example.co.in).")
    return apex, apex[: -(len(suffix) + 1)], suffix


def skeleton(label):
    """Collapse look-alike characters so imitations compare equal."""
    s = "".join(CONFUSABLE_TO_ASCII.get(ch, ch) for ch in _from_ascii(label.lower()))
    for a, b in (("rn", "m"), ("vv", "w")):
        s = s.replace(a, b)
    s = s.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "i": "l"}))
    return s.replace("-", "")


def _damerau(a, b):
    if abs(len(a) - len(b)) > 1:
        return 2
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def imitation(domain, target):
    """Return (reason, strong) if `domain` imitates `target`, else None.

    Strong: made to be mistaken for the real name (look-alike characters,
    non-Latin letters, one character off). Weak: shares the name (another
    ending, added words, extra letters), which is also how brands name their
    own services, so it only warrants a second look.
    """
    try:
        a_apex, a_label, a_suf = split_domain(domain)
        b_apex, b_label, b_suf = split_domain(target)
    except ValueError:
        return None
    if a_apex == b_apex:
        return None
    a_uni = _from_ascii(a_label)
    if not a_uni.isascii() and skeleton(a_label) == skeleton(b_label):
        return "uses look-alike non-Latin letters", True
    if a_label == b_label:
        return f"has the same name with a different ending (.{a_suf})", False
    if skeleton(a_label) == skeleton(b_label):
        return "swaps letters for look-alike characters", True
    if len(b_label) >= 5 and _damerau(a_label, b_label) == 1:
        return "differs by one character", True
    tokens = [t for t in re.split(r"[-\d]+", a_label) if t]
    if len(b_label) >= 3 and b_label in tokens and len(tokens) > 1:
        return "adds words to the real name", False
    if len(b_label) >= 6 and b_label in a_label and a_label != b_label:
        return "contains the real name with extra letters", False
    return None


# Zones where only verified organisations can register, so a name there is
# not a fraudster's lookalike: bank.in (RBI-regulated banks), gov.in and
# nic.in (Government of India), mil.in.
RESTRICTED_SUFFIXES = ("bank.in", "gov.in", "nic.in", "mil.in")
# Sending and notification domains that legitimately contain a brand's name
# or are used by many genuine senders. Never reported as lookalikes.
SERVICE_DOMAINS = {
    "amazonses.com", "facebookmail.com", "microsoftonline.com", "onmicrosoft.com", "gappssmtp.com", "googlemail.com",
    "sendgrid.net", "mailgun.org", "mcsv.net", "mandrillapp.com", "sparkpostmail.com",
}


def imitates_known(domain, extra=()):
    """Return (brand, reason, strong). Strong matches win over weak ones."""
    apex = registrable_domain((domain or "").lower().rstrip("."))
    if not apex or apex in SERVICE_DOMAINS or apex in BRANDS:
        return None, None, False
    if public_suffix(apex) in RESTRICTED_SUFFIXES:
        return None, None, False
    weak = None
    for brand in list(extra) + BRANDS:
        res = imitation(apex, brand)
        if not res:
            continue
        why, strong = res
        if strong:
            return brand, why, True
        weak = weak or (brand, why, False)
    return weak or (None, None, False)


# ------------------------------------------------------------------ generation
def generate(domain, techniques=None):
    apex, label, suffix = split_domain(domain)
    techniques = [t for t in (techniques or list(TECHNIQUES)) if t in TECHNIQUES] or list(TECHNIQUES)
    buckets = {t: [] for t in techniques}

    def add(t, lab, how, suf=None):
        if t not in buckets:
            return
        asc = _to_ascii(lab)
        if not asc or asc == label and (suf or suffix) == suffix or not _ldh(asc):
            return
        buckets[t].append((f"{asc}.{suf or suffix}", how))

    n = len(label)
    for i in range(n):
        add("typo", label[:i] + label[i + 1:], f"Typo: “{label[i]}” missing")
        add("typo", label[:i] + label[i] + label[i:], f"Typo: “{label[i]}” doubled")
        if i < n - 1 and label[i] != label[i + 1]:
            add("typo", label[:i] + label[i + 1] + label[i] + label[i + 2:], "Typo: letters swapped")
        for k in KEYBOARD.get(label[i], ""):
            add("typo", label[:i] + k + label[i + 1:], f"Typo: “{k}” for “{label[i]}” (next key)")
        for alt in ASCII_LOOKALIKE.get(label[i], []):
            add("homoglyph", label[:i] + alt + label[i + 1:], f"Look-alike: “{alt}” for “{label[i]}”")
        if label[i] in UNICODE_LOOKALIKE:
            add("homoglyph", label[:i] + UNICODE_LOOKALIKE[label[i]] + label[i + 1:], f"Look-alike: non-Latin “{label[i]}”")
        if 0 < i and label[i] != "-" and label[i - 1] != "-":
            add("hyphen", label[:i] + "-" + label[i:], "Hyphen added")
    for pair, rep in ASCII_PAIRS.items():
        start = 0
        while True:
            j = label.find(pair, start)
            if j < 0:
                break
            add("homoglyph", label[:j] + rep + label[j + 2:], f"Look-alike: “{rep}” for “{pair}”")
            start = j + 1
    if "-" in label:
        add("hyphen", label.replace("-", ""), "Hyphen removed")
    for suf in OTHER_ENDINGS:
        if suf != suffix:
            add("tld", label, f"Other ending: .{suf}", suf)
    for w in WORDS:
        add("words", f"{label}-{w}", f"Added word: “{w}”")
        add("words", f"{w}-{label}", f"Added word: “{w}”")
        add("words", f"{label}{w}", f"Added word: “{w}”")

    # Round-robin so every technique is represented under the cap.
    seen, out = {apex}, []
    iters = {t: iter(v) for t, v in buckets.items()}
    while iters and len(out) < MAX_VARIANTS:
        for t in list(iters):
            try:
                name, how = next(iters[t])
            except StopIteration:
                iters.pop(t)
                continue
            if name in seen:
                continue
            seen.add(name)
            out.append({"domain": name, "technique": t, "how": how})
            if len(out) >= MAX_VARIANTS:
                break
    total = len({d for v in buckets.values() for d, _ in v} - {apex})
    return apex, out, total


# ------------------------------------------------------------------ checks
def _rdap(domain):
    data = net.get_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}", timeout=12)
    created = next((e.get("eventDate") for e in data.get("events") or [] if e.get("eventAction") == "registration"), None)
    registrar = None
    for ent in data.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            vc = ent.get("vcardArray")
            for obj in (vc[1] if isinstance(vc, list) and len(vc) > 1 else []):
                if isinstance(obj, list) and len(obj) >= 4 and obj[0] == "fn":
                    registrar = obj[3]
            registrar = registrar or ent.get("handle")
    return created, registrar


def _title(domain):
    for scheme in ("https", "http"):
        try:
            html = net.get_text(f"{scheme}://{domain}/", timeout=8, max_bytes=300 * 1024, truncate_ok=True, memo=False,
                                headers={"Accept": "text/html"})
        except Exception:
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
        return ""
    return None


def _age_days(created):
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None


def find(domain, techniques=None, active=False, emit=None):
    emit = emit or (lambda *a, **k: None)
    started = time.time()

    def stage(sid, label, status, **kw):
        emit(dict({"group": "lookalike", "id": sid, "label": label, "status": status}, **kw))

    stage("generate", "Generate variants", "running")
    apex, variants, total = generate(domain, techniques)
    stage("generate", "Generate variants", "done", count=len(variants),
          note=f"{total} possible, first {len(variants)} checked" if total > len(variants) else None)

    # Wildcard endings: a random name that should not exist but resolves.
    suffixes = sorted({v["domain"].split(".", 1)[1] for v in variants})
    wildcard = set()

    def wc(suf):
        try:
            ans, nx = doh(f"cmp-{secrets.token_hex(6)}.{suf}", "A")
            return suf, bool(ans) and not nx
        except Exception:
            return suf, False

    with ThreadPoolExecutor(max_workers=12) as pool:
        for suf, is_wc in pool.map(wc, suffixes):
            if is_wc:
                wildcard.add(suf)

    stage("dns", "Registration and live DNS", "running")

    def check(v):
        name = v["domain"]
        try:
            ans, nx = doh(name, "NS")
            if nx:
                return dict(v, registered=False, live=False, ips=[])
            registered = True
        except Exception:
            return dict(v, registered=None, live=None, ips=[], error="DNS lookup failed")
        try:
            ips, chain = resolve_a(name)
        except Exception:
            ips, chain = [], []
        suf = name.split(".", 1)[1]
        return dict(v, registered=registered, live=bool(ips), ips=ips, cname=chain, wildcard=suf in wildcard)

    with ThreadPoolExecutor(max_workers=32) as pool:
        rows = list(pool.map(check, variants))
    registered = [r for r in rows if r.get("registered")]
    failed = sum(1 for r in rows if r.get("registered") is None)
    stage("dns", "Registration and live DNS", "failed" if failed == len(rows) and rows else "done",
          count=len(registered), note=f"{len(registered)} registered, {sum(1 for r in rows if r.get('live'))} live"
          + (f"; {failed} could not be checked" if failed else ""), error="DNS resolvers did not answer." if failed == len(rows) and rows else None)

    stage("rdap", "Registration dates (RDAP)", "running" if registered else "skipped")
    rdap_targets = sorted(registered, key=lambda r: (not r.get("live"), r["domain"]))[:MAX_RDAP]
    rdap_ok = 0

    def do_rdap(r):
        try:
            created, registrar = _rdap(r["domain"])
            r["created"], r["registrar"] = created, registrar
            return True
        except Exception as e:
            r["rdap_error"] = net.describe_error(e)
            return False

    if rdap_targets:
        with ThreadPoolExecutor(max_workers=6) as pool:
            rdap_ok = sum(pool.map(do_rdap, rdap_targets))
        stage("rdap", "Registration dates (RDAP)", "done" if rdap_ok else "failed", count=rdap_ok,
              note=f"{len(registered) - len(rdap_targets)} not looked up (limit {MAX_RDAP})" if len(registered) > len(rdap_targets) else None,
              error=None if rdap_ok else "RDAP returned no registration data.")

    live = [r for r in rows if r.get("live")]
    stage("network", "Hosting network (RIPEstat)", "running" if live else "skipped")
    ips = list(dict.fromkeys(ip for r in live for ip in r["ips"]))[:MAX_ENRICH]
    net_info = {}

    def enrich(ip):
        try:
            d = ripestat("network-info", ip)
            asns = d.get("asns") or []
            asn = f"AS{asns[0]}" if asns else None
            holder = ripestat("as-overview", asn).get("holder") if asn else None
            cdn, hosting = classify_network(asn, holder)
            return ip, {"asn": asn, "as_name": holder, "cdn": cdn, "hosting": hosting}
        except Exception:
            return ip, {}

    if ips:
        with ThreadPoolExecutor(max_workers=8) as pool:
            net_info = dict(pool.map(enrich, ips))
        stage("network", "Hosting network (RIPEstat)", "done", count=sum(1 for v in net_info.values() if v.get("asn")))

    if active and live:
        stage("titles", "Page titles (active)", "running")
        with ThreadPoolExecutor(max_workers=8) as pool:
            for r, t in zip(live[:MAX_TITLES], pool.map(lambda r: _title(r["domain"]), live[:MAX_TITLES])):
                r["title"] = t
        stage("titles", "Page titles (active)", "done", count=sum(1 for r in live if r.get("title")))

    for r in rows:
        r["display"] = ".".join(_from_ascii(p) for p in r["domain"].split("."))
        r["age_days"] = _age_days(r.get("created"))
        first_ip = r["ips"][0] if r.get("ips") else None
        r.update({k: v for k, v in (net_info.get(first_ip) or {}).items()})
        age = r["age_days"]
        if not r.get("registered"):
            r["risk"] = "none"
        elif r.get("wildcard"):
            r["risk"] = "low"
        elif r.get("live") and age is not None and age <= 30:
            r["risk"] = "high"
        elif r.get("live") or (age is not None and age <= 90):
            r["risk"] = "medium"
        else:
            r["risk"] = "low"

    order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    rows.sort(key=lambda r: (order[r["risk"]], r["registered"] is not True, not r.get("live"), r.get("age_days") if r.get("age_days") is not None else 99999, r["domain"]))
    stats = {
        "generated": len(rows),
        "possible": total,
        "registered": len(registered),
        "live": len(live),
        "new_live": sum(1 for r in rows if r["risk"] == "high"),
        "unchecked": failed,
    }
    notes = []
    if wildcard:
        notes.append("These endings answer for any name (wildcard DNS), so results under them are uncertain: "
                     + ", ".join("." + s for s in sorted(wildcard)) + ".")
    if not active:
        notes.append("Passive: the lookalike sites were not contacted. Turn on Active checks to read the page titles of live lookalikes.")
    return {
        "domain": apex,
        "techniques": [TECHNIQUES[t] for t in (techniques or list(TECHNIQUES)) if t in TECHNIQUES] or list(TECHNIQUES.values()),
        "mode": "active" if active else "passive",
        "rows": rows,
        "stats": stats,
        "notes": notes,
        "duration_s": round(time.time() - started, 1),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

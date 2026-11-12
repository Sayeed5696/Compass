"""Email header analysis.

Accepts pasted headers or a full .eml file and reports:
- the key fields (From, Reply-To, Return-Path, Subject, Date in IST and UTC)
- the Received chain hop by hop, with delays and which hops can be trusted
- the likely originating IP, or why it is not available
- SPF / DKIM / DMARC results recorded by the receiving server, with alignment
- DKIM signature verification (pure Python RSA) when the full message is given
- Message-ID checks: domain match, sender fingerprint, leaks, time check, DKIM proof
- mismatches between From, Reply-To and Return-Path, and lookalike sender domains
- the details a provider needs for a data request

Compass reports consistency, never proof that an email is genuine.
"""
import base64
import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from . import lookalike
from .discovery import doh
from .psl import registrable_domain

IST = timezone(timedelta(hours=5, minutes=30))

PROVIDER_DOMAINS = [
    ("google.com", "Google"), ("gmail.com", "Google"), ("googlemail.com", "Google"),
    ("outlook.com", "Microsoft"), ("hotmail.com", "Microsoft"), ("office365.com", "Microsoft"), ("microsoft.com", "Microsoft"),
    ("yahoo.com", "Yahoo"), ("yahoodns.net", "Yahoo"), ("yahoo.co.in", "Yahoo"),
    ("zoho.com", "Zoho"), ("zoho.in", "Zoho"), ("zohomail.in", "Zoho"), ("zohomail.com", "Zoho"),
    ("rediffmail.com", "Rediff"), ("icloud.com", "Apple"), ("me.com", "Apple"),
    ("amazonses.com", "Amazon SES"), ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("mcsv.net", "Mailchimp"),
    ("protonmail.ch", "Proton"), ("proton.me", "Proton"),
]
FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.co.in",
             "ymail.com", "rediffmail.com", "zohomail.in", "zohomail.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
             "aol.com", "gmx.com", "mail.com"}
FREE_MAIL_PROVIDER = {"gmail.com": "Google", "googlemail.com": "Google", "outlook.com": "Microsoft", "hotmail.com": "Microsoft",
                      "live.com": "Microsoft", "msn.com": "Microsoft", "yahoo.com": "Yahoo", "yahoo.co.in": "Yahoo",
                      "ymail.com": "Yahoo", "rediffmail.com": "Rediff", "zohomail.in": "Zoho", "zohomail.com": "Zoho",
                      "icloud.com": "Apple", "me.com": "Apple", "proton.me": "Proton", "protonmail.com": "Proton"}

MSGID_FORMATS = [
    ("Gmail (web or app)", r"^CA[A-Za-z0-9_+=\-]{16,}@mail\.gmail\.com$", "Google"),
    ("Gmail", r"@mail\.gmail\.com$", "Google"),
    ("Microsoft 365 / Outlook.com", r"@[A-Za-z0-9.-]*prod\.outlook\.com$", "Microsoft"),
    ("Microsoft Exchange / Outlook", r"@[A-Za-z0-9.-]*\.outlook\.com$", "Microsoft"),
    ("Yahoo Mail", r"@mail\.yahoo\.com$", "Yahoo"),
    ("Zoho Mail", r"@zoho(?:mail)?\.(?:com|in)$", "Zoho"),
    ("Amazon SES", r"@(?:[a-z0-9.-]+\.)?amazonses\.com$", "Amazon SES"),
    ("SendGrid", r"@(?:[a-z0-9.-]+\.)?sendgrid\.net$", "SendGrid"),
    ("Mailchimp", r"@(?:[a-z0-9.-]+\.)?mcsv\.net$", "Mailchimp"),
    ("Python script (smtplib)", r"^\d{11,13}\.\d+\.\d+@", None),
    ("Java program (JavaMail)", r"^-?\d+\.\d+\.\d{13}\.JavaMail\.", None),
    ("Outlook desktop (older)", r"^[0-9a-f]{12}\$[0-9a-f]+\$[0-9a-f]+@", None),
    ("Apple Mail", r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}@", None),
    ("Thunderbird or similar", r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@", None),
]
LEAK_PATTERNS = [
    (r"^localhost(?:\.localdomain)?$", "localhost"),
    (r"^(?:desktop|laptop|win|pc|user)-[a-z0-9]+", "a Windows PC name"),
    (r"\.(?:local|lan|home|localdomain|internal|intranet)$", "an internal network name"),
]
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_BR = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{2,}(?:\d{1,3}(?:\.\d{1,3}){3})?)\]")


# ---------------------------------------------------------------- parsing
def split_message(raw):
    data = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
    data = data.lstrip(b"\r\n")
    idx = data.find(b"\r\n\r\n")
    if idx < 0:
        head, body = data, None
    else:
        head, body = data[: idx + 2], data[idx + 4:]
    headers = []
    for line in head.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            if headers:
                headers[-1][1] += b"\r\n" + line
            continue
        if b":" not in line or line.startswith(b"From "):
            continue
        name = line.split(b":", 1)[0].decode("latin-1").strip()
        if not re.fullmatch(r"[!-9;-~]+", name):
            continue
        headers.append([name, line])
    if body is not None and not body.strip():
        body = None if idx < 0 else body
    return [(n, v) for n, v in headers], body


def _value(raw):
    v = raw.split(b":", 1)[1] if b":" in raw else b""
    text = v.decode("utf-8", "replace")
    return re.sub(r"\r\n[ \t]+", " ", text).strip()


def _decoded(text):
    try:
        return str(make_header(decode_header(text)))
    except Exception:
        return text


class Headers:
    def __init__(self, items):
        self.items = items

    def all(self, name):
        n = name.lower()
        return [_value(v) for k, v in self.items if k.lower() == n]

    def first(self, name):
        vals = self.all(name)
        return vals[0] if vals else None


def _addr(value):
    if not value:
        return None
    name, addr = parseaddr(_decoded(value))
    addr = (addr or "").strip().strip("<>").lower()
    dom = addr.rsplit("@", 1)[1] if "@" in addr else ""
    return {"name": name.strip(), "address": addr, "domain": dom, "org": registrable_domain(dom) if dom else ""}


def _dt(value):
    if not value:
        return None
    try:
        d = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _times(d):
    if not d:
        return None
    u = d.astimezone(timezone.utc)
    return {"utc": u.strftime("%Y-%m-%d %H:%M:%S UTC"), "ist": d.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST"),
            "iso": u.isoformat().replace("+00:00", "Z")}


def provider_of(host):
    h = (host or "").lower().rstrip(".")
    for dom, name in PROVIDER_DOMAINS:
        if h == dom or h.endswith("." + dom):
            return name
    return None


def _ip_info(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return {"ip": str(a), "public": a.is_global, "version": a.version}


# ---------------------------------------------------------------- Received
def parse_received(value):
    main, _, date = value.rpartition(";")
    if not main:
        main, date = value, ""
    flat = re.sub(r"\s+", " ", main).strip()
    out = {"raw": value[:1000]}
    m = re.search(r"\bfrom\s+(.+?)(?=\s+by\s|\s+via\s|\s+with\s|\s+id\s|\s+for\s|$)", flat, re.I)
    from_part = m.group(1) if m else ""
    b = re.search(r"\bby\s+([^\s;()]+)", flat, re.I)
    w = re.search(r"\bwith\s+([^\s;()]+)", flat, re.I)
    out["from_raw"] = from_part
    out["from_host"] = from_part.split()[0].strip("[]()") if from_part else None
    rdns = re.search(r"\(([^\s()\[\]]+\.[a-z]{2,})[\s)\[]", from_part + " ", re.I)
    out["from_rdns"] = rdns.group(1).lower() if rdns else None
    ips = []
    for cand in IPV4.findall(from_part) + IPV6_BR.findall(from_part):
        info = _ip_info(cand)
        if info and info["ip"] not in [x["ip"] for x in ips]:
            ips.append(info)
    out["from_ips"] = ips
    out["by"] = b.group(1).lower().rstrip(".") if b else None
    out["with"] = w.group(1) if w else None
    d = _dt(date.strip())
    out["time"] = _times(d)
    out["_dt"] = d
    return out


# ---------------------------------------------------------------- Authentication-Results
RESULT_RE = re.compile(r"^\s*(spf|dkim|dmarc|compauth|arc|auth|iprev)\s*=", re.I)


def _host_org(host):
    """Registered domain of a mail host name; None for IP literals and bare names."""
    h = (host or "").strip("[]").lower().rstrip(".")
    if not h or "." not in h or _ip_info(h):
        return None
    return registrable_domain(h)


def _parse_one_auth(value):
    v = re.sub(r"^\s*i\s*=\s*\d+\s*;", "", value)  # ARC-Authentication-Results starts with "i=N;"
    parts = v.split(";")
    if parts and RESULT_RE.match(parts[0]):
        serv, rest = None, parts  # Microsoft 365 omits the server name
    else:
        serv, rest = parts[0].strip().split()[0] if parts[0].strip() else None, parts[1:]
    res = {"server": serv, "spf": None, "dkim": [], "dmarc": None, "raw": value[:2000]}
    for part in rest:
        p = part.strip()
        m = re.match(r"(spf|dkim|dmarc|compauth|arc)\s*=\s*([a-zA-Z]+)", p, re.I)
        if not m:
            continue
        kind, result = m.group(1).lower(), m.group(2).lower()
        props = {k.lower(): v.strip('"<>') for k, v in re.findall(r"\b([a-z]+\.[a-z-]+)=([^\s;()]+)", p, re.I)}
        item = {"result": result, "props": props}
        if kind == "spf":
            dom = props.get("smtp.mailfrom", "")
            item["domain"] = dom.rsplit("@", 1)[-1].lower() if dom else props.get("smtp.helo", "").lower()
            res["spf"] = res["spf"] or item
        elif kind == "dkim":
            item["domain"] = (props.get("header.d") or props.get("header.i", "").rsplit("@", 1)[-1] or "").lower()
            res["dkim"].append(item)
        elif kind == "dmarc":
            item["domain"] = (props.get("header.from") or "").lower()
            m2 = re.search(r"p=([a-z]+)", p, re.I)
            item["policy"] = m2.group(1).lower() if m2 else None
            res["dmarc"] = res["dmarc"] or item
    return res


def parse_auth_results(values, arc_values, trusted_orgs, recipient_provider):
    """Pick the authentication results written by the recipient's own mail server.

    A sender can put any Authentication-Results header into a message, so a
    result is trusted only when its server name belongs to the recipient's
    servers (or, for Microsoft 365, which writes no server name, when it is the
    top header and Microsoft received the mail). Otherwise the top header is
    still shown, marked as unverified.
    """
    parsed = [_parse_one_auth(v) for v in values or []]
    for i, res in enumerate(parsed):
        org = _host_org(res["server"]) if res["server"] else None
        if (org and org in trusted_orgs) or (res["server"] is None and i == 0 and recipient_provider == "Microsoft"):
            res["trusted"] = True
            return res
    for v in arc_values or []:
        res = _parse_one_auth(v)
        org = _host_org(res["server"]) if res["server"] else None
        if org and org in trusted_orgs:
            res["trusted"] = True
            return res
    if parsed:
        parsed[0]["trusted"] = False
        return parsed[0]
    return None


# ---------------------------------------------------------------- DKIM verification
def _dkim_records(name):
    """TXT records for a DKIM key, or None if the DNS lookup itself failed."""
    try:
        answers, _nx = doh(name, "TXT")
    except Exception:
        return None
    out = []
    for a in answers:
        if a.get("type") == 16:
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', a.get("data") or "")
            out.append("".join(parts) if parts else a.get("data") or "")
    return out
def _tags(value):
    out = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = re.sub(r"\s+", "", v) if k.strip().lower() in ("b", "bh", "h", "p") else v.strip()
    return out


def _canon_header(raw, relaxed):
    if not relaxed:
        return raw + b"\r\n"
    name, _, value = raw.partition(b":")
    value = value.replace(b"\r\n", b"")
    value = re.sub(rb"[ \t]+", b" ", value).strip(b" \t")
    return name.strip().lower() + b":" + value + b"\r\n"


def _canon_body(body, relaxed):
    body = body or b""
    if relaxed:
        lines = body.split(b"\r\n")
        lines = [re.sub(rb"[ \t]+", b" ", ln).rstrip(b" \t") for ln in lines]
        body = b"\r\n".join(lines)
        while body.endswith(b"\r\n"):
            body = body[:-2]
        return body + b"\r\n" if body else b""
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    if not body.endswith(b"\r\n"):
        body += b"\r\n"
    return body


def _der(buf, i):
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, buf[i:i + ln], i + ln


def _rsa_key(der):
    _, seq, _ = _der(der, 0)
    tag1, first, j = _der(seq, 0)
    if tag1 == 0x30:  # SubjectPublicKeyInfo
        _, bits, _ = _der(seq, j)
        _, inner, _ = _der(bits[1:], 0)
        _, nb, k = _der(inner, 0)
        _, eb, _ = _der(inner, k)
    else:  # bare RSAPublicKey
        nb = first
        _, eb, _ = _der(seq, j)
    return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")


DIGEST_INFO = {"sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
               "sha1": bytes.fromhex("3021300906052b0e03021a05000414")}


def _rsa_verify(n, e, sig, digest, alg):
    k = (n.bit_length() + 7) // 8
    if len(sig) > k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")
    t = DIGEST_INFO[alg] + digest
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expected


def verify_dkim(items, body, sig_raw):
    """Verify one DKIM-Signature header. Returns a result dict."""
    sig_value = _value(sig_raw)
    t = _tags(sig_value)
    d, s, a = (t.get("d") or "").lower(), t.get("s") or "", (t.get("a") or "rsa-sha256").lower()
    signed = [h.strip().lower() for h in (t.get("h") or "").split(":") if h.strip()]
    out = {"domain": d, "selector": s, "algorithm": a, "signed_headers": signed,
           "covers_message_id": "message-id" in signed, "status": "not_checked", "reason": ""}
    if not d or not s or not t.get("b") or not t.get("bh"):
        out.update(status="fail", reason="Signature header is incomplete.")
        return out
    if a not in ("rsa-sha256", "rsa-sha1"):
        out.update(reason=f"Algorithm {a} is not supported by Compass.")
        return out
    alg = a.split("-")[1]
    hfn = hashlib.sha256 if alg == "sha256" else hashlib.sha1
    canon = (t.get("c") or "simple/simple").lower().split("/")
    hrel = canon[0] == "relaxed"
    brel = len(canon) > 1 and canon[1] == "relaxed"
    if body is None:
        out.update(reason="Only headers were provided. Upload the full .eml to verify the signature.")
        return out
    cb = _canon_body(body, brel)
    if t.get("l"):
        try:
            cb = cb[: int(t["l"])]
        except ValueError:
            pass
    try:
        bh_ok = base64.b64encode(hfn(cb).digest()).decode() == t["bh"]
    except Exception:
        bh_ok = False
    out["body_hash_ok"] = bh_ok
    # Select signed headers bottom-up.
    pool = {}
    for name, raw in items:
        pool.setdefault(name.lower(), []).append(raw)
    data = b""
    for h in signed:
        lst = pool.get(h)
        if lst:
            data += _canon_header(lst.pop(), hrel)
    name, _, value = sig_raw.partition(b":")
    value = re.sub(rb"(^|;)(\s*b\s*=)[^;]*", rb"\1\2", value)
    data += _canon_header(name + b":" + value, hrel).rstrip(b"\r\n")
    # Public key from DNS. A failed lookup is not evidence about the domain.
    recs = _dkim_records(f"{s}._domainkey.{d}")
    if recs is None:
        out.update(status="not_checked",
                   reason="Could not look up the signing key because the DNS lookup failed. Check this PC's internet access and run the analysis again.")
        return out
    key = None
    for rec in recs:
        kt = _tags(rec)
        if "p" in kt:
            key = kt
            break
    if key is None:
        out.update(status="fail", reason=f"{d} publishes no DKIM key at {s}._domainkey.{d}.")
        return out
    if not key.get("p"):
        out.update(status="fail", reason="The signing key has been revoked by the domain.")
        return out
    if (key.get("k") or "rsa").lower() != "rsa":
        out.update(reason="Key type is not RSA; not supported.")
        return out
    try:
        n, e = _rsa_key(base64.b64decode(key["p"]))
        ok = _rsa_verify(n, e, base64.b64decode(t["b"]), hfn(data).digest(), alg)
    except Exception:
        out.update(status="fail", reason="Could not read the signature or the published key.")
        return out
    if ok and bh_ok:
        out.update(status="pass", reason=f"Signature verified with the key published by {d}.")
    elif ok:
        out.update(status="fail", reason="Headers verify, but the body was changed after signing.")
    else:
        out.update(status="fail", reason="Signature did not verify. The message was altered, or the text was changed when copied.")
    return out


# ---------------------------------------------------------------- Message-ID
def message_id_checks(msgid, from_a, hops, date_dt, xmailer, dkim_aligned, authorised_by):
    checks = []
    if not msgid:
        checks.append({"id": "format", "title": "Message-ID present", "state": "warn", "label": "Missing",
                       "text": "The email has no Message-ID. Real mail systems almost always add one."})
        return {"value": None, "format": None, "provider": None, "checks": checks}
    raw = msgid.strip()
    m = re.fullmatch(r"<([^<>@\s]+)@([^<>@\s]+)>", raw)
    if not m:
        checks.append({"id": "format", "title": "Well-formed", "state": "warn", "label": "Malformed",
                       "text": f"The Message-ID {raw[:120]} does not have the usual <left@right> form."})
        left, right = (raw.strip("<>").split("@", 1) + [""])[:2]
    else:
        left, right = m.group(1), m.group(2).lower()
    fmt, fprov = None, None
    for label, pat, prov in MSGID_FORMATS:
        if re.search(pat, f"{left}@{right}", re.I if "A-F" not in pat else 0):
            fmt, fprov = label, prov
            break
    right_org = registrable_domain(right) if "." in right else right
    from_org = (from_a or {}).get("org", "")

    # 1. Domain match
    hop_providers = {provider_of(h.get("by")) for h in hops if h.get("by")} - {None}
    if from_org and right_org == from_org:
        checks.append({"id": "domain", "title": "Domain match", "state": "ok", "label": "Consistent",
                       "text": f"The Message-ID domain matches the From domain ({from_org})."})
    elif fprov and from_org and FREE_MAIL_PROVIDER.get(from_org) == fprov:
        checks.append({"id": "domain", "title": "Domain match", "state": "ok", "label": "Consistent",
                       "text": f"Written by {fprov}, which hosts the From address ({from_org})."})
    elif fprov and (dkim_aligned or authorised_by):
        proof = "its own DKIM signature verifies" if dkim_aligned else f"{authorised_by} passed for {from_org}"
        checks.append({"id": "domain", "title": "Domain match", "state": "ok", "label": "Consistent",
                       "text": f"Written by {fprov}. {from_org} uses {fprov} for its mail, and {proof}, so {fprov} is allowed to send for it."})
    elif fprov and from_org:
        checks.append({"id": "domain", "title": "Domain match", "state": "bad", "label": "Inconsistent",
                       "text": f"The Message-ID ends in @{right}, so it was written by {fprov}, but From claims {from_org}, and neither a "
                               f"{from_org} DKIM signature nor its SPF/DMARC confirms that {fprov} may send for it. It was most likely sent "
                               f"from a {fprov} account, not from {from_org}'s mail system."})
    elif from_org and right_org and right_org != from_org:
        state = "warn"
        checks.append({"id": "domain", "title": "Domain match", "state": state, "label": "Differs",
                       "text": f"The Message-ID domain ({right}) is not the From domain ({from_org}). This is normal for mailing services "
                               "and company mail servers, but worth noting for personal mail."})
    else:
        checks.append({"id": "domain", "title": "Domain match", "state": "muted", "label": "Not checked",
                       "text": "There is no From domain to compare with."})

    # 2. Sender fingerprint
    if fmt:
        agree = None
        if fprov:
            agree = fprov in hop_providers or any(provider_of(h.get("from_rdns") or h.get("from_host")) == fprov for h in hops)
        xm = (xmailer or "").lower()
        mailer_clash = bool(xm) and fprov == "Google" and ("outlook" in xm or "phpmailer" in xm)
        if agree is False or mailer_clash:
            checks.append({"id": "fingerprint", "title": "Sender fingerprint", "state": "bad", "label": "Inconsistent",
                           "text": f"The Message-ID looks like {fmt}, but " + (
                               f"no {fprov} server appears in the Received chain." if agree is False else
                               f"the X-Mailer header says {xmailer}.") + " The ID may have been copied to look genuine."})
        else:
            extra = f" The Received chain agrees: a {fprov} server handled it." if agree else ""
            state = "warn" if fmt.startswith(("Python", "Java")) else "ok"
            checks.append({"id": "fingerprint", "title": "Sender fingerprint", "state": state,
                           "label": "Script" if state == "warn" else "Consistent",
                           "text": f"Format matches {fmt}.{extra}" + (" Mail written by a script is common in bulk phishing." if state == "warn" else "")})
    else:
        checks.append({"id": "fingerprint", "title": "Sender fingerprint", "state": "none", "label": "No known format",
                       "text": f"The format does not match a known mail service. Right-hand side: {right}."
                               + (f" X-Mailer: {xmailer}." if xmailer else "")})

    # 3. Leaks
    leak = None
    for pat, what in LEAK_PATTERNS:
        if re.search(pat, right, re.I):
            leak = what
            break
    if not leak and _ip_info(right.strip("[]")):
        leak = "an IP address"
    if leak:
        checks.append({"id": "leaks", "title": "Leaks and red flags", "state": "warn", "label": "Found",
                       "text": f"The Message-ID ends in @{right}, which reveals {leak} of the sending machine. Record it as a lead."})
    else:
        checks.append({"id": "leaks", "title": "Leaks and red flags", "state": "none", "label": "None found",
                       "text": "No localhost, PC name or internal network name in the Message-ID."})

    # 4. Time check
    ts = None
    mt = re.match(r"^(\d{11,13})\.\d+\.\d+$", left)
    if mt and fmt and fmt.startswith("Python"):
        ts = datetime.fromtimestamp(int(mt.group(1)) / 100, tz=timezone.utc)
    mj = re.match(r"^-?\d+\.\d+\.(\d{13})\.JavaMail\.", left)
    if mj:
        ts = datetime.fromtimestamp(int(mj.group(1)) / 1000, tz=timezone.utc)
    if ts and date_dt:
        diff = abs((ts - date_dt).total_seconds())
        if diff <= 2 * 86400:
            checks.append({"id": "time", "title": "Time check", "state": "ok", "label": "Consistent",
                           "text": f"The Message-ID carries a timestamp ({_times(ts)['ist']}) that matches the Date header."})
        else:
            checks.append({"id": "time", "title": "Time check", "state": "bad", "label": "Inconsistent",
                           "text": f"The Message-ID timestamp ({_times(ts)['ist']}) is {round(diff / 86400)} days away from the Date header."})
    else:
        checks.append({"id": "time", "title": "Time check", "state": "muted", "label": "Not checked",
                       "text": "This format carries no readable timestamp to compare with the Date header."})

    return {"value": raw, "left": left, "right": right, "format": fmt, "provider": fprov, "checks": checks}


# ---------------------------------------------------------------- main
def analyze(raw, source="paste"):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    items, body = split_message(raw)
    if not items:
        raise ValueError("No email headers were found. Paste the full headers (they start with lines like 'Received:' or 'From:').")
    h = Headers(items)
    from_a = _addr(h.first("From"))
    reply_a = _addr(h.first("Reply-To"))
    rp_a = _addr(h.first("Return-Path"))
    sender_a = _addr(h.first("Sender"))
    to_list = [a.lower() for _, a in getaddresses([_decoded(v) for v in h.all("To") + h.all("Cc")]) if a]
    date_dt = _dt(h.first("Date"))
    subject = _decoded(h.first("Subject") or "")
    msgid = h.first("Message-ID")
    xmailer = h.first("X-Mailer") or h.first("User-Agent")

    # Received chain: headers are newest first; hop 1 is the earliest.
    recs = [parse_received(v) for v in h.all("Received")]
    hops = list(reversed(recs))
    prev = None
    for i, hop in enumerate(hops, 1):
        hop["hop"] = i
        if hop["_dt"] and prev is not None:
            hop["delay_s"] = int((hop["_dt"] - prev).total_seconds())
        if hop["_dt"]:
            prev = hop["_dt"]
    # Trust: hops added by the recipient's own servers, read from the top down.
    # A hop whose "by" is an IP address (Gmail's internal first hop) is the
    # recipient's own too.
    recipient_org = next((_host_org(hop.get("by")) for hop in recs if _host_org(hop.get("by"))), None)
    recipient_provider = None
    handoff = None
    for hop in recs:  # newest first
        by_org = _host_org(hop.get("by"))
        if (by_org is None and hop.get("by")) or (by_org is not None and by_org == recipient_org):
            hop["trust"] = "recipient"
            recipient_provider = recipient_provider or provider_of(hop.get("by"))
            if handoff is None and hop.get("from_ips"):
                if _host_org(hop.get("from_rdns") or hop.get("from_host")) != recipient_org:
                    handoff = hop
        else:
            break
    trusted_orgs = {recipient_org} | {_host_org(hp.get("by")) for hp in recs if hp.get("trust") == "recipient"}
    trusted_orgs.discard(None)
    for hop in hops:
        if not hop.get("trust"):
            prov = provider_of(hop.get("by"))
            hop["trust"] = "provider" if prov else "sender"
            hop["provider"] = prov
        hop.pop("_dt", None)

    # Originating IP.
    origin = {"state": "warn", "ip": None, "text": ""}
    hdr_ip = None
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP", "X-Client-IP"):
        v = h.first(name)
        if v:
            cand = IPV4.findall(v) or re.findall(r"[0-9a-fA-F:]{3,}", v)
            info = _ip_info(cand[0]) if cand else None
            if info:
                hdr_ip = (name, info)
                break
    earliest_public = None
    for hop in hops:
        for ipx in hop.get("from_ips") or []:
            if ipx["public"]:
                earliest_public = (hop, ipx)
                break
        if earliest_public:
            break
    msg_fmt_provider = None
    for label, pat, prov in MSGID_FORMATS:
        if msgid and re.search(pat, msgid.strip("<> "), re.I if "A-F" not in pat else 0):
            msg_fmt_provider = prov
            break
    sending_provider = msg_fmt_provider or (hops and provider_of(hops[0].get("by")))
    route_provider = next((hp["provider"] for hp in hops if hp.get("provider")), None) or \
        (provider_of(handoff.get("from_rdns") or handoff.get("from_host")) if handoff else None)
    if hdr_ip and hdr_ip[1]["public"]:
        if route_provider:
            origin = {"state": "ok", "ip": hdr_ip[1]["ip"], "how": hdr_ip[0],
                      "text": f"Reported in the {hdr_ip[0]} header, which {route_provider} adds when someone sends from its service."}
        else:
            origin = {"state": "warn", "ip": hdr_ip[1]["ip"], "how": hdr_ip[0],
                      "text": f"Reported in the {hdr_ip[0]} header. No mail provider appears in the route, so the sender could have "
                              "written this header. Confirm the IP with the provider before relying on it."}
    elif earliest_public and earliest_public[0].get("trust") != "recipient" and not provider_of(earliest_public[0].get("from_rdns") or earliest_public[0].get("from_host")):
        hop, ipx = earliest_public
        origin = {"state": "warn", "ip": ipx["ip"], "how": f"hop {hop['hop']}",
                  "text": f"Earliest public IP in the Received chain (hop {hop['hop']}). This hop was added "
                          + ("by a mail provider." if hop["trust"] == "provider" else "on the sender's side and could be forged.")}
    elif (handoff and not route_provider and not provider_of(handoff.get("from_rdns") or handoff.get("from_host"))
          and any(x["public"] for x in handoff.get("from_ips") or [])):
        ipx = next(x for x in handoff["from_ips"] if x["public"])
        origin = {"state": "warn", "ip": ipx["ip"], "how": f"hop {handoff['hop']}",
                  "text": "No mail provider appears between the sender and your server, so the IP that delivered the message "
                          "is likely the sender's own machine or server. Your server recorded it, so it cannot be forged."}
    else:
        who = route_provider or sending_provider or "the sender's mail provider"
        origin = {"state": "warn", "ip": None,
                  "text": f"Sender IP not available. {who} does not record the sender's IP for mail sent from its website or app. "
                          f"Request it from {who} using the Message-ID and time below."}
    if handoff and handoff.get("from_ips"):
        pub = [x for x in handoff["from_ips"] if x["public"]]
        if pub:
            origin["delivered_by"] = pub[0]["ip"]
            origin["delivered_by_host"] = handoff.get("from_rdns") or handoff.get("from_host")

    # Authentication, as recorded by the recipient's own server.
    auth = parse_auth_results(h.all("Authentication-Results"), h.all("ARC-Authentication-Results"), trusted_orgs, recipient_provider)
    trusted = bool(auth and auth.get("trusted"))
    received_spf = h.first("Received-SPF")
    from_org = (from_a or {}).get("org", "")

    def aligned(dom):
        return bool(dom) and registrable_domain(dom) == from_org

    authn = []
    if auth and auth.get("spf"):
        s = auth["spf"]
        st = "ok" if s["result"] == "pass" and aligned(s.get("domain")) else "warn" if s["result"] in ("pass", "neutral", "none", "softfail") else "bad"
        txt = {"pass": "Passed", "fail": "Failed", "softfail": "Soft fail", "neutral": "Neutral", "none": "No SPF record"}.get(s["result"], s["result"].title())
        note = f"Checked for {s.get('domain') or 'the envelope sender'}."
        if s["result"] == "pass" and not aligned(s.get("domain")) and from_org:
            note += f" That is not the From domain ({from_org}), so it only proves {s.get('domain')} sent it."
            txt += ", not aligned"
        authn.append({"id": "spf", "name": "SPF", "state": st, "label": txt, "text": note})
    elif received_spf:
        res = received_spf.split()[0].lower()
        authn.append({"id": "spf", "name": "SPF", "state": "ok" if res == "pass" else "warn" if res in ("neutral", "softfail", "none") else "bad",
                      "label": res.title(), "text": "From the Received-SPF header."})
    else:
        authn.append({"id": "spf", "name": "SPF", "state": "muted", "label": "Not recorded", "text": "The receiving server recorded no SPF result."})
    dk = (auth or {}).get("dkim") or []
    if dk:
        best = next((x for x in dk if x["result"] == "pass" and aligned(x.get("domain"))), None) or \
            next((x for x in dk if x["result"] == "pass"), None) or dk[0]
        st = "ok" if best["result"] == "pass" and aligned(best.get("domain")) else "warn" if best["result"] in ("pass", "none", "neutral") else "bad"
        lab = {"pass": "Passed", "fail": "Failed", "none": "Not signed", "neutral": "Neutral", "permerror": "Error", "temperror": "Error"}.get(best["result"], best["result"].title())
        note = f"Signed by d={best.get('domain') or '?'}."
        if best["result"] == "pass" and not aligned(best.get("domain")) and from_org:
            lab += ", not aligned"
            note += f" Not by the From domain ({from_org})."
        authn.append({"id": "dkim", "name": "DKIM", "state": st, "label": lab, "text": note})
    else:
        authn.append({"id": "dkim", "name": "DKIM", "state": "muted", "label": "Not recorded", "text": "The receiving server recorded no DKIM result."})
    if auth and auth.get("dmarc"):
        dm = auth["dmarc"]
        st = "ok" if dm["result"] == "pass" else "bad" if dm["result"] == "fail" else "none"
        lab = {"pass": "Passed", "fail": "Failed", "none": "No policy found", "bestguesspass": "Best-guess pass"}.get(dm["result"], dm["result"].title())
        note = f"For {dm.get('domain') or from_org or 'the From domain'}" + (f", policy p={dm['policy']}." if dm.get("policy") else ".")
        if dm["result"] == "none":
            note = f"{dm.get('domain') or from_org} publishes no DMARC record, so nothing stops its name being used this way."
        authn.append({"id": "dmarc", "name": "DMARC", "state": st, "label": lab, "text": note})
    else:
        authn.append({"id": "dmarc", "name": "DMARC", "state": "muted", "label": "Not recorded", "text": "The receiving server recorded no DMARC result."})
    if auth and not trusted:
        # Not written by the recipient's server: a sender could have added it.
        who = auth.get("server") or "an unnamed server"
        for a in authn:
            if a["label"] == "Not recorded":
                continue
            if a["state"] in ("ok", "none"):
                a["state"] = "warn"
            a["label"] += " (unverified)"
            a["text"] += f" Recorded by {who}, not by your own mail server, so the sender could have written it."

    # DKIM signatures in the message.
    sigs = []
    for name, rawh in items:
        if name.lower() == "dkim-signature":
            try:
                sigs.append(verify_dkim(items, body, rawh))
            except Exception as e:  # never let one bad signature stop the analysis
                sigs.append({"status": "fail", "reason": f"Could not check this signature: {e}", "domain": "", "covers_message_id": False})

    # Only verified evidence can show that the From domain authorised the sender:
    # a DKIM signature Compass verified, or results from the recipient's own server.
    dkim_aligned = any(sg.get("status") == "pass" and aligned(sg.get("domain")) for sg in sigs) or \
        (trusted and any(x["result"] == "pass" and aligned(x.get("domain")) for x in dk))
    authorised_by = None
    if trusted and auth.get("dmarc") and auth["dmarc"]["result"] == "pass":
        authorised_by = "DMARC"
    elif trusted and auth.get("spf") and auth["spf"]["result"] == "pass" and aligned(auth["spf"].get("domain")):
        authorised_by = "SPF"

    if authorised_by == "DMARC":
        for a in authn:
            if a["id"] in ("spf", "dkim") and a["state"] == "warn" and a["label"].startswith("Passed, not aligned"):
                a["state"], a["label"] = "ok", "Passed"
                a["text"] += " DMARC passed through the other check, which is normal for mail sent through a service."
    mid = message_id_checks(msgid, from_a, hops, date_dt, xmailer, dkim_aligned, authorised_by)
    # 5. DKIM proof for the Message-ID.
    covering = [s for s in sigs if s.get("covers_message_id")]
    passed = [s for s in covering if s.get("status") == "pass"]
    if passed:
        s = passed[0]
        mid["checks"].append({"id": "dkim", "title": "DKIM proof", "state": "ok", "label": "Verified",
                              "text": f"The Message-ID is one of the headers signed by {s['domain']}, and the signature verifies. "
                                      f"It is authentic for {s['domain']}."})
    elif covering and any(s.get("status") == "fail" for s in covering):
        s = next(s for s in covering if s.get("status") == "fail")
        mid["checks"].append({"id": "dkim", "title": "DKIM proof", "state": "warn", "label": "Did not verify",
                              "text": f"Signed by {s['domain']}, but: {s['reason']}"})
    elif covering:
        s = covering[0]
        mid["checks"].append({"id": "dkim", "title": "DKIM proof", "state": "muted", "label": "Not checked",
                              "text": f"The Message-ID is signed by {s['domain']}. {s['reason'] or 'Upload the full .eml to verify it.'}"})
    elif sigs:
        mid["checks"].append({"id": "dkim", "title": "DKIM proof", "state": "none", "label": "Not signed",
                              "text": "The message has a DKIM signature, but the Message-ID is not one of the signed headers."})
    else:
        mid["checks"].append({"id": "dkim", "title": "DKIM proof", "state": "none", "label": "No signature",
                              "text": "The message carries no DKIM signature."})

    # Mismatches and lookalikes.
    mism = []
    if from_a and reply_a and reply_a["address"] and reply_a["address"] != from_a["address"]:
        webmail = from_a["domain"] in FREE_MAIL
        if reply_a["org"] != from_a["org"] or webmail:
            if webmail and reply_a["org"] == from_a["org"]:
                text = (f"Replies go to a different {FREE_MAIL_PROVIDER.get(from_a['domain'], 'webmail')} account ({reply_a['address']}), "
                        f"not to the sender ({from_a['address']}). Anyone can open such accounts, and this pattern is common in "
                        "payment and impersonation scams.")
            else:
                text = f"Replies go to {reply_a['address']}, not to {from_a['address']}."
            mism.append({"state": "bad", "label": "Mismatch", "title": "From and Reply-To differ", "text": text,
                         "pivot": reply_a["address"] if reply_a["domain"] not in FREE_MAIL else None})
        else:
            mism.append({"state": "warn", "label": "Differs", "title": "Reply-To is another address on the same domain",
                         "text": f"Replies go to {reply_a['address']}."})
    if from_a and rp_a and rp_a["org"] and rp_a["org"] != from_a["org"]:
        bad = rp_a["domain"] in FREE_MAIL and from_a["domain"] not in FREE_MAIL
        state = "bad" if bad else ("none" if authorised_by == "DMARC" else "warn")
        mism.append({"state": state, "label": "Mismatch" if bad else "Differs", "title": "From and Return-Path differ",
                     "text": f"Bounces go to {rp_a['address']}." + (" A personal webmail account sent this, not the organisation." if bad else
                                                                   " This is normal for newsletters and mailing services."),
                     "pivot": rp_a["address"] if rp_a["domain"] not in FREE_MAIL else None})
    if from_a and from_a["name"]:
        em = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", from_a["name"])
        if em and em.group(0).lower() != from_a["address"]:
            mism.append({"state": "bad", "label": "Spoofed name", "title": "Display name shows a different address",
                         "text": f"The name shows {em.group(0)} but the real address is {from_a['address']}."})
    extra = [registrable_domain(a.rsplit("@", 1)[1]) for a in to_list if "@" in a]
    for label, addr in (("From", from_a), ("Reply-To", reply_a), ("Return-Path", rp_a)):
        if addr and addr["domain"] and addr["domain"] not in FREE_MAIL:
            brand, why, strong = lookalike.imitates_known(addr["domain"], extra=[e for e in extra if e and e != addr["org"]])
            if brand and strong:
                mism.append({"state": "bad", "label": "Lookalike", "title": f"{label} domain imitates {brand}",
                             "text": f"{addr['domain']} {why} to imitate {brand}.", "pivot": addr["domain"], "lookalike_of": brand})
            elif brand:
                mism.append({"state": "warn", "label": "Similar name", "title": f"{label} domain resembles {brand}",
                             "text": f"{addr['domain']} looks similar to {brand}: it {why}. Organisations also register names like this "
                                     "for their own services, so check who owns it before relying on it.",
                             "pivot": addr["domain"], "lookalike_of": brand})
    if date_dt and recs and recs[0].get("time"):
        top_dt = _dt(h.all("Received")[0].rpartition(";")[2].strip())
        if top_dt:
            skew = (top_dt - date_dt).total_seconds()
            if skew < -3600 or skew > 2 * 86400:
                mism.append({"state": "warn", "label": "Time skew", "title": "Date header does not match delivery time",
                             "text": f"The Date header is {abs(round(skew / 3600))} hours {'after' if skew < 0 else 'before'} your server received it."})
    for hop in hops[:2]:
        mh = re.search(r"\bE?HELO[= ]\s*([^\s()\[\]]+)", hop.get("from_raw") or "", re.I)
        helo = (mh.group(1) if mh else hop.get("from_host")) or ""
        if re.search(r"^(?:desktop|laptop|win|pc|user)-[a-z0-9]+", helo, re.I) or re.search(r"\.(?:local|lan|home|localdomain)$", helo, re.I):
            mism.append({"state": "warn", "label": "Found", "title": "Sender's computer name is visible",
                         "text": f"Hop {hop['hop']} shows the sending machine introduced itself as {helo}. Record it as a lead."})
            break
    if xmailer and re.search(r"phpmailer|swiftmailer|python|smtplib|bulk|mass", xmailer, re.I):
        mism.append({"state": "warn", "label": "Script", "title": "Sent by a mailing script", "text": f"X-Mailer: {xmailer}."})

    # Verdict.
    reds = [c for c in mid["checks"] if c["state"] == "bad"] + [m for m in mism if m["state"] == "bad"] + [a for a in authn if a["state"] == "bad"]
    ambers = [c for c in mid["checks"] if c["state"] == "warn"] + [m for m in mism if m["state"] == "warn"] + [a for a in authn if a["state"] == "warn"]
    if reds:
        verdict, vstate = "Suspicious", "bad"
    elif ambers:
        verdict, vstate = "Inconsistent", "warn"
    else:
        verdict, vstate = "Consistent", "ok"
    headline = ""
    if any(m.get("lookalike_of") and m["state"] == "bad" for m in mism):
        headline = "Likely spoofed: the sender's domain imitates a known domain"
    elif any(c["id"] == "domain" and c["state"] == "bad" for c in mid["checks"]):
        headline = f"Likely spoofed: sent from a {mid['provider']} account, not from the claimed sender's mail system"
    elif reds:
        headline = "Signs of spoofing found"
    elif ambers:
        headline = "Some details do not line up; check them before relying on this email"
    else:
        headline = "The headers are consistent with the claimed sender"

    # For a data request.
    acct = None
    imitating = any(m.get("lookalike_of") and m["state"] == "bad" for m in mism)
    if route_provider:
        req_provider = route_provider
    elif authorised_by and from_org and not imitating and mid.get("provider"):
        req_provider = f"{mid['provider']} (handles mail for {from_org})"
    elif authorised_by and from_org and not imitating:
        req_provider = f"{from_org} (its own mail servers sent this)"
    elif origin.get("ip") and origin.get("how", "").startswith("hop"):
        req_provider = f"The network that owns {origin['ip']} (investigate the IP to find it)"
    elif origin.get("delivered_by"):
        req_provider = f"The network that owns {origin['delivered_by']} (investigate the IP to find it)"
    else:
        req_provider = mid.get("provider") or sending_provider
    if rp_a and rp_a["domain"] in FREE_MAIL:
        acct = rp_a["address"]
        req_provider = FREE_MAIL_PROVIDER.get(rp_a["domain"], req_provider)
    elif from_a and from_a["domain"] in FREE_MAIL:
        acct = from_a["address"]
        req_provider = FREE_MAIL_PROVIDER.get(from_a["domain"], req_provider)
    request = {"provider": req_provider or (from_org or "the sending organisation"), "account": acct or (from_a or {}).get("address"),
               "message_id": msgid, "sent": _times(date_dt)}

    to_pivot = sorted({x for x in [(from_a or {}).get("domain"), (reply_a or {}).get("domain"), (rp_a or {}).get("domain")] if x})
    return {
        "source": source,
        "full_message": body is not None,
        "verdict": verdict,
        "verdict_state": vstate,
        "headline": headline,
        "finding_counts": {"red": len(reds), "amber": len(ambers)},
        "fields": {
            "from": from_a, "reply_to": reply_a, "return_path": rp_a, "sender": sender_a,
            "to": to_list[:20], "subject": subject, "date": _times(date_dt), "date_raw": h.first("Date"),
            "message_id": msgid, "x_mailer": xmailer,
        },
        "authentication": authn,
        "auth_server": (auth or {}).get("server"),
        "dkim_signatures": sigs,
        "message_id": mid,
        "mismatches": mism,
        "hops": hops,
        "origin": origin,
        "request": request,
        "domains": to_pivot,
        "header_count": len(items),
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

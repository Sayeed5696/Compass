import hashlib
import ipaddress
import re
from urllib.parse import urlparse

HASH_PATTERNS = {
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
}

def refang(value):
    """Undo common defanging: hxxp://, [.], (.), {.}, [dot], [:], [@]."""
    v = (value or "").strip().strip("'\"<>`")
    v = re.sub(r"^h[x*]{2}p(s?)://", r"http\1://", v, flags=re.I)
    v = re.sub(r"^fxp://", "ftp://", v, flags=re.I)
    v = re.sub(r"\s*[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]\s*", ".", v, flags=re.I)
    v = re.sub(r"\[\s*:\s*\]", ":", v)
    v = re.sub(r"\[\s*(?:@|at)\s*\]", "@", v, flags=re.I)
    v = v.replace("[://]", "://")
    return v


def detect_ioc(value):
    original = value
    value = refang(value)
    if not value:
        return {"type": "unknown", "original": original, "normalized": ""}

    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)
        if parsed.hostname:
            return {"type": "url", "original": original, "normalized": value, "hostname": parsed.hostname.lower()}

    try:
        ip = ipaddress.ip_address(value)
        return {
            "type": "ip" if ip.version == 4 else "ipv6",
            "original": original,
            "normalized": str(ip),
            "version": ip.version,
        }
    except ValueError:
        pass

    for kind, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(value):
            return {"type": kind, "original": original, "normalized": value.lower()}

    # Conservative domain validation; internationalized names may be supplied in IDNA form.
    domain = value.rstrip(".").lower()
    if len(domain) <= 253 and "." in domain and all(
        0 < len(part) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part, re.I)
        for part in domain.split(".")
    ):
        return {"type": "domain", "original": original, "normalized": domain}

    return {"type": "unknown", "original": original, "normalized": value}

def file_hashes(data):
    return {"md5": hashlib.md5(data).hexdigest()}

def url_parts(url):
    p = urlparse(url)
    return {
        "scheme": p.scheme,
        "hostname": (p.hostname or "").lower(),
        "port": p.port,
        "path": p.path or "/",
        "query": p.query,
        "fragment": p.fragment,
        "username": p.username,
        "has_password": bool(p.password),
    }

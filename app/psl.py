"""Public Suffix List helpers (bundled list, no network access needed).

`registrable_domain("a.b.example.co.in") -> "example.co.in"`
"""
import threading
from pathlib import Path

PSL_FILE = Path(__file__).resolve().parent / "data" / "public_suffix_list.dat"

_rules = None
_lock = threading.Lock()


def _load():
    global _rules
    with _lock:
        if _rules is not None:
            return _rules
        normal, wildcard, exception = set(), set(), set()
        try:
            text = PSL_FILE.read_text(encoding="utf-8")
        except OSError:
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            try:
                rule = rule.encode("idna").decode("ascii") if not rule.isascii() else rule
            except Exception:
                pass
            if rule.startswith("!"):
                exception.add(rule[1:])
            elif rule.startswith("*."):
                wildcard.add(rule[2:])
            else:
                normal.add(rule)
        _rules = (normal, wildcard, exception)
        return _rules


def public_suffix(host):
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    normal, wildcard, exception = _load()
    labels = host.split(".")
    # Walk from the longest candidate to the shortest; first match wins
    # (the PSL algorithm picks the longest matching rule).
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            return ".".join(labels[i + 1:])
        if candidate in normal:
            return candidate
        parent = ".".join(labels[i + 1:])
        if parent and parent in wildcard:
            return candidate
    # Default rule "*": the last label is the suffix.
    return labels[-1]


def registrable_domain(host):
    host = (host or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return host
    suffix = public_suffix(host)
    if not suffix or suffix == host:
        return host
    rest = host[: -(len(suffix) + 1)]
    if not rest:
        return host
    return rest.split(".")[-1] + "." + suffix


def is_under(host, apex):
    host = (host or "").lower().rstrip(".")
    apex = (apex or "").lower().rstrip(".")
    return bool(host) and bool(apex) and (host == apex or host.endswith("." + apex))

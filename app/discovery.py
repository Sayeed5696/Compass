"""Compass discovery engine: subdomains, linked IPs and related domains.

Domain input  -> parent domain (Public Suffix List) -> passive sources in
                 parallel -> clean -> live DNS validation (DoH) -> group by IP
                 -> enrich IPs -> related domains, mail infrastructure and
                 possible origin servers behind a CDN.
IP input      -> reverse IP from passive sources -> check which domains still
                 resolve to the IP -> network, exposure and anonymity context.

Passive mode (default) never connects to the target. Active mode adds a
direct TLS certificate fetch and a small subdomain wordlist.
"""
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import config, net
from .psl import is_under, public_suffix, registrable_domain

MAX_RESOLVE = 400          # hostnames validated through DNS per investigation
MAX_ENRICH_BASIC = 40      # IPs enriched with ASN / prefix / country (RIPEstat)
MAX_ENRICH_EXPOSURE = 25   # IPs looked up in Shodan InternetDB
MAX_ENRICH_FLAGS = 12      # IPs looked up in ipapi.is (VPN/proxy/datacenter flags)
MAX_IP_VALIDATE = 150      # domains re-resolved when investigating an IP
SHARED_CERT_LIMIT = 50     # certificates listing more names than this are treated as shared
SHARED_HOSTING_DOMAINS = 40

VT_LIMIT = net.limiter("virustotal", int(os.environ.get("COMPASS_VT_PER_MIN", "4") or 4))

SOURCE_LABELS = {
    "dns": "Live DNS (DoH)",
    "crtsh": "crt.sh certificate logs",
    "certspotter": "CertSpotter certificate logs",
    "vt_subdomains": "VirusTotal subdomains",
    "vt_resolutions": "VirusTotal passive DNS",
    "otx": "AlienVault OTX passive DNS",
    "urlscan": "urlscan.io scans",
    "hackertarget": "HackerTarget DNS dataset",
    "wayback": "Wayback Machine archive",
    "securitytrails": "SecurityTrails",
    "bruteforce": "Wordlist brute-force (active)",
    "tls_active": "Direct TLS certificate (active)",
    "resolve": "Validate subdomains (DNS)",
    "cohost": "Co-hosted domains",
    "ptr": "Reverse DNS (PTR)",
    "internetdb": "Shodan InternetDB",
    "ripestat": "RIPEstat network data",
    "ipapi": "ipapi.is (VPN / proxy / datacenter)",
    "tor": "Tor exit-node list",
    "enrich": "Enrich linked IPs",
    "validate": "Check current DNS for each domain",
}

# Edge networks where many unrelated sites share the same IPs.
CDN_ASNS = {
    13335: "Cloudflare", 209242: "Cloudflare", 20940: "Akamai", 16625: "Akamai", 12222: "Akamai",
    54113: "Fastly", 19551: "Imperva", 30148: "Sucuri", 60068: "CDN77", 15133: "Edgio",
    22822: "Edgio", 200325: "Bunny CDN", 33438: "StackPath",
}
CDN_KEYWORDS = {
    "CLOUDFLARE": "Cloudflare", "AKAMAI": "Akamai", "FASTLY": "Fastly", "INCAPSULA": "Imperva",
    "IMPERVA": "Imperva", "SUCURI": "Sucuri", "CDN77": "CDN77", "EDGECAST": "Edgio",
    "LIMELIGHT": "Edgio", "STACKPATH": "StackPath", "BUNNY": "Bunny CDN", "CLOUDFRONT": "Amazon CloudFront",
}
# Large clouds / shared web hosts: an IP here may be dedicated or shared.
HOSTING_ASNS = {
    16509: "Amazon AWS", 14618: "Amazon AWS", 15169: "Google", 396982: "Google Cloud", 19527: "Google",
    8075: "Microsoft", 8068: "Microsoft", 14061: "DigitalOcean", 16276: "OVH", 24940: "Hetzner",
    63949: "Akamai Linode", 45102: "Alibaba Cloud", 37963: "Alibaba Cloud", 46606: "Unified Layer (shared hosting)",
    47583: "Hostinger", 26496: "GoDaddy", 398101: "GoDaddy", 8560: "IONOS", 36351: "IBM Cloud",
    132203: "Tencent Cloud", 20473: "Vultr (Choopa)", 51167: "Contabo", 394695: "PublicDomainRegistry",
}

WORDLIST = """www mail webmail smtp pop imap mx mx1 mx2 ns ns1 ns2 ns3 dns dns1 dns2 ftp sftp ssh vpn vpn1 remote
rdp gateway gw portal admin administrator panel cpanel whm plesk webdisk autodiscover autoconfig owa exchange
outlook lync teams sip api api1 api2 apis app apps mobile m dev development test testing qa uat stage staging
preprod demo beta alpha sandbox old new legacy backup bak db database mysql sql postgres redis mongo elastic kibana
grafana prometheus jenkins ci cd git gitlab github bitbucket jira confluence wiki docs help support status monitor
nagios zabbix intranet internal extranet corp corporate office files file share upload uploads download downloads
cdn static assets img images media video stream blog shop store pay payment payments billing secure login sso auth
id accounts account my client clients customer partners partner hr careers jobs crm erp sap web web1 web2 host
server server1 cloud s3 storage email news forum community chat proxy firewall fw router ldap ad dc exchange2
test1 test2 dev1 dev2 office365 mdm vault""".split()

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$")


class NotConfigured(Exception):
    pass


class Skipped(Exception):
    pass


# ------------------------------------------------------------------ helpers
def day(value):
    """Normalise epoch seconds / ISO strings to YYYY-MM-DD."""
    if value in (None, "", 0):
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            v = float(value)
            if v > 1e12:
                v /= 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d")
        s = str(value).strip()
        m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
        if m:
            return m.group(1)
        m = re.match(r"(\d{4})(\d{2})(\d{2})", s)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    except Exception:
        return None
    return None


def clean_host(value):
    h = str(value or "").strip().lower().rstrip(".")
    while h.startswith("*."):
        h = h[2:]
    if h.startswith("."):
        h = h.lstrip(".")
    if not h or "@" in h or " " in h:
        return None
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except Exception:
            return None
    try:
        ipaddress.ip_address(h)
        return None  # an IP address, not a hostname
    except ValueError:
        pass
    return h if HOST_RE.match(h) else None


def valid_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_reserved or ip.is_multicast or ip.is_link_local:
        return None
    return str(ip)


def _min_day(a, b):
    vals = [v for v in (a, b) if v]
    return min(vals) if vals else None


def _max_day(a, b):
    vals = [v for v in (a, b) if v]
    return max(vals) if vals else None


class Collector:
    """Thread-safe accumulator for hosts, IPs and related domains."""

    def __init__(self, apex=None):
        self.apex = apex
        self.hosts = {}
        self.ips = {}
        self.related = {}
        self.lock = threading.Lock()

    def add_host(self, name, source, first=None, last=None):
        h = clean_host(name)
        if not h:
            return False
        if self.apex and not is_under(h, self.apex):
            return False
        with self.lock:
            row = self.hosts.setdefault(h, {"sources": set(), "first": None, "last": None})
            row["sources"].add(source)
            row["first"] = _min_day(row["first"], day(first))
            row["last"] = _max_day(row["last"], day(last))
        return True

    def add_ip(self, ip, source, relation, first=None, last=None, host=None):
        ip = valid_ip(ip)
        if not ip:
            return False
        with self.lock:
            row = self.ips.setdefault(ip, {"sources": set(), "relations": set(), "hosts": set(), "first": None, "last": None})
            row["sources"].add(source)
            row["relations"].add(relation)
            row["first"] = _min_day(row["first"], day(first))
            row["last"] = _max_day(row["last"], day(last))
            h = clean_host(host) if host else None
            if h:
                row["hosts"].add(h)
        return True

    def add_related(self, name, relation, source, via=None):
        h = clean_host(name)
        if not h or (self.apex and is_under(h, self.apex)):
            return False
        with self.lock:
            row = self.related.setdefault(h, {"relations": set(), "sources": set(), "via": set()})
            row["relations"].add(relation)
            row["sources"].add(source)
            if via:
                row["via"].add(str(via))
        return True


class Runner:
    """Runs sources concurrently and reports progress through `emit`."""

    def __init__(self, emit=None):
        self.emit = emit or (lambda *a, **k: None)
        self.sources = {}
        self.lock = threading.Lock()

    def _set(self, sid, status, count=None, error=None, ms=None, note=None):
        row = {"id": sid, "label": SOURCE_LABELS.get(sid, sid), "status": status}
        if count is not None:
            row["count"] = count
        if error:
            row["error"] = error
        if ms is not None:
            row["ms"] = ms
        if note:
            row["note"] = note
        with self.lock:
            self.sources[sid] = row
        try:
            self.emit(dict(row, group="discovery"))
        except Exception:
            pass

    def queue(self, sid):
        self._set(sid, "queued")

    def run(self, sid, fn, *args):
        self._set(sid, "running")
        t0 = time.time()
        try:
            result = fn(*args)
            count, note = (result if isinstance(result, tuple) else (result, None))
            self._set(sid, "done", count=count, ms=int((time.time() - t0) * 1000), note=note)
        except NotConfigured as e:
            self._set(sid, "not_configured", error=str(e) or "API key not configured.")
        except Skipped as e:
            self._set(sid, "skipped", error=str(e))
        except net.RateLimited as e:
            self._set(sid, "rate_limited", error=str(e), ms=int((time.time() - t0) * 1000))
        except Exception as e:
            self._set(sid, "failed", error=net.describe_error(e), ms=int((time.time() - t0) * 1000))

    def parallel(self, jobs, workers=10):
        for sid, _fn, *_ in jobs:
            self.queue(sid)
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as pool:
            futures = [pool.submit(self.run, sid, fn, *args) for sid, fn, *args in jobs]
            for f in as_completed(futures):
                f.result()

    def table(self):
        order = list(SOURCE_LABELS.keys())
        with self.lock:
            rows = list(self.sources.values())
        return sorted(rows, key=lambda r: order.index(r["id"]) if r["id"] in order else 99)


# ---------------------------------------------------------------------- DNS
DOH = [
    ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
    ("https://dns.google/resolve", {"Accept": "application/json"}),
]
RTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}


def doh(name, rtype="A", timeout=6):
    """Return (answers, nxdomain). answers = list of {type, data} dicts."""
    last_err = None
    for endpoint, headers in DOH:
        try:
            url = endpoint + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
            data = net.get_json(url, headers=headers, timeout=timeout, memo=False)
            status = int(data.get("Status", 0) or 0)
            answers = []
            for a in data.get("Answer") or []:
                answers.append({"type": a.get("type"), "data": str(a.get("data") or "").strip()})
            if answers or status == 3:
                return answers, status == 3
            if status == 0:
                return [], False
        except Exception as e:
            last_err = e
    if last_err:
        raise last_err
    return [], False


def resolve_a(name):
    """Resolve A + AAAA, returning (ips, cname_chain)."""
    ips, chain = [], []
    for rtype in ("A", "AAAA"):
        try:
            answers, nx = doh(name, rtype)
        except Exception:
            continue
        for a in answers:
            if a["type"] == RTYPE_NUM["CNAME"]:
                c = clean_host(a["data"])
                if c and c not in chain:
                    chain.append(c)
            elif a["type"] in (RTYPE_NUM["A"], RTYPE_NUM["AAAA"]):
                ip = valid_ip(a["data"])
                if ip and ip not in ips:
                    ips.append(ip)
        if nx:
            break
    return ips, chain


def txt_values(name):
    try:
        answers, _ = doh(name, "TXT")
    except Exception:
        return []
    out = []
    for a in answers:
        if a["type"] == RTYPE_NUM["TXT"]:
            # DoH JSON returns quoted strings, possibly split into chunks.
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', a["data"])
            out.append("".join(parts) if parts else a["data"])
    return out


def host_values(name, rtype):
    try:
        answers, _ = doh(name, rtype)
    except Exception:
        return []
    out = []
    for a in answers:
        if a["type"] == RTYPE_NUM[rtype]:
            h = clean_host(a["data"].split()[-1])
            if h and h not in out:
                out.append(h)
    return out


def parse_spf(record):
    out = {"record": record, "ip4": [], "ip6": [], "include": [], "redirect": None}
    for tok in record.split():
        t = tok.lstrip("+-~?")
        low = t.lower()
        if low.startswith("ip4:"):
            out["ip4"].append(t[4:])
        elif low.startswith("ip6:"):
            out["ip6"].append(t[4:])
        elif low.startswith("include:"):
            out["include"].append(t[8:].lower())
        elif low.startswith("redirect="):
            out["redirect"] = t[9:].lower()
    return out


# ----------------------------------------------------------- shared lookups
_tor_lock = threading.Lock()
_tor_cache = {"at": 0.0, "ips": set(), "error": None}


def tor_exit_ips():
    with _tor_lock:
        if time.time() - _tor_cache["at"] < 6 * 3600 and _tor_cache["ips"]:
            return _tor_cache["ips"]
    text = net.get_text("https://check.torproject.org/torbulkexitlist", timeout=15, memo=False)
    ips = {line.strip() for line in text.splitlines() if valid_ip(line.strip())}
    with _tor_lock:
        _tor_cache.update({"at": time.time(), "ips": ips, "error": None})
    return ips


RIPE = "https://stat.ripe.net/data/{call}/data.json?"


def ripestat(call, resource, timeout=12):
    url = RIPE.format(call=call) + urllib.parse.urlencode({"resource": resource, "sourceapp": "compass-ti"})
    return (net.get_json(url, timeout=timeout) or {}).get("data") or {}


def classify_network(asn, holder):
    try:
        asn_i = int(str(asn or "").upper().replace("AS", "").strip() or 0)
    except ValueError:
        asn_i = 0
    if asn_i in CDN_ASNS:
        return CDN_ASNS[asn_i], None
    if asn_i in HOSTING_ASNS:
        return None, HOSTING_ASNS[asn_i]
    up = str(holder or "").upper()
    if "LINODE" in up or "CONNECTED CLOUD" in up:
        return None, "Akamai Linode"
    for kw, name in CDN_KEYWORDS.items():
        if kw in up:
            return name, None
    return None, None


def enrich_ips(ip_list, runner):
    """Return {ip: enrichment} using RIPEstat, InternetDB, ipapi.is and the Tor list."""
    ip_list = list(dict.fromkeys(ip_list))[:MAX_ENRICH_BASIC]
    info = {ip: {} for ip in ip_list}
    if not ip_list:
        for sid in ("ripestat", "internetdb", "ipapi", "tor"):
            runner._set(sid, "skipped", error="No IPs to enrich.")
        return info

    def do_ripe():
        asn_holder = {}

        def one(ip):
            d = ripestat("network-info", ip)
            asns = d.get("asns") or []
            info[ip]["asn"] = f"AS{asns[0]}" if asns else None
            info[ip]["prefix"] = d.get("prefix")
            try:
                g = ripestat("maxmind-geo-lite", ip)
                for res in g.get("located_resources") or []:
                    for loc in res.get("locations") or []:
                        if loc.get("country"):
                            info[ip]["country"] = loc.get("country")
                            info[ip]["city"] = loc.get("city") or None
                            break
                    if info[ip].get("country"):
                        break
            except Exception:
                pass
            return info[ip]["asn"]

        ok = 0
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(one, ip): ip for ip in ip_list}
            for f in as_completed(futs):
                try:
                    if f.result():
                        ok += 1
                except Exception:
                    pass
        asns = {v.get("asn") for v in info.values() if v.get("asn")}

        def holder(asn):
            try:
                return asn, ripestat("as-overview", asn).get("holder")
            except Exception:
                return asn, None

        with ThreadPoolExecutor(max_workers=6) as pool:
            for asn, h in pool.map(holder, list(asns)):
                asn_holder[asn] = h
        for ip in ip_list:
            a = info[ip].get("asn")
            if a:
                info[ip]["as_name"] = asn_holder.get(a)
        if not ok:
            raise RuntimeError("RIPEstat returned no network data.")
        return ok

    def do_internetdb():
        targets = ip_list[:MAX_ENRICH_EXPOSURE]

        def one(ip):
            try:
                d = net.get_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}", timeout=10)
            except net.HTTPStatusError as e:
                if e.code == 404:
                    return False
                raise
            info[ip]["ports"] = sorted(d.get("ports") or [])
            info[ip]["vulns"] = sorted(d.get("vulns") or [])
            info[ip]["cpes"] = d.get("cpes") or []
            info[ip]["tags"] = d.get("tags") or []
            info[ip]["idb_hostnames"] = d.get("hostnames") or []
            return True

        hits, errors = 0, []
        with ThreadPoolExecutor(max_workers=5) as pool:
            for f in as_completed([pool.submit(one, ip) for ip in targets]):
                try:
                    hits += 1 if f.result() else 0
                except Exception as e:
                    errors.append(e)
        if errors and not hits and len(errors) == len(targets):
            raise errors[0]
        return hits, f"{hits} of {len(targets)} IPs have exposure data"

    def do_ipapi():
        targets = ip_list[:MAX_ENRICH_FLAGS]

        def one(ip):
            d = net.get_json(f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}", timeout=10)
            if not isinstance(d, dict) or d.get("error"):
                raise RuntimeError(str(d.get("error") if isinstance(d, dict) else "bad response"))
            comp = d.get("company") or {}
            asn = d.get("asn") or {}
            loc = d.get("location") or {}
            info[ip]["flags"] = {
                "vpn": bool(d.get("is_vpn")), "proxy": bool(d.get("is_proxy")), "tor": bool(d.get("is_tor")),
                "datacenter": bool(d.get("is_datacenter")), "abuser": bool(d.get("is_abuser")),
                "mobile": bool(d.get("is_mobile")),
            }
            info[ip]["org"] = comp.get("name") or asn.get("org")
            info[ip]["company_type"] = comp.get("type")
            info[ip].setdefault("country", loc.get("country_code") or loc.get("country"))
            if not info[ip].get("city"):
                info[ip]["city"] = loc.get("city")
            if not info[ip].get("asn") and asn.get("asn"):
                info[ip]["asn"] = f"AS{asn.get('asn')}"
                info[ip]["as_name"] = asn.get("org") or asn.get("descr")
            return True

        hits, errors = 0, []
        with ThreadPoolExecutor(max_workers=4) as pool:
            for f in as_completed([pool.submit(one, ip) for ip in targets]):
                try:
                    hits += 1 if f.result() else 0
                except Exception as e:
                    errors.append(e)
        if errors and not hits:
            raise errors[0]
        return hits

    def do_tor():
        ips = tor_exit_ips()
        n = 0
        for ip in ip_list:
            info[ip]["tor_exit"] = ip in ips
            n += 1 if ip in ips else 0
        return n, f"{n} Tor exit node(s) among linked IPs"

    runner.parallel([("ripestat", do_ripe), ("internetdb", do_internetdb), ("ipapi", do_ipapi), ("tor", do_tor)], workers=4)
    for ip in ip_list:
        cdn, hosting = classify_network(info[ip].get("asn"), info[ip].get("as_name") or info[ip].get("org"))
        info[ip]["cdn"] = cdn
        info[ip]["hosting"] = hosting
    return info


# --------------------------------------------------------- domain sources
def _vt_key():
    key = config.get_key("virustotal")
    if not key:
        raise NotConfigured("VirusTotal API key not configured.")
    return key


def src_crtsh(apex, col, ctx):
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{apex}", "output": "json", "deduplicate": "Y"})
    rows = None
    for attempt in range(2):
        try:
            rows = net.get_json(url, timeout=40, memo=False, max_bytes=60 * 1024 * 1024)
            break
        except (net.HTTPStatusError, ValueError) as e:
            # crt.sh is frequently overloaded (502/503) - one quick retry.
            if attempt or (isinstance(e, net.HTTPStatusError) and e.code < 500):
                raise RuntimeError("crt.sh is busy or returned an invalid response; try again later.")
            time.sleep(2)
    found = set()
    certs = {}
    for row in rows or []:
        names = {n for n in (row.get("name_value") or "").split("\n") if n}
        if row.get("common_name"):
            names.add(row["common_name"])
        nb = row.get("not_before")
        cid = row.get("id")
        cleaned = {clean_host(n) for n in names}
        cleaned.discard(None)
        for n in cleaned:
            if col.add_host(n, "crt.sh", nb, nb):
                found.add(n)
        if cid is not None:
            c = certs.setdefault(cid, {"names": set(), "issuer": row.get("issuer_name"), "cn": row.get("common_name"),
                                       "not_before": row.get("not_before"), "not_after": row.get("not_after")})
            c["names"] |= cleaned
    ctx["certs"].extend(certs.values())
    return len(found)


def src_certspotter(apex, col, ctx):
    url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(
        {"domain": apex, "include_subdomains": "true", "expand": "dns_names"})
    rows = net.get_json(url, timeout=25)
    found = set()
    for iss in rows or []:
        names = {clean_host(n) for n in iss.get("dns_names") or []}
        names.discard(None)
        nb = iss.get("not_before")
        for n in names:
            if col.add_host(n, "CertSpotter", nb, nb):
                found.add(n)
        ctx["certs"].append({"names": names, "issuer": None, "cn": None, "not_before": nb, "not_after": iss.get("not_after")})
    return len(found)


def src_vt_subdomains(apex, col, ctx):
    key = _vt_key()
    data = net.get_json(f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(apex)}/subdomains?limit=40",
                        headers={"x-apikey": key}, timeout=20, limit=VT_LIMIT)
    n = 0
    for item in data.get("data") or []:
        name = item.get("id")
        attrs = item.get("attributes") or {}
        when = attrs.get("last_dns_records_date") or attrs.get("last_modification_date")
        if col.add_host(name, "VirusTotal", when, when):
            n += 1
            for rec in attrs.get("last_dns_records") or []:
                if rec.get("type") in ("A", "AAAA"):
                    col.add_ip(rec.get("value"), "VirusTotal", "Subdomain IP (passive)", when, when, host=name)
    total = (data.get("meta") or {}).get("count")
    note = f"VirusTotal knows {total} subdomains; first {n} shown (free API page size)" if total and total > n else None
    return n, note


def src_vt_resolutions(host, col, ctx):
    key = _vt_key()
    data = net.get_json(f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(host)}/resolutions?limit=40",
                        headers={"x-apikey": key}, timeout=20, limit=VT_LIMIT)
    n = 0
    for item in data.get("data") or []:
        a = item.get("attributes") or {}
        if col.add_ip(a.get("ip_address"), "VirusTotal", "Historical A record", a.get("date"), a.get("date"), host=a.get("host_name") or host):
            n += 1
    return n


def _otx_headers():
    key = config.get_key("otx")
    return {"X-OTX-API-KEY": key} if key else {}


def src_otx_domain(apex, col, ctx):
    data = net.get_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(apex)}/passive_dns",
                        headers=_otx_headers(), timeout=25)
    n = 0
    for row in data.get("passive_dns") or []:
        h = row.get("hostname")
        first, last = row.get("first"), row.get("last")
        if col.add_host(h, "OTX", first, last):
            n += 1
        if str(row.get("record_type") or "").upper() in ("A", "AAAA"):
            col.add_ip(row.get("address"), "OTX", "Historical A record", first, last, host=h)
    return n


def src_urlscan_domain(apex, col, ctx):
    key = config.get_key("urlscan")
    if not key:
        raise NotConfigured("urlscan API key not configured.")
    url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": f"domain:{apex}", "size": 100})
    data = net.get_json(url, headers={"API-Key": key}, timeout=20)
    n = 0
    for r in data.get("results") or []:
        page = r.get("page") or {}
        d = page.get("domain")
        t = (r.get("task") or {}).get("time")
        if col.add_host(d, "urlscan", t, t):
            n += 1
            col.add_ip(page.get("ip"), "urlscan", "Seen in urlscan scan", t, t, host=d)
    return n


def _ht_url(endpoint, q):
    params = {"q": q}
    key = config.get_key("hackertarget")
    if key:
        params["apikey"] = key
    return f"https://api.hackertarget.com/{endpoint}/?" + urllib.parse.urlencode(params)


def _ht_check(text):
    low = text.strip().lower()
    if low.startswith("error") or "api count exceeded" in low or "increase quota" in low:
        if "api count" in low or "quota" in low:
            raise net.RateLimited("HackerTarget daily free quota used up.")
        raise RuntimeError(text.strip()[:160])
    return text


def src_hackertarget_hosts(apex, col, ctx):
    text = _ht_check(net.get_text(_ht_url("hostsearch", apex), timeout=20))
    n = 0
    for line in text.splitlines():
        if "," not in line:
            continue
        h, ip = line.split(",", 1)
        if col.add_host(h, "HackerTarget"):
            n += 1
            col.add_ip(ip.strip(), "HackerTarget", "Subdomain IP (passive)", host=h)
    return n


def src_wayback(apex, col, ctx):
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(
        {"url": f"*.{apex}", "output": "txt", "fl": "original", "collapse": "urlkey", "limit": "15000"})
    text = net.get_text(url, timeout=35, max_bytes=8 * 1024 * 1024, memo=False, truncate_ok=True)
    found = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            host = urllib.parse.urlsplit(line if "://" in line else "http://" + line).hostname
        except ValueError:
            continue
        h = clean_host(host)
        if h and h not in found and col.add_host(h, "Wayback"):
            found.add(h)
    return len(found)


def src_securitytrails(apex, col, ctx):
    key = config.get_key("securitytrails")
    if not key:
        raise NotConfigured("SecurityTrails API key not configured (optional).")
    url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(apex)}/subdomains?children_only=false&include_inactive=true"
    data = net.get_json(url, headers={"APIKEY": key}, timeout=20)
    n = 0
    for s in data.get("subdomains") or []:
        if col.add_host(f"{s}.{apex}", "SecurityTrails"):
            n += 1
    return n


def src_bruteforce(apex, col, ctx):
    wildcard = set(ctx.get("wildcard_ips") or [])

    def probe(word):
        name = f"{word}.{apex}"
        ips, chain = resolve_a(name)
        if ips and not (wildcard and set(ips) <= wildcard):
            return name
        return None

    n = 0
    with ThreadPoolExecutor(max_workers=16) as pool:
        for name in pool.map(probe, list(dict.fromkeys(WORDLIST))):
            if name and col.add_host(name, "Brute-force"):
                n += 1
    return n, f"{len(set(WORDLIST))} common names tried"


def fetch_tls(host, port=443, timeout=8):
    """Active: connect to the target and read its certificate."""
    from .infrastructure import tls_certificate
    return tls_certificate(host, port)


def src_tls_active(host, col, ctx):
    cert = fetch_tls(host)
    if cert.get("error"):
        raise RuntimeError(cert["error"])
    ctx["live_cert"] = cert
    n = 0
    for s in cert.get("subjectAltNames") or []:
        if col.add_host(s, "TLS certificate"):
            n += 1
        else:
            col.add_related(s, "Shares a TLS certificate", "TLS certificate", via=host)
    return n


def src_dns_baseline(host, apex, col, ctx):
    """Current A/AAAA, MX, NS, SPF and DMARC for the target and its parent domain."""
    n = 0
    mail = {"mx": [], "ns": [], "spf": None, "dmarc": None, "spf_ranges": [], "spf_includes": []}
    for name, relation in ((host, "A record (target)"), (apex, "A record (parent domain)")):
        ips, chain = resolve_a(name)
        if ips:
            col.add_host(name, "Live DNS")
        for ip in ips:
            col.add_ip(ip, "Live DNS", relation, host=name)
            n += 1
        ctx.setdefault("target_ips" if name == host else "apex_ips", ips)
        ctx.setdefault("cname_" + name, chain)
        if host == apex:
            ctx["apex_ips"] = ips
            break
    mail["mx"] = host_values(apex, "MX")
    mail["ns"] = host_values(apex, "NS")
    for rec in txt_values(apex):
        if rec.lower().startswith("v=spf1"):
            spf = parse_spf(rec)
            mail["spf"] = rec
            mail["spf_includes"] = spf["include"] + ([spf["redirect"]] if spf["redirect"] else [])
            for cidr in spf["ip4"] + spf["ip6"]:
                try:
                    net_ = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if net_.num_addresses == 1:
                    col.add_ip(str(net_.network_address), "SPF", "Mail sender (SPF)")
                else:
                    mail["spf_ranges"].append(str(net_))
    for rec in txt_values(f"_dmarc.{apex}"):
        if rec.lower().startswith("v=dmarc1"):
            mail["dmarc"] = rec
    # Resolve mail and name servers to IPs.
    for mx in mail["mx"][:5]:
        for ip in resolve_a(mx)[0][:4]:
            col.add_ip(ip, "Live DNS", "Mail server (MX)", host=mx)
            n += 1
    for ns in mail["ns"][:4]:
        for ip in resolve_a(ns)[0][:2]:
            col.add_ip(ip, "Live DNS", "Name server (NS)", host=ns)
    ctx["mail"] = mail
    return n


# -------------------------------------------------------- domain discovery
def discover_domain(host, active=False, emit=None):
    host = clean_host(host) or host
    apex = registrable_domain(host)
    if not apex or public_suffix(apex) == apex:
        raise ValueError(f"{host} is a public suffix (like co.in or gov.in), not an organisation's domain.")
    col = Collector(apex)
    runner = Runner(emit)
    ctx = {"certs": [], "wildcard_ips": [], "mail": {}}
    started = time.time()

    # Wildcard DNS: a random label that should not exist.
    probe = f"cmp-{secrets.token_hex(5)}.{apex}"
    try:
        wc_ips, _ = resolve_a(probe)
    except Exception:
        wc_ips = []
    ctx["wildcard_ips"] = wc_ips

    jobs = [
        ("dns", src_dns_baseline, host, apex, col, ctx),
        ("crtsh", src_crtsh, apex, col, ctx),
        ("certspotter", src_certspotter, apex, col, ctx),
        ("vt_subdomains", src_vt_subdomains, apex, col, ctx),
        ("vt_resolutions", src_vt_resolutions, host, col, ctx),
        ("otx", src_otx_domain, apex, col, ctx),
        ("urlscan", src_urlscan_domain, apex, col, ctx),
        ("hackertarget", src_hackertarget_hosts, apex, col, ctx),
        ("wayback", src_wayback, apex, col, ctx),
        ("securitytrails", src_securitytrails, apex, col, ctx),
    ]
    if active:
        jobs.append(("bruteforce", src_bruteforce, apex, col, ctx))
        jobs.append(("tls_active", src_tls_active, host, col, ctx))
    for sid in ("resolve", "enrich", "ripestat", "internetdb", "ipapi", "tor", "cohost"):
        runner.queue(sid)
    runner.parallel(jobs, workers=12)

    # ---- validate every discovered name against live DNS
    resolved = {}

    def do_resolve():
        names = sorted(col.hosts.keys(), key=lambda h: (-len(col.hosts[h]["sources"]), h.count("."), h))
        targets = names[:MAX_RESOLVE]

        def one(name):
            try:
                return name, resolve_a(name)
            except Exception:
                return name, ([], [])

        live = 0
        with ThreadPoolExecutor(max_workers=24) as pool:
            for name, (ips, chain) in pool.map(one, targets):
                resolved[name] = (ips, chain)
                if ips:
                    live += 1
                for ip in ips:
                    col.add_ip(ip, "Live DNS", "Subdomain IP (live)", host=name)
        skipped = len(names) - len(targets)
        note = f"{live} of {len(targets)} names resolve" + (f"; {skipped} not checked (limit {MAX_RESOLVE})" if skipped else "")
        return live, note

    runner.run("resolve", do_resolve)

    # ---- enrich linked IPs (priority: target, parent, live subdomains, mail, historical)
    priority = ["A record (target)", "A record (parent domain)", "Subdomain IP (live)", "Mail server (MX)",
                "Historical A record", "Subdomain IP (passive)", "Seen in urlscan scan", "Name server (NS)", "Mail sender (SPF)"]

    def ip_rank(ip):
        rels = col.ips[ip]["relations"]
        return min((priority.index(r) for r in rels if r in priority), default=len(priority))

    ordered_ips = sorted(col.ips.keys(), key=lambda ip: (ip_rank(ip), ip))
    enrichment = {}

    def do_enrich():
        enrichment.update(enrich_ips(ordered_ips, runner))
        return len(enrichment), (f"{len(ordered_ips) - len(enrichment)} lower-priority IPs not enriched"
                                 if len(ordered_ips) > len(enrichment) else None)

    runner.run("enrich", do_enrich)

    # ---- co-hosted domains on the target's own (non-CDN) IPs
    main_ips = [ip for ip in (ctx.get("target_ips") or []) + (ctx.get("apex_ips") or []) if ip]
    main_ips = list(dict.fromkeys(main_ips))
    shared_cdn = None
    for ip in main_ips:
        if enrichment.get(ip, {}).get("cdn"):
            shared_cdn = enrichment[ip]["cdn"]

    def do_cohost():
        if not main_ips:
            raise Skipped("Target does not currently resolve.")
        if shared_cdn:
            raise Skipped(f"Target is behind {shared_cdn}; co-hosted domains on CDN IPs are unrelated.")
        n = 0
        for ip in main_ips[:2]:
            for name, src in _reverse_ip_light(ip):
                if col.add_related(name, "Hosted on the same IP", src, via=ip):
                    n += 1
        return n

    runner.run("cohost", do_cohost)

    # ---- certificate siblings (names on the same certificate, outside the parent domain)
    shared_certs = 0
    for cert in ctx["certs"]:
        names = cert.get("names") or set()
        if len(names) > SHARED_CERT_LIMIT:
            shared_certs += 1
            continue
        for n in names:
            col.add_related(n, "Shares a TLS certificate", "Certificate logs", via=cert.get("cn") or "certificate")

    return _build_domain_result(host, apex, active, col, ctx, runner, resolved, enrichment, main_ips,
                                shared_cdn, shared_certs, started)


def _reverse_ip_light(ip):
    """Free reverse-IP sources used for co-hosting checks (OTX + HackerTarget)."""
    out = []
    try:
        kind = "IPv6" if ":" in ip else "IPv4"
        data = net.get_json(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(ip)}/passive_dns",
                            headers=_otx_headers(), timeout=20)
        for row in data.get("passive_dns") or []:
            if row.get("hostname"):
                out.append((row["hostname"], "OTX"))
    except Exception:
        pass
    try:
        text = _ht_check(net.get_text(_ht_url("reverseiplookup", ip), timeout=20))
        if "no dns a records" not in text.lower():
            out += [(line.strip(), "HackerTarget") for line in text.splitlines() if line.strip()]
    except Exception:
        pass
    return out[:300]


def _best_cert(host, certs):
    best = None
    for c in certs:
        if host in (c.get("names") or set()) and c.get("issuer"):
            if not best or str(c.get("not_before") or "") > str(best.get("not_before") or ""):
                best = c
    if not best:
        return None
    return {
        "source": "Certificate Transparency (crt.sh)",
        "subjectText": f"CN={best.get('cn')}" if best.get("cn") else "",
        "issuerText": best.get("issuer") or "",
        "notBefore": best.get("not_before"),
        "notAfter": best.get("not_after"),
        "subjectAltNames": sorted(best.get("names") or [])[:100],
    }


def _ip_row(ip, row, enr):
    e = enr.get(ip, {})
    flags = e.get("flags") or {}
    return {
        "ip": ip,
        "version": 6 if ":" in ip else 4,
        "relations": sorted(row["relations"]),
        "hosts": sorted(row["hosts"])[:200],
        "host_count": len(row["hosts"]),
        "sources": sorted(row["sources"]),
        "first_seen": row["first"],
        "last_seen": row["last"],
        "asn": e.get("asn"),
        "as_name": e.get("as_name"),
        "org": e.get("org"),
        "prefix": e.get("prefix"),
        "country": e.get("country"),
        "city": e.get("city"),
        "cdn": e.get("cdn"),
        "hosting": e.get("hosting"),
        "ports": e.get("ports") or [],
        "vulns": e.get("vulns") or [],
        "tags": e.get("tags") or [],
        "tor": bool(e.get("tor_exit") or flags.get("tor")),
        "vpn": bool(flags.get("vpn")),
        "proxy": bool(flags.get("proxy")),
        "datacenter": bool(flags.get("datacenter")),
        "abuser": bool(flags.get("abuser")),
        "enriched": bool(e),
    }


def _build_domain_result(host, apex, active, col, ctx, runner, resolved, enr, main_ips, shared_cdn, shared_certs, started):
    wildcard = set(ctx.get("wildcard_ips") or [])
    subdomains = []
    for name, row in col.hosts.items():
        ips, chain = resolved.get(name, (None, None))
        live = None if ips is None else bool(ips)
        is_wc = bool(wildcard and ips and set(ips) <= wildcard and name not in (host, apex))
        cdn = None
        for ip in ips or []:
            if enr.get(ip, {}).get("cdn"):
                cdn = enr[ip]["cdn"]
        subdomains.append({
            "name": name,
            "live": live,
            "wildcard": is_wc,
            "ips": ips or [],
            "cname": chain or [],
            "cdn": cdn,
            "sources": sorted(row["sources"]),
            "first_seen": row["first"],
            "last_seen": row["last"],
        })
    subdomains.sort(key=lambda s: (0 if s["live"] else 1 if s["live"] is False else 2, s["name"].count("."), s["name"]))

    ips = [_ip_row(ip, row, enr) for ip, row in col.ips.items()]
    rel_rank = {"A record (target)": 0, "A record (parent domain)": 1, "Subdomain IP (live)": 2, "Mail server (MX)": 3}
    ips.sort(key=lambda r: (min((rel_rank.get(x, 9) for x in r["relations"]), default=9), -r["host_count"], r["ip"]))

    related = []
    for name, row in col.related.items():
        related.append({"name": name, "apex": registrable_domain(name), "relations": sorted(row["relations"]),
                        "sources": sorted(row["sources"]), "via": sorted(row["via"])[:5]})
    related.sort(key=lambda r: (r["apex"], r["name"]))

    # Possible origin servers when the site sits behind a CDN.
    origins = []
    if shared_cdn:
        for r in ips:
            if r["cdn"] or not r["enriched"]:
                continue
            rels = set(r["relations"])
            if rels & {"Subdomain IP (live)", "Historical A record", "Subdomain IP (passive)", "Seen in urlscan scan"}:
                if r["hosting"] in ("Google", "Microsoft") and rels <= {"Mail server (MX)", "Mail sender (SPF)"}:
                    continue
                why = []
                if "Historical A record" in rels:
                    why.append("historical A record" + (f" (last seen {r['last_seen']})" if r["last_seen"] else ""))
                live_hosts = [h for h in r["hosts"] if r["ip"] in (resolved.get(h, ([], []))[0] or [])]
                if live_hosts:
                    why.append("non-CDN subdomain " + ", ".join(live_hosts[:3]))
                origins.append({"ip": r["ip"], "reason": "; ".join(why) or "non-CDN IP linked to the domain",
                                "asn": r["asn"], "as_name": r["as_name"]})
        origins = origins[:20]

    live_count = sum(1 for s in subdomains if s["live"])
    notes = []
    if wildcard:
        notes.append(f"Wildcard DNS detected (*.{apex} → {', '.join(sorted(wildcard)[:3])}); names resolving only to these IPs are flagged.")
    if shared_cdn:
        notes.append(f"{host} is served through {shared_cdn}. Its IPs are shared with unrelated sites; see 'Possible origin servers'.")
    if shared_certs:
        notes.append(f"{shared_certs} shared certificate(s) with more than {SHARED_CERT_LIMIT} names were ignored for related-domain discovery.")
    if not active:
        notes.append("Passive mode: Compass did not connect to the target. Enable active checks to fetch the live certificate and try common subdomain names.")

    return {
        "kind": "domain",
        "target": host,
        "apex": apex,
        "mode": "active" if active else "passive",
        "duration_s": round(time.time() - started, 1),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": runner.table(),
        "wildcard": {"detected": bool(wildcard), "ips": sorted(wildcard)},
        "subdomains": subdomains,
        "ips": ips,
        "related_domains": related[:500],
        "mail": ctx.get("mail") or {},
        "origin_candidates": origins,
        "shared_hosting": {"cdn": shared_cdn, "target_ips": main_ips},
        "certificate": ctx.get("live_cert") or _best_cert(host, ctx["certs"]) or _best_cert(apex, ctx["certs"]),
        "stats": {
            "subdomains": len(subdomains),
            "live": live_count,
            "ips": len(ips),
            "related": len(related),
            "sources_ok": sum(1 for s in runner.table() if s["status"] == "done"),
        },
        "notes": notes,
    }


# ------------------------------------------------------------ IP discovery
def discover_ip(ip, active=False, emit=None):
    ip = str(ipaddress.ip_address(ip))
    col = Collector(None)
    runner = Runner(emit)
    ctx = {}
    started = time.time()

    def s_ptr():
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = None
        ctx["ptr"] = name
        if name and col.add_host(name, "PTR"):
            return 1
        return 0

    def s_vt():
        key = _vt_key()
        data = net.get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}/resolutions?limit=40",
                            headers={"x-apikey": key}, timeout=20, limit=VT_LIMIT)
        n = 0
        for item in data.get("data") or []:
            a = item.get("attributes") or {}
            if col.add_host(a.get("host_name"), "VirusTotal", a.get("date"), a.get("date")):
                n += 1
        return n

    def s_otx():
        kind = "IPv6" if ":" in ip else "IPv4"
        data = net.get_json(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(ip)}/passive_dns",
                            headers=_otx_headers(), timeout=25)
        n = 0
        for row in data.get("passive_dns") or []:
            if col.add_host(row.get("hostname"), "OTX", row.get("first"), row.get("last")):
                n += 1
        return n

    def s_urlscan():
        key = config.get_key("urlscan")
        if not key:
            raise NotConfigured("urlscan API key not configured.")
        url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": f'page.ip:"{ip}"', "size": 100})
        data = net.get_json(url, headers={"API-Key": key}, timeout=20)
        n = 0
        for r in data.get("results") or []:
            t = (r.get("task") or {}).get("time")
            if col.add_host((r.get("page") or {}).get("domain"), "urlscan", t, t):
                n += 1
        return n

    def s_ht():
        text = _ht_check(net.get_text(_ht_url("reverseiplookup", ip), timeout=20))
        if "no dns a records" in text.lower() or "no records" in text.lower():
            return 0
        n = 0
        for line in text.splitlines():
            if col.add_host(line.strip(), "HackerTarget"):
                n += 1
        return n

    def s_tls():
        cert = fetch_tls(ip)
        if cert.get("error"):
            raise RuntimeError(cert["error"])
        ctx["live_cert"] = cert
        n = 0
        for s in cert.get("subjectAltNames") or []:
            if col.add_host(s, "TLS certificate"):
                n += 1
        return n

    jobs = [("ptr", s_ptr), ("vt_resolutions", s_vt), ("otx", s_otx), ("urlscan", s_urlscan), ("hackertarget", s_ht)]
    if active:
        jobs.append(("tls_active", s_tls))
    for sid in ("enrich", "ripestat", "internetdb", "ipapi", "tor", "validate"):
        runner.queue(sid)
    runner.parallel(jobs, workers=8)

    enrichment = {}

    def do_enrich():
        enrichment.update(enrich_ips([ip], runner))
        return 1

    runner.run("enrich", do_enrich)
    e = enrichment.get(ip, {})
    for h in e.get("idb_hostnames") or []:
        col.add_host(h, "Shodan InternetDB")

    current = {}

    def do_validate():
        names = sorted(col.hosts.keys(), key=lambda h: (-len(col.hosts[h]["sources"]), h))[:MAX_IP_VALIDATE]

        def one(name):
            try:
                return name, resolve_a(name)[0]
            except Exception:
                return name, None

        hits = 0
        with ThreadPoolExecutor(max_workers=24) as pool:
            for name, ips in pool.map(one, names):
                current[name] = None if ips is None else (ip in ips)
                hits += 1 if current[name] else 0
        return hits, f"{hits} of {len(names)} domains still point to {ip}"

    runner.run("validate", do_validate)

    domains = []
    apexes = {}
    for name, row in col.hosts.items():
        apex = registrable_domain(name)
        apexes[apex] = apexes.get(apex, 0) + 1
        domains.append({"name": name, "apex": apex, "current": current.get(name), "sources": sorted(row["sources"]),
                        "first_seen": row["first"], "last_seen": row["last"]})
    domains.sort(key=lambda d: (0 if d["current"] else 1, d["apex"], d["name"]))

    flags = e.get("flags") or {}
    cdn = e.get("cdn")
    shared = bool(cdn) or len(apexes) > SHARED_HOSTING_DOMAINS
    reason = None
    if cdn:
        reason = f"{ip} belongs to {cdn}; thousands of unrelated sites share CDN IPs, so co-hosted domains are not evidence of a link."
    elif len(apexes) > SHARED_HOSTING_DOMAINS:
        reason = f"{len(apexes)} different registered domains point here, which suggests shared hosting; treat co-hosted domains with caution."

    notes = []
    if not active:
        notes.append("Passive mode: Compass did not connect to this IP. Enable active checks to read the certificate it serves.")
    return {
        "kind": "ip",
        "target": ip,
        "mode": "active" if active else "passive",
        "duration_s": round(time.time() - started, 1),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": runner.table(),
        "ptr": ctx.get("ptr"),
        "network": {"asn": e.get("asn"), "as_name": e.get("as_name"), "org": e.get("org"), "prefix": e.get("prefix"),
                    "country": e.get("country"), "city": e.get("city"), "cdn": cdn, "hosting": e.get("hosting"),
                    "company_type": e.get("company_type")},
        "exposure": {"ports": e.get("ports") or [], "vulns": e.get("vulns") or [], "cpes": e.get("cpes") or [],
                     "tags": e.get("tags") or [], "hostnames": e.get("idb_hostnames") or [],
                     "available": "ports" in e},
        "anonymity": {"tor": bool(e.get("tor_exit") or flags.get("tor")), "vpn": bool(flags.get("vpn")),
                      "proxy": bool(flags.get("proxy")), "datacenter": bool(flags.get("datacenter")),
                      "abuser": bool(flags.get("abuser")), "mobile": bool(flags.get("mobile")),
                      "checked": bool(flags) or "tor_exit" in e},
        "domains": domains[:1000],
        "apex_counts": sorted(({"apex": k, "count": v} for k, v in apexes.items()), key=lambda x: (-x["count"], x["apex"]))[:200],
        "shared_hosting": {"shared": shared, "cdn": cdn, "reason": reason},
        "certificate": ctx.get("live_cert"),
        "stats": {"domains": len(domains), "current": sum(1 for d in domains if d["current"]), "apexes": len(apexes),
                  "sources_ok": sum(1 for s in runner.table() if s["status"] == "done")},
        "notes": notes,
    }

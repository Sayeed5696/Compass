import base64
import json
import urllib.parse

from . import config, net

UA = net.USER_AGENT


class ProviderResult:
    def __init__(self, provider, status, data=None, error=None):
        self.provider = provider
        self.status = status
        self.data = data or {}
        self.error = error

    def as_dict(self):
        out = {"provider": self.provider, "status": self.status, "data": self.data}
        if self.error:
            out["error"] = self.error
        return out


def request_json(url, headers=None, timeout=12, method="GET", body=None, limit=None):
    raw = net.request(url, headers=headers or {}, timeout=timeout, method=method, body=body,
                      memo=(method == "GET"), limit=limit)
    return 200, json.loads(raw.decode("utf-8", errors="replace"))


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def virustotal(ioc):
    key = config.get_key("virustotal")
    if not key:
        return ProviderResult("virustotal", "NOT_CONFIGURED")
    typ = ioc["type"]
    value = ioc["normalized"]
    try:
        if typ in ("ip", "ipv6"):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(value)}"
        elif typ == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(value)}"
        elif typ == "url":
            endpoint = f"https://www.virustotal.com/api/v3/urls/{vt_url_id(value)}"
        elif typ in ("md5", "sha1", "sha256"):
            endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
        else:
            return ProviderResult("virustotal", "NOT_SUPPORTED")
        from .discovery import VT_LIMIT
        status, data = request_json(endpoint, {"x-apikey": key}, limit=VT_LIMIT)
        obj = data.get("data", {})
        attrs = obj.get("attributes", {})
        return ProviderResult("virustotal", "COMPLETED", {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "meaningful_relationships": {
                "resolutions": attrs.get("last_dns_records"),
                "names": attrs.get("names"),
                "popular_threat_classification": attrs.get("popular_threat_classification"),
            }
        })
    except net.HTTPStatusError as e:
        if e.code == 404:
            return ProviderResult("virustotal", "NOT_FOUND", error="VirusTotal has no record of this IOC.")
        return ProviderResult("virustotal", "FAILED", error=f"HTTP {e.code}: {e.reason}")
    except net.RateLimited as e:
        return ProviderResult("virustotal", "FAILED", error=str(e))
    except Exception as e:
        return ProviderResult("virustotal", "FAILED", error=net.describe_error(e))

def abuseipdb(ioc):
    key = config.get_key("abuseipdb")
    if not key:
        return ProviderResult("abuseipdb", "NOT_CONFIGURED")
    if ioc["type"] not in ("ip", "ipv6"):
        return ProviderResult("abuseipdb", "NOT_SUPPORTED")
    try:
        q = urllib.parse.urlencode({"ipAddress": ioc["normalized"], "maxAgeInDays": 90})
        status, data = request_json("https://api.abuseipdb.com/api/v2/check?" + q, {
            "Key": key, "Accept": "application/json", "User-Agent": UA
        })
        return ProviderResult("abuseipdb", "COMPLETED", data.get("data", {}))
    except net.HTTPStatusError as e:
        return ProviderResult("abuseipdb", "FAILED", error=f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        return ProviderResult("abuseipdb", "FAILED", error=net.describe_error(e))

def greynoise(ioc):
    key = config.get_key("greynoise")
    if not key:
        return ProviderResult("greynoise", "NOT_CONFIGURED")
    if ioc["type"] != "ip":
        return ProviderResult("greynoise", "NOT_SUPPORTED")
    try:
        status, data = request_json(f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ioc['normalized'])}", {
            "key": key, "User-Agent": UA
        })
        return ProviderResult("greynoise", "COMPLETED", {
            k: data.get(k) for k in ["ip", "noise", "riot", "classification", "name", "last_seen", "link"]
        })
    except net.HTTPStatusError as e:
        if e.code == 404:
            return ProviderResult("greynoise", "NOT_FOUND", error="No GreyNoise community record")
        return ProviderResult("greynoise", "FAILED", error=f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        return ProviderResult("greynoise", "FAILED", error=net.describe_error(e))

def urlscan(ioc):
    key = config.get_key("urlscan")
    if not key:
        return ProviderResult("urlscan", "NOT_CONFIGURED")
    if ioc["type"] not in ("url", "domain", "ip"):
        return ProviderResult("urlscan", "NOT_SUPPORTED")
    try:
        q = urllib.parse.urlencode({"q": ioc["normalized"]})
        status, data = request_json("https://urlscan.io/api/v1/search/?" + q, {
            "api-key": key, "User-Agent": UA
        })
        results = []
        for r in (data.get("results") or [])[:10]:
            page = r.get("page", {})
            results.append({
                "task_uuid": r.get("_id"),
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "asn": page.get("asn"),
                "country": page.get("country"),
                "server": page.get("server"),
                "scan": r.get("task", {}).get("uuid"),
                "time": r.get("task", {}).get("time"),
            })
        return ProviderResult("urlscan", "COMPLETED", {"total": data.get("total"), "results": results})
    except net.HTTPStatusError as e:
        return ProviderResult("urlscan", "FAILED", error=f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        return ProviderResult("urlscan", "FAILED", error=net.describe_error(e))

def _urlhaus_post(endpoint, fields, key):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    return request_json(endpoint, {
        "Auth-Key": key,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": UA,
    }, timeout=15, method="POST", body=body)

def urlhaus(ioc):
    """Query URLhaus for URL, host (domain/IP), or malware payload hash."""
    key = config.get_key("urlhaus")
    if not key:
        return ProviderResult("urlhaus", "NOT_CONFIGURED")
    typ = ioc["type"]
    value = ioc["normalized"]
    try:
        if typ == "url":
            _, data = _urlhaus_post("https://urlhaus-api.abuse.ch/v1/url/", {"url": value}, key)
        elif typ in ("ip", "domain"):
            _, data = _urlhaus_post("https://urlhaus-api.abuse.ch/v1/host/", {"host": value}, key)
        elif typ == "md5":
            _, data = _urlhaus_post("https://urlhaus-api.abuse.ch/v1/payload/", {"md5_hash": value}, key)
        elif typ == "sha256":
            _, data = _urlhaus_post("https://urlhaus-api.abuse.ch/v1/payload/", {"sha256_hash": value}, key)
        else:
            return ProviderResult("urlhaus", "NOT_SUPPORTED")

        qs = data.get("query_status")
        if qs == "ok":
            # Keep a compact, analyst-friendly relationship view alongside the
            # provider payload. The UI uses this to show every URL tracked for
            # a host/IP (and the IPs observed inside those URLs) without exposing
            # the full raw API response in the normal Threat Intel view.
            import ipaddress
            related_urls = []
            related_ips = []
            rows = data.get("urls") or []
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                u = (row.get("url") or "").strip()
                host = (row.get("host") or "").strip().lower().rstrip(".")
                if u:
                    parsed = urllib.parse.urlparse(u)
                    if not host:
                        host = (parsed.hostname or "").lower().rstrip(".")
                    related_urls.append({
                        "id": row.get("id"),
                        "url": u,
                        "host": host,
                        "status": row.get("url_status"),
                        "date_added": row.get("date_added"),
                        "threat": row.get("threat"),
                        "tags": row.get("tags") or [],
                        "reference": row.get("urlhaus_reference"),
                    })
                    if parsed.hostname:
                        try:
                            ipaddress.ip_address(parsed.hostname)
                            if parsed.hostname not in related_ips:
                                related_ips.append(parsed.hostname)
                        except ValueError:
                            pass
                if host:
                    try:
                        ipaddress.ip_address(host)
                        if host not in related_ips:
                            related_ips.append(host)
                    except ValueError:
                        pass
            # Payload lookups can also contain URL relationships.
            for payload in data.get("payloads") or []:
                if not isinstance(payload, dict):
                    continue
                for row in payload.get("urls") or []:
                    if not isinstance(row, dict):
                        continue
                    u = (row.get("url") or "").strip()
                    if not u:
                        continue
                    parsed = urllib.parse.urlparse(u)
                    host = (parsed.hostname or "").lower().rstrip(".")
                    related_urls.append({
                        "id": row.get("id"),
                        "url": u,
                        "host": host,
                        "status": row.get("url_status"),
                        "date_added": row.get("firstseen"),
                        "threat": row.get("threat"),
                        "tags": row.get("tags") or [],
                        "reference": row.get("urlhaus_reference"),
                    })
                    try:
                        ipaddress.ip_address(parsed.hostname or "")
                        if parsed.hostname not in related_ips:
                            related_ips.append(parsed.hostname)
                    except ValueError:
                        pass
            # De-duplicate while preserving URLhaus ordering.
            seen_urls=set(); unique_urls=[]
            for row in related_urls:
                marker=row.get("url")
                if marker and marker not in seen_urls:
                    seen_urls.add(marker); unique_urls.append(row)
            data["related"] = {
                "urls": unique_urls,
                "ips": related_ips,
                "count": len(unique_urls),
            }
            return ProviderResult("urlhaus", "COMPLETED", data)
        if qs == "no_results":
            return ProviderResult("urlhaus", "COMPLETED", {"query_status": "no_results"})
        return ProviderResult("urlhaus", "FAILED", data=data, error=f"URLhaus query status: {qs or 'unknown'}")
    except net.HTTPStatusError as e:
        return ProviderResult("urlhaus", "FAILED", error=f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        return ProviderResult("urlhaus", "FAILED", error=net.describe_error(e))

PROVIDERS = {
    "virustotal": virustotal,
    "abuseipdb": abuseipdb,
    "greynoise": greynoise,
    "urlscan": urlscan,
    "urlhaus": urlhaus,
}

def run_provider(name, ioc):
    fn = PROVIDERS[name]
    return fn(ioc)

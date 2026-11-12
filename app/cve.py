import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = "Compass/1.0 (CVE search)"


def _get_json(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _cvss(vuln):
    metrics = vuln.get("metrics") or {}
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if entries:
            item = entries[0]
            data = item.get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or item.get("baseSeverity") or ""
            vector = data.get("vectorString") or ""
            return {"version": version, "score": score, "severity": severity.upper(), "vector": vector}
    return {"version": None, "score": None, "severity": "UNKNOWN", "vector": ""}


def _description(vuln):
    for d in vuln.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return (vuln.get("descriptions") or [{}])[0].get("value", "")


def _weaknesses(vuln):
    out = []
    for w in vuln.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value")
            if val and val not in out:
                out.append(val)
    return out


def _affected(vuln):
    out = []
    for cfg in vuln.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                criteria = m.get("criteria")
                if criteria:
                    out.append({
                        "cpe": criteria,
                        "vulnerable": bool(m.get("vulnerable", True)),
                        "versionStartIncluding": m.get("versionStartIncluding"),
                        "versionStartExcluding": m.get("versionStartExcluding"),
                        "versionEndIncluding": m.get("versionEndIncluding"),
                        "versionEndExcluding": m.get("versionEndExcluding"),
                    })
    return out[:100]


def _references(vuln):
    out = []
    for r in vuln.get("references") or []:
        url = r.get("url")
        if url:
            out.append({"url": url, "source": r.get("source"), "tags": r.get("tags") or []})
    return out[:50]


def _normalize(vuln, kev_ids):
    cve = vuln.get("id") or ""
    cvss = _cvss(vuln)
    return {
        "id": cve,
        "sourceIdentifier": vuln.get("sourceIdentifier"),
        "published": vuln.get("published"),
        "lastModified": vuln.get("lastModified"),
        "vulnStatus": vuln.get("vulnStatus"),
        "description": _description(vuln),
        "cvss": cvss,
        "cwe": _weaknesses(vuln),
        "affected": _affected(vuln),
        "references": _references(vuln),
        "kev": cve in kev_ids,
    }


def load_kev():
    """Fetch the current CISA KEV catalog directly from the Internet.

    Offline caching is intentionally deferred to a later phase.
    """
    try:
        data = _get_json(KEV_URL, timeout=20)
        return data.get("vulnerabilities", []), "online"
    except Exception as e:
        return [], f"unavailable: {e}"


PRODUCT_CPE_ALIASES = {
    "apache": "cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*",
    "apache http server": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "apache httpd": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "httpd": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
}

def _search_nvd(params, headers):
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    return _get_json(url, headers=headers, timeout=20)


def search(query="", sort="relevance", limit=25, cve_id=""):
    kev, kev_source = load_kev()
    kev_map = {x.get("cveID"): x for x in kev if x.get("cveID")}
    requested_limit = max(1, min(int(limit), 100))
    params = {"resultsPerPage": requested_limit}
    product_search = False
    if cve_id:
        params["cveId"] = cve_id.upper()
    elif query:
        normalized_query = " ".join(query.strip().lower().split())
        cpe_match = PRODUCT_CPE_ALIASES.get(normalized_query)
        if cpe_match:
            # Fetch a larger page, then sort locally by publication date.
            # This prevents a generic application search such as 'apache'
            # from returning an old keyword-relevance slice while newer CVEs
            # are present deeper in the NVD result set.
            params["virtualMatchString"] = cpe_match
            params["resultsPerPage"] = max(100, requested_limit)
            product_search = True
        else:
            params["keywordSearch"] = query.strip()
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        params["pubStartDate"] = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        params["pubEndDate"] = end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    headers = {}
    try:
        from app import config
        key = config.get_key("nvd")
        if key:
            headers["apiKey"] = key
    except Exception:
        pass
    data = _search_nvd(params, headers)
    vulns = [_normalize(x.get("cve", {}), set(kev_map)) for x in data.get("vulnerabilities", [])]
    if product_search:
        vulns.sort(key=lambda x: (x.get("published") or "", x.get("lastModified") or ""), reverse=True)
        vulns = vulns[:requested_limit]
    for item in vulns:
        k = kev_map.get(item["id"])
        if k:
            item["kevDetails"] = {
                "vendorProject": k.get("vendorProject"),
                "product": k.get("product"),
                "vulnerabilityName": k.get("vulnerabilityName"),
                "dateAdded": k.get("dateAdded"),
                "dueDate": k.get("dueDate"),
                "knownRansomwareCampaignUse": k.get("knownRansomwareCampaignUse"),
                "notes": k.get("notes"),
                "requiredAction": k.get("requiredAction"),
            }
    def score(x):
        return x.get("cvss", {}).get("score") or -1
    def published(x): return x.get("published") or ""
    def modified(x): return x.get("lastModified") or ""
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    if sort == "severity_desc": vulns.sort(key=lambda x: (severity_rank.get(x["cvss"].get("severity"), 0), score(x), modified(x)), reverse=True)
    elif sort == "published_desc": vulns.sort(key=published, reverse=True)
    elif sort == "modified_desc": vulns.sort(key=modified, reverse=True)
    elif sort == "cvss_desc": vulns.sort(key=score, reverse=True)
    elif sort == "kev_first": vulns.sort(key=lambda x: (x.get("kev", False), severity_rank.get(x["cvss"].get("severity"), 0), score(x)), reverse=True)
    return {
        "ok": True,
        "query": query or cve_id or "latest 30 days",
        "count": len(vulns),
        "totalResults": data.get("totalResults", len(vulns)),
        "results": vulns,
        "sources": {"nvd": "online", "cisaKev": kev_source},
    }

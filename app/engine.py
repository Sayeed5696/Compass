import copy
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import cache, config, discovery, infrastructure, providers
from .ioc import detect_ioc, file_hashes

DISCOVERY_TYPES = ("ip", "ipv6", "domain", "url")


def _provider_selection(ioc):
    return [name for name, meta in config.PROVIDERS.items()
            if name in providers.PROVIDERS and ioc["type"] in meta["supports"]]


def _assess_provider(result):
    name = result.get("provider", "")
    status = result.get("status")
    data = result.get("data") or {}
    if status == "NOT_CONFIGURED":
        return {"verdict": "NOT_CONFIGURED", "confidence": "—", "summary": "API key is not configured.", "evidence": []}
    if status == "NOT_FOUND":
        return {"verdict": "NOT_FOUND", "confidence": "—", "summary": "No record was found by this provider.", "evidence": []}
    if status != "COMPLETED":
        return {"verdict": "ERROR", "confidence": "—", "summary": result.get("error") or "Provider query failed.", "evidence": []}

    if name == "virustotal":
        stats = data.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
        if malicious > 0:
            verdict = "MALICIOUS"
            confidence = "HIGH" if malicious >= 3 else "MEDIUM"
            summary = f"{malicious} security engines flagged this IOC as malicious" + (f"; {suspicious} flagged it suspicious" if suspicious else "") + "."
        elif suspicious > 0:
            verdict, confidence, summary = "SUSPICIOUS", "MEDIUM", f"{suspicious} security engines flagged this IOC as suspicious; no engines flagged it malicious."
        elif total:
            verdict, confidence, summary = "NO MALICIOUS DETECTIONS", "MEDIUM", "No malicious or suspicious detections were returned by the engines in the latest analysis."
        else:
            verdict, confidence, summary = "UNKNOWN", "LOW", "VirusTotal returned no usable engine statistics."
        return {"verdict": verdict, "confidence": confidence, "summary": summary,
                "evidence": [f"Malicious: {malicious}", f"Suspicious: {suspicious}", f"Undetected: {stats.get('undetected', 0)}"]}

    if name == "abuseipdb":
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        if score >= 75:
            verdict, confidence = "MALICIOUS", "HIGH"
        elif score >= 25:
            verdict, confidence = "SUSPICIOUS", "MEDIUM"
        else:
            verdict, confidence = "NO ABUSE SIGNAL", "MEDIUM"
        return {"verdict": verdict, "confidence": confidence, "summary": f"Abuse Confidence Score is {score}/100 based on {reports} report(s).",
                "evidence": [f"Abuse Confidence: {score}/100", f"Reports: {reports}", f"ISP: {data.get('isp') or 'Unknown'}", f"Country: {data.get('countryCode') or 'Unknown'}"]}

    if name == "greynoise":
        classification = str(data.get("classification") or "unknown").lower()
        riot = bool(data.get("riot"))
        noise = bool(data.get("noise"))
        if riot:
            verdict, confidence, summary = "BENIGN / RIOT", "HIGH", "GreyNoise identifies this IP as benign/known-good infrastructure."
        elif classification == "malicious":
            verdict, confidence, summary = "MALICIOUS", "HIGH", "GreyNoise classifies this IP as malicious."
        elif classification == "benign":
            verdict, confidence, summary = "BENIGN", "HIGH", "GreyNoise classifies this IP as benign."
        elif noise:
            verdict, confidence, summary = "SCANNER / NOISE", "MEDIUM", "GreyNoise has observed this IP generating Internet scanning/noise; this alone is not proof of malware."
        else:
            verdict, confidence, summary = "UNKNOWN", "LOW", "GreyNoise has no strong classification for this IP."
        return {"verdict": verdict, "confidence": confidence, "summary": summary,
                "evidence": [f"Classification: {classification}", f"Noise: {noise}", f"RIOT: {riot}"]}

    if name == "urlhaus":
        qs = str(data.get("query_status") or "").lower()
        if qs == "no_results":
            return {"verdict": "NO URLHAUS RECORD", "confidence": "MEDIUM", "summary": "URLhaus returned no matching malware record for this IOC.", "evidence": []}
        if qs == "ok":
            if "payloads" in data:
                payloads = data.get("payloads") or []
                return {"verdict": "MALICIOUS", "confidence": "HIGH", "summary": f"URLhaus has a malware payload record for this hash ({len(payloads)} payload record(s)).", "evidence": [f"Payload records: {len(payloads)}"]}
            if "urls" in data:
                urls = data.get("urls") or []
                online = sum(1 for u in urls if str(u.get("url_status") or "").lower() == "online")
                return {"verdict": "MALICIOUS", "confidence": "HIGH", "summary": f"URLhaus tracks {len(urls)} malware URL(s) for this host, including {online} currently online.", "evidence": [f"Tracked URLs: {len(urls)}", f"Online: {online}"]}
            return {"verdict": "MALICIOUS", "confidence": "HIGH", "summary": "URLhaus has a malware URL record for this IOC.", "evidence": []}
        return {"verdict": "UNKNOWN", "confidence": "LOW", "summary": "URLhaus returned an unrecognized response.", "evidence": []}

    if name == "urlscan":
        total = data.get("total")
        n = len(data.get("results") or [])
        if n:
            return {"verdict": "OBSERVED", "confidence": "LOW", "summary": f"urlscan has {total if total is not None else n} matching scan result(s). Observation is not itself a malicious verdict.", "evidence": [f"Matching scans: {total if total is not None else n}"]}
        return {"verdict": "NO OBSERVATIONS", "confidence": "LOW", "summary": "No matching urlscan observations were returned.", "evidence": []}

    return {"verdict": "UNKNOWN", "confidence": "LOW", "summary": "No assessment rule is defined for this provider.", "evidence": []}


def _aggregate_assessment(provider_results):
    assessed = [p.get("assessment", {}) for p in provider_results]
    strong = [a for a in assessed if a.get("verdict") == "MALICIOUS"]
    suspicious = [a for a in assessed if a.get("verdict") == "SUSPICIOUS"]
    if strong:
        confidence = "HIGH" if any(a.get("confidence") == "HIGH" for a in strong) else "MEDIUM"
        return {"verdict": "MALICIOUS", "confidence": confidence, "summary": f"Malicious evidence was returned by {len(strong)} provider(s).", "provider_count": len(strong)}
    if suspicious:
        return {"verdict": "SUSPICIOUS", "confidence": "MEDIUM", "summary": f"Suspicious evidence was returned by {len(suspicious)} provider(s), with no strong malicious verdict.", "provider_count": len(suspicious)}
    completed = [a for a in assessed if a.get("verdict") not in ("NOT_CONFIGURED", "NOT_FOUND", "ERROR", None)]
    if completed:
        return {"verdict": "NO STRONG MALICIOUS SIGNAL", "confidence": "MEDIUM", "summary": "No configured provider returned a strong malicious verdict.", "provider_count": len(completed)}
    return {"verdict": "INSUFFICIENT DATA", "confidence": "LOW", "summary": "Configure and/or query more providers to produce a stronger assessment.", "provider_count": 0}


def _cache_result_is_reusable(cached, ioc):
    """Reuse cache only when it holds usable current provider and discovery results."""
    if not isinstance(cached.get("threat_assessment"), dict):
        return False
    if ioc["type"] in DISCOVERY_TYPES and not isinstance(cached.get("discovery"), dict):
        return False
    providers_by_name = {p.get("provider"): p for p in (cached.get("providers") or []) if isinstance(p, dict)}
    status = config.provider_status()
    for name in _provider_selection(ioc):
        meta = status.get(name, {})
        if meta.get("configured") and providers_by_name.get(name, {}).get("status") not in ("COMPLETED", "NOT_FOUND"):
            return False
    return True


def _relationships_from_discovery(ioc, disc, infra):
    """Compact relationship summary kept for reports and older views."""
    rel = {"subdomains": [], "ips": [], "hostnames": [], "sources": []}
    if not disc or disc.get("error"):
        return rel
    if disc.get("kind") == "domain":
        rel["subdomains"] = [s["name"] for s in disc.get("subdomains", []) if s["name"] != disc.get("apex")]
        rel["ips"] = [r["ip"] for r in disc.get("ips", [])]
        rel["hostnames"] = sorted({h for r in disc.get("ips", []) for h in r.get("hosts", [])})[:500]
    else:
        rel["hostnames"] = [d["name"] for d in disc.get("domains", [])]
        rel["subdomains"] = list(rel["hostnames"])
    rel["sources"] = [{"source": s["label"], "value": s.get("count", s["status"])} for s in disc.get("sources", []) if s["status"] == "done"]
    return rel


def investigate(payload, emit=None):
    emit = emit or (lambda *a, **k: None)
    value = payload.get("ioc", "")
    active = bool(payload.get("active"))
    refresh = bool(payload.get("refresh"))
    mode = "active" if active else "passive"
    ioc = detect_ioc(value)

    def stage(sid, label, status, **kw):
        emit(dict({"group": "pipeline", "id": sid, "label": label, "status": status}, **kw))

    stage("detect", "Detect & normalise", "done", note=ioc["type"])
    cache_key = f"{ioc['normalized']}|{mode}"
    if ioc["type"] != "unknown" and not refresh:
        cached = cache.get(ioc["type"], cache_key)
        if cached and _cache_result_is_reusable(cached, ioc):
            result = copy.deepcopy(cached)
            result["cached"] = True
            result["message"] = "Loaded from the local cache (results up to 24 hours old). Use Refresh for live data."
            stage("cache", "Local cache", "done", note="Cached result reused")
            return result

    result = {
        "ioc": ioc,
        "mode": mode,
        "started_at": time.time(),
        "pipeline": [{"stage": "Detection", "status": "COMPLETED"},
                     {"stage": "Normalization", "status": "COMPLETED" if ioc["type"] != "unknown" else "FAILED"}],
        "infrastructure": {},
        "relationships": {"subdomains": [], "ips": [], "hostnames": [], "sources": []},
        "discovery": None,
        "providers": [],
        "message": "",
    }
    if ioc["type"] == "unknown":
        result["message"] = "The input could not be recognised as an IP, domain, URL or hash."
        result["threat_assessment"] = _aggregate_assessment([])
        return result

    # ---------------------------------------------------------- workers
    def run_infra():
        stage("infra", "Infrastructure (DNS, RDAP, GeoIP)", "running")
        try:
            if ioc["type"] in ("ip", "ipv6"):
                data = infrastructure.infrastructure_for_ip(ioc["normalized"])
            elif ioc["type"] == "domain":
                data = infrastructure.infrastructure_for_domain(ioc["normalized"], active=active)
            elif ioc["type"] == "url":
                data = infrastructure.infrastructure_for_url(ioc["normalized"], active=active)
            else:
                data = {"file_hash": ioc["normalized"]}
            stage("infra", "Infrastructure (DNS, RDAP, GeoIP)", "done")
            return data
        except Exception as e:
            stage("infra", "Infrastructure (DNS, RDAP, GeoIP)", "failed", error=str(e))
            return {"error": str(e)}

    def run_discovery():
        if ioc["type"] not in DISCOVERY_TYPES:
            return None
        stage("discovery", "Subdomain & IP discovery", "running")
        try:
            target = ioc["normalized"]
            kind = ioc["type"]
            if kind == "url":
                target = ioc.get("hostname") or ""
                kind = "domain"
                try:
                    import ipaddress
                    ipaddress.ip_address(target)
                    kind = "ip"
                except ValueError:
                    pass
            if kind in ("ip", "ipv6"):
                data = discovery.discover_ip(target, active=active, emit=emit)
                stage("discovery", "Subdomain & IP discovery", "done", note=f"{data['stats']['domains']} domains on this IP")
            else:
                data = discovery.discover_domain(target, active=active, emit=emit)
                stage("discovery", "Subdomain & IP discovery", "done",
                      note=f"{data['stats']['subdomains']} subdomains · {data['stats']['ips']} linked IPs")
            return data
        except Exception as e:
            stage("discovery", "Subdomain & IP discovery", "failed", error=str(e))
            return {"error": str(e), "kind": "error"}

    def run_intel():
        selected = _provider_selection(ioc)
        stage("intel", "Threat intelligence providers", "running")
        results = [None] * len(selected)

        def one(idx, name):
            emit({"group": "intel", "id": name, "label": config.PROVIDERS[name]["label"], "status": "running"})
            try:
                r = providers.run_provider(name, ioc).as_dict()
            except Exception as e:
                r = {"provider": name, "status": "FAILED", "data": {}, "error": str(e)}
            status_map = {"COMPLETED": "done", "NOT_CONFIGURED": "not_configured", "NOT_FOUND": "done", "NOT_SUPPORTED": "skipped"}
            emit({"group": "intel", "id": name, "label": config.PROVIDERS[name]["label"],
                  "status": status_map.get(r.get("status"), "failed"), "error": r.get("error")})
            return idx, r

        if selected:
            with ThreadPoolExecutor(max_workers=len(selected)) as pool:
                for fut in as_completed([pool.submit(one, i, n) for i, n in enumerate(selected)]):
                    idx, r = fut.result()
                    results[idx] = r
        for item in results:
            item["assessment"] = _assess_provider(item)
        stage("intel", "Threat intelligence providers", "done")
        return selected, results

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_infra = pool.submit(run_infra)
        f_disc = pool.submit(run_discovery)
        f_intel = pool.submit(run_intel)
        infra = f_infra.result()
        disc = f_disc.result()
        selected, results = f_intel.result()

    # Passive mode: show the certificate from CT logs instead of connecting to the target.
    if disc and not disc.get("error") and disc.get("certificate"):
        if ioc["type"] == "domain" and not infra.get("tls"):
            infra["tls"] = disc["certificate"]
        elif ioc["type"] == "url" and isinstance(infra.get("domain"), dict) and not infra["domain"].get("tls"):
            infra["domain"]["tls"] = disc["certificate"]

    result["infrastructure"] = infra
    result["discovery"] = disc
    result["relationships"] = _relationships_from_discovery(ioc, disc, infra)
    result["providers"] = results
    result["threat_assessment"] = _aggregate_assessment(results)
    result["pipeline"] += [{"stage": "Infrastructure", "status": "FAILED" if infra.get("error") else "COMPLETED"},
                           {"stage": "Discovery", "status": "SKIPPED" if disc is None else ("FAILED" if disc.get("error") else "COMPLETED")},
                           {"stage": "Threat Intelligence", "status": "COMPLETED"}]
    status = config.provider_status()
    configured = sum(1 for name in selected if status[name]["configured"])
    result["configured_provider_count"] = configured
    result["selected_provider_count"] = len(selected)
    msg = f"Investigation complete. {configured} of {len(selected)} applicable threat-intel providers configured."
    if disc and not disc.get("error"):
        st = disc.get("stats", {})
        if disc.get("kind") == "domain":
            msg += f" Found {st.get('subdomains', 0)} subdomains ({st.get('live', 0)} live) and {st.get('ips', 0)} linked IPs."
        else:
            msg += f" Found {st.get('domains', 0)} domains linked to this IP ({st.get('current', 0)} still resolve to it)."
    result["message"] = msg
    result["finished_at"] = time.time()
    cache.put(ioc["type"], cache_key, result)
    result["cached"] = False
    return result


def prepare_file(name, data):
    hashes = file_hashes(data)
    return {"type": "file", "name": name, "size": len(data), "hashes": hashes, "ioc": hashes["md5"]}

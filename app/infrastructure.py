"""Infrastructure enrichment: DNS, RDAP, TLS and IP context.

All lookups are passive (third-party services) unless `active=True`, in which
case Compass also connects to the target on port 443 to read its certificate.
"""
import base64
import json
import os
import socket
import ssl
import tempfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import net
from .ioc import url_parts
from .psl import registrable_domain


def _json_get(url, headers=None, timeout=8):
    return net.get_json(url, headers=headers, timeout=timeout)


def resolve_host(host):
    result = {"host": host, "a": [], "aaaa": [], "errors": []}
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for fam, _, _, _, addr in infos:
            ip = addr[0]
            if fam == socket.AF_INET and ip not in result["a"]:
                result["a"].append(ip)
            elif fam == socket.AF_INET6 and ip not in result["aaaa"]:
                result["aaaa"].append(ip)
    except Exception as e:
        result["errors"].append(str(e))
    return result


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


RTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


def dns_records(domain):
    """Resolve common record types through public DNS-over-HTTPS resolvers."""
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    out = {"domain": domain, **{rtype: [] for rtype in record_types}, "errors": []}

    def query_type(rtype):
        errors = []
        providers = [
            ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
            ("https://dns.google/resolve", {"Accept": "application/json"}),
        ]
        for endpoint, headers in providers:
            try:
                url = endpoint + "?" + urllib.parse.urlencode({"name": domain, "type": rtype})
                data = net.get_json(url, headers=headers, timeout=6, memo=False)
                vals, seen = [], set()
                records = list(data.get("Answer", []) or [])
                if rtype in ("SOA", "NS"):
                    records += list(data.get("Authority", []) or [])
                want = RTYPE_NUM.get(rtype)
                for ans in records:
                    # Answers can include the CNAME chain; keep only the type asked for.
                    if want and ans.get("type") != want:
                        continue
                    item = {"name": ans.get("name"), "type": ans.get("type"), "ttl": ans.get("TTL"), "data": ans.get("data")}
                    marker = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    if marker not in seen:
                        vals.append(item)
                        seen.add(marker)
                if vals or int(data.get("Status", 0) or 0) == 3:
                    return rtype, vals, None
            except Exception as e:
                errors.append(net.describe_error(e))
        return rtype, [], "; ".join(errors)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for fut in as_completed([pool.submit(query_type, r) for r in record_types]):
            rtype, vals, error = fut.result()
            out[rtype] = vals
            if error:
                out["errors"].append(f"{rtype}: {error}")

    if not out["A"] or not out["AAAA"]:
        resolved = resolve_host(domain)
        if not out["A"]:
            out["A"] = [{"name": domain, "type": 1, "ttl": None, "data": x} for x in resolved["a"]]
        if not out["AAAA"]:
            out["AAAA"] = [{"name": domain, "type": 28, "ttl": None, "data": x} for x in resolved["aaaa"]]
        out["errors"].extend(resolved["errors"])
    return out


def rdap_ip(ip):
    try:
        data = _json_get(f"https://rdap.org/ip/{urllib.parse.quote(ip)}", timeout=10)
        entities = []
        for ent in data.get("entities", []) or []:
            name = None
            vcard = ent.get("vcardArray")
            for obj in (vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []):
                if isinstance(obj, list) and len(obj) >= 4 and obj[0] == "fn":
                    name = obj[3]
                    break
            entities.append({"handle": ent.get("handle"), "roles": ent.get("roles", []), "name": name})
        return {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
            "country": data.get("country"),
            "entities": entities,
            "remarks": data.get("remarks", []),
        }
    except Exception as e:
        return {"error": net.describe_error(e)}


def rdap_domain(domain):
    try:
        data = _json_get(f"https://rdap.org/domain/{urllib.parse.quote(domain)}", timeout=10)
        events = data.get("events", []) or []
        created = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
        return {
            "ldhName": data.get("ldhName"),
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "nameservers": [x.get("ldhName") for x in data.get("nameservers", []) if x.get("ldhName")],
            "events": events,
            "created": created,
            "entities": [{"handle": x.get("handle"), "roles": x.get("roles", [])} for x in data.get("entities", [])],
        }
    except Exception as e:
        return {"error": net.describe_error(e)}


def _name_text(name):
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _decode_der_certificate(der_bytes):
    # ssl.getpeercert() returns an empty dict for unverified connections, so
    # decode the DER certificate with Python's internal helper.
    encoded = base64.b64encode(der_bytes).decode("ascii")
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + "\n-----END CERTIFICATE-----\n"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        path = f.name
        f.write(pem.encode("ascii"))
    try:
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        return decoder(path) if decoder else {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def tls_certificate(host, port=443):
    """ACTIVE: connect to host:port and read the certificate it presents."""
    result = {"host": host, "port": port, "source": "Direct TLS connection (active)"}
    contexts = [ssl.create_default_context(), ssl._create_unverified_context()]
    last_error = None
    for ctx in contexts:
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    if not cert.get("subject") or not cert.get("issuer"):
                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            cert = _decode_der_certificate(der) or cert
                    subject = cert.get("subject") or []
                    issuer = cert.get("issuer") or []
                    result.update({
                        "subject": subject,
                        "subjectText": _name_text(subject),
                        "issuer": issuer,
                        "issuerText": _name_text(issuer),
                        "version": cert.get("version"),
                        "serialNumber": cert.get("serialNumber"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "subjectAltNames": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
                        "cipher": ssock.cipher(),
                    })
                    return result
        except Exception as e:
            last_error = str(e)
    result["error"] = last_error or "TLS connection failed"
    return result


def online_ip_intelligence(ip):
    """Geo/ASN context. ipapi.is first (also gives VPN/proxy/datacenter flags), ipapi.co as fallback."""
    errors = []
    try:
        data = net.get_json(f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}", timeout=10)
        if not isinstance(data, dict) or not data.get("ip"):
            raise ValueError("ipapi.is returned no IP data")
        location = data.get("location") or {}
        company = data.get("company") or {}
        asn = data.get("asn") or {}
        return {
            "available": True,
            "source": "ipapi.is",
            "ip": data.get("ip", ip),
            "country": location.get("country"),
            "countryCode": location.get("country_code"),
            "region": location.get("state") or location.get("state_code"),
            "city": location.get("city"),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
            "timezone": location.get("timezone"),
            "asn": f"AS{asn.get('asn')}" if asn.get("asn") else None,
            "organization": company.get("name") or asn.get("org"),
            "hostname": data.get("hostname"),
            "flags": {k: bool(data.get("is_" + k)) for k in ("vpn", "proxy", "tor", "datacenter", "abuser", "mobile")},
        }
    except Exception as e:
        errors.append(f"ipapi.is: {net.describe_error(e)}")
    try:
        data = net.get_json(f"https://ipapi.co/{urllib.parse.quote(ip)}/json/", timeout=8)
        if data.get("error"):
            raise ValueError(data.get("reason") or "ipapi.co returned an error")
        return {
            "available": True,
            "source": "ipapi.co",
            "ip": data.get("ip", ip),
            "country": data.get("country_name") or data.get("country_code"),
            "countryCode": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("timezone"),
            "asn": data.get("asn"),
            "organization": data.get("org"),
            "hostname": data.get("hostname"),
        }
    except Exception as e:
        errors.append(f"ipapi.co: {net.describe_error(e)}")
    return {"available": False, "source": "online", "errors": errors}


def infrastructure_for_ip(ip):
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_ptr = pool.submit(reverse_dns, ip)
        f_rdap = pool.submit(rdap_ip, ip)
        f_geo = pool.submit(online_ip_intelligence, ip)
        return {"reverse_dns": f_ptr.result(), "rdap": f_rdap.result(), "geoip": f_geo.result()}


def infrastructure_for_domain(domain, active=False):
    dns = dns_records(domain)
    ips = []
    for rtype in ("A", "AAAA"):
        for item in dns.get(rtype, []) or []:
            value = item.get("data") if isinstance(item, dict) else item
            if value and value not in ips:
                ips.append(value)
    ips = ips[:10]
    with ThreadPoolExecutor(max_workers=min(12, 2 + len(ips))) as pool:
        f_rdap = pool.submit(rdap_domain, registrable_domain(domain) or domain)
        f_tls = pool.submit(tls_certificate, domain) if active else None
        ip_futures = {ip: pool.submit(infrastructure_for_ip, ip) for ip in ips}
        rdap = f_rdap.result()
        tls = f_tls.result() if f_tls else None
        resolved = {ip: ip_futures[ip].result() for ip in ips}
    return {"dns": dns, "rdap": rdap, "resolved_ips": resolved, "tls": tls}


def infrastructure_for_url(url, active=False):
    parts = url_parts(url)
    host = parts["hostname"]
    domain_data = {}
    if host:
        try:
            import ipaddress
            ipaddress.ip_address(host)
            domain_data = {"ip": infrastructure_for_ip(host)}
        except ValueError:
            domain_data = infrastructure_for_domain(host, active=active)
    return {"url_parts": parts, "domain": domain_data}

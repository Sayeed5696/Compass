import base64
import ctypes
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
KEY_FILE = DATA_DIR / "providers.json"

PROVIDERS = {
    # Threat-intelligence providers (verdicts). `category` drives the Settings page.
    "virustotal": {
        "label": "VirusTotal",
        "category": "intel",
        "supports": ["ip", "ipv6", "domain", "url", "md5", "sha1", "sha256", "file"],
        "key_required": True,
        "help": "Verdicts plus subdomains and passive DNS for discovery. Free API: 4 requests/min, 500/day.",
    },
    "abuseipdb": {
        "label": "AbuseIPDB",
        "category": "intel",
        "supports": ["ip", "ipv6"],
        "key_required": True,
        "help": "Abuse confidence score and report counts for IPs.",
    },
    "greynoise": {
        "label": "GreyNoise Community",
        "category": "intel",
        "supports": ["ip"],
        "key_required": True,
        "help": "Separates Internet scanners and benign services from targeted activity.",
    },
    "urlscan": {
        "label": "URLScan",
        "category": "intel",
        "supports": ["url", "domain", "ip"],
        "key_required": True,
        "help": "Scan history; also used to find subdomains and domains hosted on an IP.",
    },
    "urlhaus": {
        "label": "URLhaus",
        "category": "intel",
        "supports": ["ip", "domain", "url", "md5", "sha256"],
        "key_required": True,
        "help": "abuse.ch malware URL and payload database (abuse.ch Auth-Key).",
    },
    # Discovery sources: optional keys that raise limits or add data.
    "otx": {
        "label": "AlienVault OTX",
        "category": "discovery",
        "supports": ["domain", "ip"],
        "key_required": False,
        "help": "Passive DNS. Works without a key; a free key raises rate limits.",
    },
    "hackertarget": {
        "label": "HackerTarget",
        "category": "discovery",
        "supports": ["domain", "ip"],
        "key_required": False,
        "help": "Host search and reverse IP. Free tier has a small daily quota; a paid key raises it.",
    },
    "securitytrails": {
        "label": "SecurityTrails",
        "category": "discovery",
        "supports": ["domain"],
        "key_required": True,
        "help": "Optional. Large subdomain dataset (free plan has a small monthly quota).",
    },
    "nvd": {
        "label": "NVD",
        "category": "cve",
        "supports": ["cve", "keyword", "application"],
        "key_required": False,
        "help": "Optional. Raises NVD CVE API rate limits.",
    },
}

def _protect_windows(value: str) -> str:
    if os.name != "nt":
        raise RuntimeError("API keys are encrypted with Windows DPAPI, so keys can only be saved when Compass runs on Windows.")
    raw = value.encode("utf-8")
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    blob_in = DATA_BLOB()
    blob_in.cbData = len(raw)
    buf = ctypes.create_string_buffer(raw)
    blob_in.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return base64.b64encode(encrypted).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)

def _unprotect_windows(value: str) -> str:
    if os.name != "nt":
        return ""
    encrypted = base64.b64decode(value.encode("ascii"))
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    blob_in = DATA_BLOB()
    blob_in.cbData = len(encrypted)
    buf = ctypes.create_string_buffer(encrypted)
    blob_in.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)

def _load():
    if not KEY_FILE.exists():
        return {}
    try:
        data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _save(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = KEY_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(KEY_FILE)

def provider_status():
    data = _load()
    out = {}
    for name, meta in PROVIDERS.items():
        out[name] = {
            "name": name,
            "label": meta["label"],
            "supports": meta["supports"],
            "key_required": meta["key_required"],
            "category": meta.get("category", "intel"),
            "help": meta.get("help", ""),
            "configured": bool(data.get(name)),
        }
    return out

def get_key(name):
    if name not in PROVIDERS:
        return None
    value = _load().get(name)
    if not value:
        return None
    try:
        return _unprotect_windows(value) or None
    except Exception:
        # A key encrypted under another Windows account/PC cannot be decrypted here.
        return None

def set_key(name, key):
    if name not in PROVIDERS:
        raise ValueError("Unknown provider")
    key = (key or "").strip()
    if not key:
        raise ValueError("API key cannot be empty")
    data = _load()
    data[name] = _protect_windows(key)
    _save(data)

def delete_key(name):
    if name not in PROVIDERS:
        raise ValueError("Unknown provider")
    data = _load()
    data.pop(name, None)
    _save(data)

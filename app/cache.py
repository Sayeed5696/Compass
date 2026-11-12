"""Small local server-side investigation cache for recurring IOC searches."""
import json
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data"
CACHE_FILE = CACHE_DIR / "investigation_cache.json"
TTL_SECONDS = 24 * 60 * 60
CACHE_VERSION = "5.0"
MAX_ENTRIES = 250
_lock = threading.RLock()


def _load():
    if not CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp.replace(CACHE_FILE)


def make_key(ioc_type, value):
    return f"{CACHE_VERSION}:{str(ioc_type or '').lower()}:{str(value or '').strip().lower()}"


def get(ioc_type, value):
    key = make_key(ioc_type, value)
    now = time.time()
    with _lock:
        data = _load()
        item = data.get(key)
        if not isinstance(item, dict):
            return None
        if now - float(item.get("cached_at", 0)) > TTL_SECONDS:
            data.pop(key, None)
            _save(data)
            return None
        result = item.get("result")
        if not isinstance(result, dict):
            return None
        return result


def put(ioc_type, value, result):
    key = make_key(ioc_type, value)
    with _lock:
        data = _load()
        data[key] = {"cached_at": time.time(), "result": result}
        # Keep the newest entries only.
        if len(data) > MAX_ENTRIES:
            ordered = sorted(data.items(), key=lambda kv: float(kv[1].get("cached_at", 0)), reverse=True)
            data = dict(ordered[:MAX_ENTRIES])
        _save(data)

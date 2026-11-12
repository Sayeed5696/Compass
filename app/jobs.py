"""Background investigation jobs with live progress.

Investigations can take 20-60 seconds, so the browser starts a job and polls
for progress instead of holding one long HTTP request open. Jobs belong to
the user who started them; other users cannot read them.
"""
import secrets
import threading
import time
import traceback

MAX_CONCURRENT = 6        # investigations running at once (others wait in a queue)
KEEP_SECONDS = 30 * 60    # finished jobs are kept this long for the browser to collect

_jobs = {}
_lock = threading.Lock()
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


class Job:
    def __init__(self, user_id, kind, title):
        self.id = secrets.token_urlsafe(12)
        self.user_id = user_id
        self.kind = kind
        self.title = title
        self.status = "queued"
        self.created = time.time()
        self.updated = self.created
        self.events = {}
        self.order = []
        self.result = None
        self.error = None
        self.lock = threading.Lock()

    def emit(self, event):
        key = f"{event.get('group', 'misc')}:{event.get('id')}"
        with self.lock:
            if key not in self.events:
                self.order.append(key)
            prev = self.events.get(key, {})
            merged = dict(prev)
            merged.update({k: v for k, v in event.items() if v is not None})
            if event.get("status") in ("running", "queued"):
                merged.pop("error", None)
            self.events[key] = merged
            self.updated = time.time()

    def snapshot(self, include_result=True):
        with self.lock:
            out = {
                "id": self.id,
                "kind": self.kind,
                "title": self.title,
                "status": self.status,
                "created": self.created,
                "elapsed": round((self.updated if self.status in ("done", "failed") else time.time()) - self.created, 1),
                "events": [self.events[k] for k in self.order],
            }
            if self.status == "done" and include_result:
                out["result"] = self.result
            if self.error:
                out["error"] = self.error
            return out


def _cleanup():
    now = time.time()
    with _lock:
        for jid in [j for j, job in _jobs.items() if job.status in ("done", "failed") and now - job.updated > KEEP_SECONDS]:
            _jobs.pop(jid, None)


def start(user_id, kind, title, fn, on_done=None):
    """Run fn(job) in a background thread. on_done(job) runs after success."""
    _cleanup()
    job = Job(user_id, kind, title)
    with _lock:
        _jobs[job.id] = job

    def runner():
        with _slots:
            job.status = "running"
            job.updated = time.time()
            try:
                job.result = fn(job)
                job.status = "done"
                if on_done:
                    try:
                        on_done(job)
                    except Exception:
                        traceback.print_exc()
            except Exception as e:
                traceback.print_exc()
                job.error = str(e) or e.__class__.__name__
                job.status = "failed"
            job.updated = time.time()

    threading.Thread(target=runner, name=f"job-{job.id}", daemon=True).start()
    return job


def get(job_id, user_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job or job.user_id != user_id:
        return None
    return job

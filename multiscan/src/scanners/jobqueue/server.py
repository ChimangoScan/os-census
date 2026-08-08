"""HTTP coordinator: serves one SQLite-backed queue over HTTP so many worker
machines can claim jobs and post results to a single shared queue. Started by
``scanners coordinator``."""
from __future__ import annotations
import json, logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..models import Target
from .sqlite_queue import SqliteQueue

log = logging.getLogger("scanners.coordinator")

# Wire protocol (JSON in, JSON out):
#   POST /claim      {worker_id}                       -> {job:{id,target,attempts}} | 204
#   POST /heartbeat  {job_id, worker_id}               -> {}
#   POST /complete   {job_id, worker_id, report}       -> {}
#   POST /fail       {job_id, worker_id, error, max_attempts} -> {}
#   POST /skip       {job_id, worker_id, reason}       -> {}
#   POST /seed       {targets:[...]}                   -> {added}
#   POST /reset      {failed, skipped}                 -> {requeued}
#   POST /reset_stale {stale_minutes}                  -> {requeued}
#   GET  /stats                                        -> {...}
#   GET  /reports                                      -> JSON Lines (one report per line)
#   GET  /healthz                                      -> {ok:true}


class _Handler(BaseHTTPRequestHandler):
    """Request handler translating the wire protocol above 1:1 onto a ``SqliteQueue``.

    Stateless per request: all state lives in ``self.server.queue``, shared by
    every thread of the ``ThreadingHTTPServer``.
    """

    protocol_version = "HTTP/1.1"

    @property
    def q(self) -> SqliteQueue:
        """The shared `SqliteQueue` instance, stashed on the server object so every handler/thread reaches the same queue."""
        return self.server.queue          # type: ignore[attr-defined]

    @property
    def token(self) -> str:
        """The configured bearer token (empty string if auth is disabled)."""
        return self.server.token          # type: ignore[attr-defined]

    def log_message(self, fmt, *args):    # quieter default logging
        """Override BaseHTTPRequestHandler's default stderr access log to route through the module logger at debug level instead."""
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ── helpers ─────────────────────────────────────────────────────────────
    def _auth_ok(self) -> bool:
        """True if no token is configured, or the request's bearer token matches it."""
        if not self.token:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {self.token}"

    def _body(self) -> dict:
        """Read and JSON-decode the request body, or ``{}`` if there is none."""
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def _send(self, code: int, obj=None, *, raw: bytes | None = None, ctype="application/json"):
        """Write a full HTTP response: ``obj`` JSON-encoded, or ``raw`` bytes verbatim if given."""
        payload = raw if raw is not None else (b"" if obj is None else json.dumps(obj).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _guard(self) -> bool:
        """Send 401 and return False if auth fails; otherwise return True."""
        if not self._auth_ok():
            self._send(401, {"error": "unauthorized"})
            return False
        return True

    # ── routes ──────────────────────────────────────────────────────────────
    def do_GET(self):
        """Dispatch GET /healthz, /stats, /reports; 404 otherwise."""
        if not self._guard():
            return
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        if self.path == "/stats":
            return self._send(200, self.q.stats())
        if self.path == "/reports":
            lines = b"".join(json.dumps(r).encode() + b"\n" for r in self.q.iter_reports())
            return self._send(200, raw=lines, ctype="application/x-ndjson")
        self._send(404, {"error": "not found"})

    def do_POST(self):
        """Dispatch each mutating queue op to the matching ``SqliteQueue`` method.

        A missing required field raises ``KeyError``, reported as 400; any other
        exception is logged and reported as 500 rather than crashing the
        (shared, multi-threaded) server process.
        """
        if not self._guard():
            return
        try:
            b = self._body()
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "bad json"})
        try:
            if self.path == "/claim":
                job = self.q.claim(b["worker_id"])
                if job is None:
                    return self._send(204)
                return self._send(200, {"job": {"id": job.id, "target": job.target.to_json(),
                                                "attempts": job.attempts}})
            if self.path == "/heartbeat":
                self.q.heartbeat(b["job_id"], b["worker_id"]); return self._send(200, {})
            if self.path == "/complete":
                self.q.complete(b["job_id"], b["worker_id"], b.get("report") or {}); return self._send(200, {})
            if self.path == "/fail":
                self.q.fail(b["job_id"], b["worker_id"], b.get("error", ""), int(b.get("max_attempts", 3)))
                return self._send(200, {})
            if self.path == "/skip":
                self.q.skip(b["job_id"], b["worker_id"], b.get("reason", "")); return self._send(200, {})
            if self.path == "/seed":
                ts = [Target.from_json(t) for t in b.get("targets", [])]
                return self._send(200, {"added": self.q.seed(ts)})
            if self.path == "/reset":
                return self._send(200, {"requeued": self.q.reset(failed=bool(b.get("failed")),
                                                                 skipped=bool(b.get("skipped")),
                                                                 done=bool(b.get("done")))})
            if self.path == "/reset_stale":
                return self._send(200, {"requeued": self.q.reset_stale(int(b.get("stale_minutes", 15)))})
        except KeyError as e:
            return self._send(400, {"error": f"missing field {e}"})
        except Exception as e:                       # never take the server down
            log.exception("handler error")
            return self._send(500, {"error": str(e)})
        self._send(404, {"error": "not found"})


class _Server(ThreadingHTTPServer):
    """A ``ThreadingHTTPServer`` with daemon worker threads and address reuse for quick restarts."""

    daemon_threads = True
    allow_reuse_address = True


def serve(db_path: str, host: str, port: int, token: str = "") -> None:
    """Run the coordinator forever: open/create the SQLite queue at ``db_path`` and serve it on ``host:port``.

    Blocks until interrupted (``Ctrl-C``), then shuts the server down cleanly.
    ``token``, if set, is required as a bearer token on every request.
    """
    srv = _Server((host, port), _Handler)
    srv.queue = SqliteQueue(db_path)      # type: ignore[attr-defined]
    srv.token = token                     # type: ignore[attr-defined]
    log.info("coordinator on http://%s:%d (db=%s, auth=%s)", host, port, db_path, "on" if token else "off")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()

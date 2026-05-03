#!/usr/bin/env python3
"""Local reverse proxy: routes /anthropic/* and /openai/* to their respective APIs."""
import http.server
import urllib.request
import urllib.error
import ssl
import os
import time
import json
import hmac
import threading
from datetime import datetime

PORT = int(os.environ.get("PROXY_PORT", "8080"))
PROXY_API_KEY = os.environ.get("PROXY_API_KEY", "")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "skills-network")
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(50 * 1024 * 1024)))  # 50MB
UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "300"))  # 5 minutes

# Lockout against PROXY_API_KEY brute-force. After AUTH_FAIL_MAX failures
# within AUTH_FAIL_WINDOW seconds from the same client IP, every request
# from that IP is rejected with 429 + Retry-After for AUTH_FAIL_LOCKOUT
# seconds. Defaults are conservative: a real user mistyping their key a
# couple times in a row won't trip it, but a brute-force loop will.
AUTH_FAIL_MAX = int(os.environ.get("AUTH_FAIL_MAX", "5"))
AUTH_FAIL_WINDOW = int(os.environ.get("AUTH_FAIL_WINDOW", "60"))
AUTH_FAIL_LOCKOUT = int(os.environ.get("AUTH_FAIL_LOCKOUT", "60"))
_auth_lock = threading.Lock()
_auth_state: dict = {}  # ip -> {"fails": int, "first_fail_ts": float, "locked_until": float}
_auth_cleanup_at = 0.0


def _auth_cleanup_locked(now: float):
    global _auth_cleanup_at
    if now < _auth_cleanup_at:
        return
    _auth_cleanup_at = now + 300
    expired = [ip for ip, s in _auth_state.items()
               if s["locked_until"] <= now and now - s["first_fail_ts"] > AUTH_FAIL_WINDOW]
    for ip in expired:
        _auth_state.pop(ip, None)


def auth_lockout_remaining(ip: str) -> int:
    """Seconds left in lockout for `ip`, or 0 if not locked."""
    if not ip:
        return 0
    now = time.time()
    with _auth_lock:
        s = _auth_state.get(ip)
        if not s:
            return 0
        return max(0, int(s["locked_until"] - now))


def auth_record_fail(ip: str):
    if not ip:
        return
    now = time.time()
    with _auth_lock:
        _auth_cleanup_locked(now)
        s = _auth_state.get(ip) or {"fails": 0, "first_fail_ts": now, "locked_until": 0.0}
        if now - s["first_fail_ts"] > AUTH_FAIL_WINDOW:
            s["fails"] = 0
            s["first_fail_ts"] = now
        s["fails"] += 1
        if s["fails"] >= AUTH_FAIL_MAX:
            s["locked_until"] = now + AUTH_FAIL_LOCKOUT
        _auth_state[ip] = s


def auth_record_success(ip: str):
    if not ip:
        return
    with _auth_lock:
        _auth_state.pop(ip, None)


ROUTES = {
    "/anthropic": "https://api.anthropic.com",
    "/openai":    "https://api.openai.com",
}

AUTH_HEADER_NAMES = {"x-api-key", "authorization"}

# Strict allowlist: only upstream response headers the client legitimately
# needs are forwarded. Everything else (Skills-Network-*, helmet/Express
# security headers, Server, Date, Etag, CSP, Cross-Origin-*, etc.) is
# dropped so the public tunnel reveals nothing about what's behind it.
SAFE_RESPONSE_HEADERS = {
    "content-type",
    "content-encoding",
    "cache-control",
    "retry-after",
    "request-id",
    "x-request-id",
}
SAFE_RESPONSE_PREFIXES = ("anthropic-", "openai-", "x-ratelimit-")


def _is_safe_response_header(name: str) -> bool:
    n = name.lower()
    return n in SAFE_RESPONSE_HEADERS or any(n.startswith(p) for p in SAFE_RESPONSE_PREFIXES)


# Skills-Network upstream returns every API error inside an HTTP 200, which
# breaks SDK error handling and silences automatic retries (rate_limit,
# overloaded). We detect the error envelope, unwrap it, and restore the
# correct status. Two formats supported:
#   Anthropic: {"type":"error","error":{"type":"...","message":"..."}}
#   OpenAI:    {"error":{"message":"...","type":"...","code":"..."}}
ANTHROPIC_ERROR_STATUS = {
    "invalid_request_error": 400,
    "authentication_error": 401,
    "billing_error": 400,
    "permission_error": 403,
    "not_found_error": 404,
    "request_too_large": 413,
    "rate_limit_error": 429,
    "api_error": 500,
    "overloaded_error": 529,
}

# OpenAI exposes the more specific situation in `error.code`, so we check it
# first and fall back to `error.type`.
OPENAI_ERROR_CODE_STATUS = {
    "model_not_found": 404,
    "invalid_api_key": 401,
    "rate_limit_exceeded": 429,
    "insufficient_quota": 429,
    "context_length_exceeded": 400,
}
OPENAI_ERROR_TYPE_STATUS = {
    "invalid_request_error": 400,
    "authentication_error": 401,
    "permission_error": 403,
    "not_found_error": 404,
    "rate_limit_error": 429,
    "server_error": 500,
    "insufficient_quota": 429,
}


def _unwrap_error_status(status: int, content_type: str, body: bytes) -> int:
    if status != 200 or "application/json" not in (content_type or "").lower():
        return status
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return status
    if not isinstance(payload, dict):
        return status

    # Anthropic envelope
    if payload.get("type") == "error":
        err = payload.get("error")
        if isinstance(err, dict):
            return ANTHROPIC_ERROR_STATUS.get(err.get("type", ""), 500)
        return status

    # OpenAI envelope (no top-level "type":"error" wrapper)
    err = payload.get("error")
    if isinstance(err, dict) and ("type" in err or "message" in err):
        return (OPENAI_ERROR_CODE_STATUS.get(err.get("code") or "")
                or OPENAI_ERROR_TYPE_STATUS.get(err.get("type") or "")
                or 500)

    return status


def _find_header(headers: dict, name: str):
    """Case-insensitive header lookup. Returns (key, value) or (None, None)."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return k, v
    return None, None


def check_and_replace_key(headers: dict, ts: str, api: str):
    """Validate the incoming API key and swap it for the internal one."""
    if not PROXY_API_KEY:
        return headers, True

    _, x_api = _find_header(headers, "x-api-key")
    _, auth = _find_header(headers, "authorization")

    bearer = ""
    if auth:
        a = auth.strip()
        if a.lower().startswith("bearer "):
            bearer = a[7:].strip()
        else:
            bearer = a

    provided = (x_api or "").strip() or bearer

    if not hmac.compare_digest(provided, PROXY_API_KEY):
        print(f"[{ts}]     {api:10s} 401 invalid API key", flush=True)
        return headers, False

    cleaned = {k: v for k, v in headers.items() if k.lower() not in AUTH_HEADER_NAMES}
    if x_api is not None:
        cleaned["x-api-key"] = INTERNAL_API_KEY
    if auth is not None:
        cleaned["Authorization"] = f"Bearer {INTERNAL_API_KEY}"

    return cleaned, True


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _client_ip(self) -> str:
        # ngrok prepends the real external client IP to X-Forwarded-For;
        # take the first non-empty value. Fall back to the TCP peer if absent.
        xff = self.headers.get("X-Forwarded-For", "") or ""
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        try:
            return self.client_address[0]
        except (AttributeError, IndexError, TypeError):
            return ""

    def _is_external(self) -> bool:
        # ngrok always injects X-Forwarded-For. Local callers (run.sh,
        # health checks on 127.0.0.1) do not.
        return bool(self.headers.get("X-Forwarded-For"))

    def _extract_provided_key(self) -> str:
        x_api = ""
        auth = ""
        for k, v in self.headers.items():
            kl = k.lower()
            if kl == "x-api-key":
                x_api = v
            elif kl == "authorization":
                auth = v
        bearer = ""
        if auth:
            a = auth.strip()
            if a.lower().startswith("bearer "):
                bearer = a[7:].strip()
            else:
                bearer = a
        return (x_api or "").strip() or bearer

    def _send_locked(self, retry_after: int):
        body = b'{"error":"Too many failed auth attempts"}'
        try:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry_after))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_response(self, code, message=None):
        # Skip the default Server header to avoid leaking
        # "BaseHTTP/x.y Python/z.w".
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _send_chunk(self, data: bytes):
        size = f"{len(data):X}\r\n".encode()
        self.wfile.write(size + data + b"\r\n")
        self.wfile.flush()

    def _health(self, ip: str = ""):
        # Allow unauthenticated /health for local callers (run.sh's watch
        # loop hits 127.0.0.1 and never sets X-Forwarded-For). External
        # callers must present PROXY_API_KEY.
        if self._is_external() and PROXY_API_KEY:
            provided = self._extract_provided_key()
            if not hmac.compare_digest(provided, PROXY_API_KEY):
                auth_record_fail(ip)
                self._send_simple(401, b'{"error":"Invalid API key"}')
                return
            auth_record_success(ip)
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _send_simple(self, code: int, body: bytes, content_type: str = "application/json"):
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _proxy(self):
        ts = datetime.now().strftime("%H:%M:%S")
        ip = self._client_ip()

        remaining = auth_lockout_remaining(ip)
        if remaining > 0:
            print(f"[{ts}] LOCK {ip} ({remaining}s left)", flush=True)
            self._send_locked(remaining)
            return

        if self.path == "/health":
            self._health(ip)
            return

        for prefix, target in ROUTES.items():
            if self.path.startswith(prefix):
                upstream_path = self.path[len(prefix):] or "/"
                if not upstream_path.startswith("/"):
                    upstream_path = "/" + upstream_path
                url = target + upstream_path
                api = prefix.lstrip("/").upper()
                break
        else:
            print(f"[{ts}] 404  NO ROUTE  {self.path}", flush=True)
            self._send_simple(404, b'{"error":"No route"}')
            return

        # Body with size cap
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_simple(400, b'{"error":"Invalid Content-Length"}')
            return

        if length > MAX_BODY_BYTES:
            self._send_simple(413, b'{"error":"Request body too large"}')
            return

        body = self.rfile.read(length) if length > 0 else None

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "content-length", "transfer-encoding")}

        headers, authorized = check_and_replace_key(headers, ts, api)
        if not authorized:
            auth_record_fail(ip)
            self._send_simple(401, b'{"error":"Invalid API key"}')
            return
        auth_record_success(ip)

        req = urllib.request.Request(url, data=body, headers=headers, method=self.command)
        ctx = ssl.create_default_context()

        print(f"[{ts}] --> {api:10s} {self.command} {upstream_path}", flush=True)
        t0 = time.time()

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=UPSTREAM_TIMEOUT) as resp:
                content_type = resp.headers.get("Content-Type", "")
                is_stream = "text/event-stream" in content_type

                if is_stream:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if _is_safe_response_header(k):
                            self.send_header(k, v)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.send_header("Connection", "close")
                    self.end_headers()

                    print(f"[{ts}]     {api:10s} streaming...", flush=True)
                    bytes_sent = 0
                    try:
                        # Read line by line — SSE events are line-delimited and end with \n\n
                        buf = bytearray()
                        while True:
                            line = resp.readline()
                            if not line:
                                break
                            buf.extend(line)
                            # Flush on event boundary (blank line) or when buffer gets large
                            if line in (b"\n", b"\r\n") or len(buf) > 16384:
                                self._send_chunk(bytes(buf))
                                bytes_sent += len(buf)
                                buf.clear()
                        if buf:
                            self._send_chunk(bytes(buf))
                            bytes_sent += len(buf)
                        self.wfile.write(b"0\r\n\r\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    elapsed = int((time.time() - t0) * 1000)
                    print(f"[{ts}] <-- {api:10s} {resp.status} stream done ({elapsed}ms) {bytes_sent}b", flush=True)
                else:
                    # Buffer the body so we can recover the real HTTP status
                    # when Skills-Network wrapped an error inside a 200.
                    data = resp.read()
                    status = _unwrap_error_status(resp.status, content_type, data)

                    self.send_response(status)
                    for k, v in resp.headers.items():
                        if _is_safe_response_header(k):
                            self.send_header(k, v)
                    self.send_header("Connection", "close")
                    self.end_headers()

                    elapsed = int((time.time() - t0) * 1000)
                    label = f"{resp.status}->{status}" if status != resp.status else f"{status}"
                    print(f"[{ts}] <-- {api:10s} {label} ({elapsed}ms) {len(data)}b", flush=True)
                    try:
                        self.wfile.write(data)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

        except urllib.error.HTTPError as e:
            data = e.read()
            elapsed = int((time.time() - t0) * 1000)
            print(f"[{ts}] <-- {api:10s} {e.code} ERROR ({elapsed}ms) {data[:200]!r}", flush=True)
            try:
                self.send_response(e.code)
                for k, v in e.headers.items():
                    if _is_safe_response_header(k):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        except (BrokenPipeError, ConnectionResetError):
            elapsed = int((time.time() - t0) * 1000)
            print(f"[{ts}] <-- {api:10s} client disconnected ({elapsed}ms)", flush=True)
        except Exception as e:
            elapsed = int((time.time() - t0) * 1000)
            print(f"[{ts}] <-- {api:10s} FAILED ({elapsed}ms) {e}", flush=True)
            self._send_simple(502, json.dumps({"error": "Upstream error", "detail": str(e)}).encode())

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _proxy


if __name__ == "__main__":
    if not PROXY_API_KEY:
        print("[proxy] WARNING: PROXY_API_KEY not set — tunnel is open to anyone", flush=True)
    else:
        print("[proxy] API key protection enabled", flush=True)

    # SO_REUSEADDR avoids "Address already in use" right after restart
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), ProxyHandler)
    print(f"[proxy] Listening on http://127.0.0.1:{PORT}", flush=True)
    print(f"[proxy]   max body: {MAX_BODY_BYTES} bytes, upstream timeout: {UPSTREAM_TIMEOUT}s", flush=True)
    for prefix, target in ROUTES.items():
        print(f"[proxy]   {prefix}/* → {target}/*", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

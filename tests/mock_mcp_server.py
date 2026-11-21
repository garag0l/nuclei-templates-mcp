"""Configurable mock MCP server (Streamable HTTP + legacy SSE + OAuth metadata) for template tests.

  python tests/mock_mcp_server.py --port 8801                      # vulnerable: no auth, no Host/Origin/Content-Type checks, SSE on
  python tests/mock_mcp_server.py --port 8802 --auth --validate-host --strict-content-type --no-sse   # hardened

Never exposes anything real: tools are fake and are never executed.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "run_query", "description": "Run a read-only SQL query", "inputSchema": {"type": "object"}},
    {"name": "read_file", "description": "Read a file from the workspace", "inputSchema": {"type": "object"}},
]


def make_handler(cfg):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", ctype="application/json", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self):
            if not cfg.validate_host:
                return True
            host = (self.headers.get("Host") or "").split(":")[0]
            origin = self.headers.get("Origin")
            if host not in ("localhost", "127.0.0.1"):
                return False
            return origin is None or origin.startswith(("http://localhost", "http://127.0.0.1"))

        def _authorized(self):
            return not cfg.auth or self.headers.get("Authorization") == "Bearer test-token"

        def _unauth(self):
            base = f"http://{self.headers.get('Host')}"
            self._send(401, b'{"error":"unauthorized"}', extra={
                "WWW-Authenticate": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"'})

        def do_GET(self):
            base = f"http://{self.headers.get('Host')}"
            if self.path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource") and cfg.auth:
                return self._send(200, json.dumps({
                    "resource": f"{base}/mcp", "authorization_servers": ["https://auth.example.com"],
                    "scopes_supported": ["mcp"], "bearer_methods_supported": ["header"]}).encode())
            if self.path == "/sse" and cfg.sse:
                if not self._host_ok():
                    return self._send(403, b'{"error":"forbidden host"}')
                if not self._authorized():
                    return self._unauth()
                # Like real SSE servers: send the endpoint event, then keep the stream open (no length, no close).
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                sid = uuid.uuid4().hex
                self.wfile.write(f"event: endpoint\ndata: /messages?sessionId={sid}\n\n".encode())
                self.wfile.flush()
                for _ in range(60):  # keep-alive pings for up to 60s, then give up
                    time.sleep(1)
                    try:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                    except OSError:
                        break
                self.close_connection = True
                return
            self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            if self.path not in ("/mcp", "/mcp/"):
                return self._send(404, b'{"error":"not found"}')
            if not self._host_ok():
                return self._send(403, b'{"error":"forbidden host or origin"}')
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if cfg.strict_content_type and ctype != "application/json":
                return self._send(415, b'{"error":"unsupported media type"}')
            if not self._authorized():
                return self._unauth()
            try:
                msg = json.loads(raw or b"{}")
            except ValueError:
                return self._send(400, b'{"error":"parse error"}')
            method, mid = msg.get("method"), msg.get("id")
            if method == "initialize":
                result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "mock-mcp", "version": "1.2.3"}}
                return self._send(200, json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}).encode(),
                                  extra={"Mcp-Session-Id": uuid.uuid4().hex})
            if method == "tools/list":
                return self._send(200, json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}).encode())
            if method and method.startswith("notifications/"):
                return self._send(202)
            return self._send(200, json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}}).encode())

    return H


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--auth", action="store_true")
    p.add_argument("--validate-host", action="store_true")
    p.add_argument("--strict-content-type", action="store_true")
    p.add_argument("--no-sse", dest="sse", action="store_false")
    cfg = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", cfg.port), make_handler(cfg))
    print(f"mock MCP on http://127.0.0.1:{cfg.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

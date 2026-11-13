"""Live dashboard. Run from the project root:  python dashboard/dashboard_server.py
Open http://127.0.0.1:8080  -- reads logs/forensic_report.json (refreshes every 2 s)."""
import http.server, os, socketserver
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(ROOT, "logs", "forensic_report.json")

class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/api/report"):
            try: body = open(REPORT, "rb").read()
            except OSError: body = b"{}"
            return self._send(200, "application/json", body)
        if self.path in ("/", "/index.html"):
            return self._send(200, "text/html; charset=utf-8", open(os.path.join(HERE, "index.html"), "rb").read())
        self._send(404, "text/plain", b"not found")
    def log_message(self, *a): pass

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", 8080), H) as s:
        print("Dashboard on http://127.0.0.1:8080  (Ctrl+C to stop)"); s.serve_forever()

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from urllib.parse import urlparse
from datetime import datetime


class Handler(BaseHTTPRequestHandler):
    def _set_json(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "http://localhost:5174")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "http://localhost:5174")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._set_json()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return

        # /api/v1/alerts/{id}/file
        parts = path.strip("/").split("/")
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "alerts" and parts[4] == "file":
            alert_id = parts[3]
            now = datetime.utcnow().isoformat() + "Z"
            resp = {
                "scan_id": alert_id,
                "filename": f"example_{alert_id}.txt",
                "input_preview": "This is a small preview of the file contents...",
                "entities": [{"type": "EMAIL_ADDRESS", "value": "secret@example.com", "start": 10, "end": 27}],
                "created_at": now,
            }
            self._set_json()
            self.wfile.write(json.dumps(resp).encode())
            return

        # Not found
        self.send_response(404)
        self.end_headers()


def run(port=8000):
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Dev stub running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    run()

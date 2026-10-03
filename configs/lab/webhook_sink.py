"""Dev-only webhook receiver: logs every POST body (and signature header) as one JSON line."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        print(json.dumps({"path": self.path, "signature": self.headers.get("X-BB-Signature"),
                          "body": body.decode("utf-8", "replace")}), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Sink).serve_forever()  # noqa: S104 - internal compose network only

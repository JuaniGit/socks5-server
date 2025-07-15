#!/usr/bin/env python3
# save as server.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = b"A" * 1024  # 1 KB of dummy data
        self.send_response(200)
        self.send_header('Content-type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass  # Silence the logs

PORT = 3000
print(f"Serving 1KB responses on http://localhost:{PORT}")
HTTPServer(('', PORT), SimpleHandler).serve_forever()
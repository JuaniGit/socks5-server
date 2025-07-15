#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

CHUNK_SIZE = 1024 * 1024  # 1 MB
NUM_CHUNKS = 1024         # 1024 MB = 1 GB

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""

class OneGBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        total_size = CHUNK_SIZE * NUM_CHUNKS
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total_size))
        self.end_headers()

        data = b"A" * CHUNK_SIZE
        for _ in range(NUM_CHUNKS):
            try:
                self.wfile.write(data)
            except BrokenPipeError:
                break  # client disconnected

    def log_message(self, format, *args):
        return  # Silence logs

if __name__ == "__main__":
    server_address = ('', 3000)
    httpd = ThreadedHTTPServer(server_address, OneGBHandler)
    print("💣 Serving 1GB per request on http://localhost:3000")
    httpd.serve_forever()

"""Always-pass captcha siteverify for real-stack e2e. Not a bot check."""

from http.server import BaseHTTPRequestHandler, HTTPServer


class DummyCaptchaHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"success":true}')

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.end_headers()
        self.wfile.write(b"// e2e dummy captcha\n")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 80), DummyCaptchaHandler).serve_forever()

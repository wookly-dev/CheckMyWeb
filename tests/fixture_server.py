"""Local test website with configurable security weaknesses.

Serves HTTPS (with a throwaway test CA generated into tests/certs) and a companion plain
HTTP port on 127.0.0.1. Profiles reproduce typical servers so CheckMyWeb can be
verified without scanning anyone's real site:

  weak      Apache + PHP: no security headers, exposed .env/.git, TRACE,
            reflected CORS, plain-HTTP login page, outdated jQuery
  typical   Apache + PHP kept up reasonably well: HTTPS and HSTS in place, only
            CSP, clickjacking and a few low-severity items missing (grade B)
  hardened  nginx with every recommended header and nothing exposed
  cdn       a site behind Cloudflare (CF-Ray header)

Run by hand:  python tests/fixture_server.py --profile weak
"""
from __future__ import annotations

import argparse
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CERT_DIR = Path(__file__).with_name("certs")
CA_FILE = str(CERT_DIR / "ca.pem")


def ensure_certs() -> bool:
    """Generate the throwaway test certificates on first use (they are not committed)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("make_certs", CERT_DIR / "make_certs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ensure(CERT_DIR)

APP_JS = ("application/javascript", "console.log('fixture');\n")

HOME_WEAK = """<!doctype html><html><head><title>Fixture shop</title>
<meta name="generator" content="WordPress 5.8.1">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.min.js"></script>
<script src="/static/app.js"></script>
</head><body>
<form action="/login" method="post"><input name="id"><input type="password" name="pw"></form>
<img src="http://insecure.example/logo.png" alt="">
</body></html>"""

HOME_PLAIN = """<!doctype html><html><head><title>Fixture</title>
<script src="/static/app.js"></script></head><body><p>hello</p></body></html>"""

PROFILES = {
    "weak": {
        "server": "Apache/2.4.41 (Ubuntu)",
        "home": HOME_WEAK,
        "headers": {"X-Powered-By": "PHP/7.4.3"},
        "cookies": ["PHPSESSID=fixture123; path=/"],
        "trace": True,
        "cors_reflect": True,
        "allow": "GET, POST, OPTIONS, HEAD, TRACE, PUT, DELETE",
        "files": {
            "/.env": ("text/plain", "APP_KEY=base64:Zml4dHVyZQ==\nDB_PASSWORD=fixture-only\n"),
            "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
            "/uploads/": ("text/html", "<html><head><title>Index of /uploads</title></head>"
                                       "<body><h1>Index of /uploads</h1></body></html>"),
            "/static/app.js": APP_JS,
        },
        "not_found": "<html><body><h1>Not Found</h1><hr>"
                     "<address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1 Port 443</address></body></html>",
        "http_redirect": False,
    },
    "typical": {
        "server": "Apache/2.4.62 (Rocky Linux)",
        "home": HOME_PLAIN,
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Powered-By": "PHP/8.2.27",
        },
        "cookies": ["PHPSESSID=fixture123; path=/; Secure; HttpOnly"],
        "trace": False,
        "cors_reflect": False,
        "allow": "GET, POST, HEAD, OPTIONS",
        "files": {"/static/app.js": APP_JS},
        "not_found": "<html><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>",
        "http_redirect": True,
    },
    "hardened": {
        "server": "nginx",
        "home": HOME_PLAIN,
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
        "cookies": ["__Host-sid=fixture; Path=/; Secure; HttpOnly; SameSite=Strict"],
        "trace": False,
        "cors_reflect": False,
        "allow": "GET, POST, HEAD, OPTIONS",
        "files": {
            "/static/app.js": APP_JS,
            "/.well-known/security.txt": ("text/plain", "Contact: mailto:security@example.com\n"
                                                        "Expires: 2099-12-31T00:00:00Z\n"),
        },
        "not_found": "<html><body><h1>404 Not Found</h1><hr><center>nginx</center></body></html>",
        "http_redirect": True,
    },
    "cdn": {
        "server": "cloudflare",
        "home": HOME_PLAIN,
        "headers": {"CF-RAY": "8f00f1x7ure0000-ICN", "CF-Cache-Status": "DYNAMIC"},
        "cookies": [],
        "trace": False,
        "cors_reflect": False,
        "allow": "",
        "files": {"/static/app.js": APP_JS},
        "not_found": "<html><body>Not found</body></html>",
        "http_redirect": True,
    },
}


def make_handler(profile: dict, state: dict):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self):
            return profile["server"]

        def log_message(self, format, *args):  # keep test output quiet
            pass

        def _send(self, status, body: bytes, ctype="text/html; charset=utf-8", extra=(), head=False):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for key, value in extra:
                self.send_header(key, value)
            self.end_headers()
            if not head:
                self.wfile.write(body)
            self.close_connection = True

        def _site_headers(self):
            headers = list(profile["headers"].items())
            origin = self.headers.get("Origin")
            if origin and profile["cors_reflect"]:
                headers += [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            return headers

        def _route(self, head=False):
            path = self.path.split("?", 1)[0]
            if state.get("plain") and profile["http_redirect"]:
                location = f"https://127.0.0.1:{state['https_port']}{self.path}"
                return self._send(301, b"", extra=[("Location", location)], head=head)
            if path == "/":
                extra = self._site_headers() + [("Set-Cookie", c) for c in profile["cookies"]]
                return self._send(200, profile["home"].encode(), extra=extra, head=head)
            if path == "/.well-known/checkmyweb-verify.txt" and state.get("verify_token"):
                return self._send(200, state["verify_token"].encode(), "text/plain", head=head)
            if path in profile["files"]:
                ctype, body = profile["files"][path]
                return self._send(200, body.encode(), ctype, extra=self._site_headers(), head=head)
            return self._send(404, profile["not_found"].encode(), extra=self._site_headers(), head=head)

        def do_GET(self):
            self._route()

        def do_HEAD(self):
            self._route(head=True)

        def do_OPTIONS(self):
            if profile["allow"]:
                self._send(200, b"", extra=[("Allow", profile["allow"])])
            else:
                self._send(405, b"", "text/plain")

        def do_TRACE(self):
            if profile["trace"]:
                self._send(200, f"{self.requestline}\r\n{self.headers}".encode(), "message/http")
            else:
                self._send(405, b"Method Not Allowed", "text/plain")

    return Handler


class _TLSServer(ThreadingHTTPServer):
    """Does the TLS handshake in the worker thread, so a failed probe cannot stall the accept loop."""

    def __init__(self, address, handler, context: ssl.SSLContext):
        super().__init__(address, handler)
        self.context = context

    def finish_request(self, request, client_address):
        request.settimeout(10)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return  # scanners probe old protocols and ciphers on purpose
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass


class FixtureSite:
    def __init__(self, profile: str = "weak", verify_token: str | None = None,
                 https_port: int = 0, http_port: int = 0):
        self.profile = PROFILES[profile]
        self.state = {"verify_token": verify_token}
        self._ports = (https_port, http_port)
        self._threads: list[threading.Thread] = []

    def start(self) -> "FixtureSite":
        if not ensure_certs():
            raise RuntimeError("openssl is needed once to create the test certificates (tests/certs/make_certs.py)")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_DIR / "server.pem", CERT_DIR / "server.key")
        self.https = _TLSServer(("127.0.0.1", self._ports[0]), make_handler(self.profile, self.state), context)
        self.state["https_port"] = self.https.server_address[1]
        plain_state = dict(self.state, plain=True)
        self.http = ThreadingHTTPServer(("127.0.0.1", self._ports[1]), make_handler(self.profile, plain_state))
        for server in (self.https, self.http):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def stop(self) -> None:
        for server in (self.https, self.http):
            server.shutdown()
            server.server_close()

    def __enter__(self) -> "FixtureSite":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def https_port(self) -> int:
        return self.https.server_address[1]

    @property
    def http_port(self) -> int:
        return self.http.server_address[1]

    @property
    def https_url(self) -> str:
        return f"https://127.0.0.1:{self.https_port}/"


def main() -> None:
    parser = argparse.ArgumentParser(description="CheckMyWeb local test site")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="weak")
    parser.add_argument("--https-port", type=int, default=8443)
    parser.add_argument("--http-port", type=int, default=8080)
    args = parser.parse_args()
    site = FixtureSite(args.profile, https_port=args.https_port, http_port=args.http_port).start()
    print(f"{args.profile} profile: {site.https_url}  (HTTP {site.http_port})")
    print(f"scan: python -m checkmyweb {site.https_url} --http-port {site.http_port} --ca-file {CA_FILE}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        site.stop()


if __name__ == "__main__":
    main()

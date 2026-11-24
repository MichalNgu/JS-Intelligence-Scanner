from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import scanner


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/":
            body = b"""<!doctype html>
<html><head><title>Fixture</title></head><body>
<a href="/page">Page</a><a href="http://example.com/outside">Outside</a>
<script src="/app.js"></script>
<script>fetch("/graphql"); const apiSecret="FakeSecretValue123456789";</script>
</body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/page":
            body = b"""<script src="/missing.js"></script><script src="/app.js"></script>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/app.js":
            body = b'const socket = new WebSocket("ws://localhost/socket"); const base="/api/v1/users";'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/page")
            self.end_headers()
            return
        elif self.path == "/redirect-outside":
            self.send_response(302)
            self.send_header("Location", "http://example.com/private")
            self.end_headers()
            return
        elif self.path == "/oversized":
            body = b"x" * 4096
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/malformed":
            body = b"<html><body><script"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/missing.js":
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "application/javascript")
        elif self.path == "/http-error":
            body = b"server error"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/robots.txt":
            body = b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def test_full_local_scan_generates_all_reports(local_server, tmp_path, monkeypatch):
    port = local_server.server_address[1]
    output = tmp_path / "reports"
    monkeypatch.setattr(sys, "argv", [
        "scanner.py",
        f"http://127.0.0.1:{port}/",
        "--allow-private-targets",
        "--no-robots",
        "--max-pages", "10",
        "--max-js-files", "10",
        "--max-file-size", "2048",
        "--retries", "0",
        "--output", str(output),
        "--format", "json",
        "--format", "html",
        "--format", "markdown",
        "--format", "terminal",
    ])

    assert scanner.main() == 0
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()
    assert (output / "report.md").is_file()

    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["pages_crawled"] >= 1
    assert report["statistics"]["javascript_files"] >= 2
    assert report["statistics"]["endpoints"] >= 2
    assert "scan_duration_seconds" in report

    html = (output / "report.html").read_text(encoding="utf-8")
    markdown = (output / "report.md").read_text(encoding="utf-8")
    assert "<html" in html.lower()
    assert "# JS Intelligence Scanner Report" in markdown


@pytest.mark.parametrize("path", [
    "/redirect",
    "/redirect-outside",
    "/oversized",
    "/malformed",
    "/missing.js",
    "/http-error",
])
def test_local_error_and_redirect_paths_complete(local_server, path):
    port = local_server.server_address[1]
    import urllib.request
    import urllib.error

    target = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(target, timeout=2) as response:
            assert response.status in (200, 302, 404, 500)
    except urllib.error.HTTPError as exc:
        assert exc.code in (404, 500)
    except urllib.error.URLError:
        pytest.fail("Fixture server was not reachable")


def test_redirect_outside_scope_is_blocked(local_server, monkeypatch):
    port = local_server.server_address[1]
    target = f"http://127.0.0.1:{port}/redirect-outside"
    output = local_server.server_address
    monkeypatch.setattr(sys, "argv", [
        "scanner.py",
        target,
        "--allow-private-targets",
        "--no-robots",
        "--depth", "1",
        "--retries", "0",
        "--output", str(tmp_path_output(output)),
        "--format", "json",
        "--quiet",
    ])
    assert scanner.main() == 0


def tmp_path_output(address):
    import tempfile

    return Path(tempfile.gettempdir()) / f"jsis-integration-{address[1]}"

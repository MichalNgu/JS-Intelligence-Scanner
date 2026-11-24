from __future__ import annotations

import json
import subprocess
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
        self.server.requests_seen.append((self.path, self.headers.get("User-Agent")))
        if self.path == "/entry-redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
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
        elif self.path == "/redirect-outside":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://localhost:{self.server.server_port}/outside",
            )
            self.end_headers()
            return
        elif self.path == "/oversized":
            body = b"x" * 4096
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/stream-oversized":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"x" * 4096)
            return
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
    server.requests_seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def _run_cli(monkeypatch, args: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["scanner.py", *args])
    return scanner.main()


def _report_directory(output: Path) -> Path:
    target_directories = list((output / "127.0.0.1").iterdir())
    assert len(target_directories) == 1
    return target_directories[0]


def test_full_local_scan_generates_all_reports(local_server, tmp_path, monkeypatch, capsys):
    port = local_server.server_address[1]
    output = tmp_path / "reports"

    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}/entry-redirect",
        "--allow-private-targets",
        "--no-robots",
        "--max-pages", "10",
        "--max-js-files", "10",
        "--max-file-size", "2048",
        "--retries", "0",
        "--delay", "0",
        "--output", str(output),
        "--format", "json",
        "--format", "html",
        "--format", "markdown",
        "--format", "terminal",
    ]) == 0
    assert "JS INTELLIGENCE SCANNER" in capsys.readouterr().out

    report_directory = _report_directory(output)
    assert (report_directory / "report.json").is_file()
    assert (report_directory / "index.html").is_file()
    assert (report_directory / "style.css").is_file()
    assert (report_directory / "app.js").is_file()
    assert (report_directory / "report.md").is_file()

    report = json.loads((report_directory / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["pages_crawled"] == 2
    assert report["statistics"]["javascript_files"] >= 2
    assert report["statistics"]["endpoints"] >= 2
    assert report["statistics"]["http_requests"] == len(local_server.requests_seen)
    assert not any(
        resource["url"].endswith("/missing.js")
        for resource in report["javascript_resources"]
    )
    assert "scan_duration_seconds" in report
    assert any(path == "/missing.js" for path, _ in local_server.requests_seen)
    assert not any(path == "/outside" for path, _ in local_server.requests_seen)

    html = (report_directory / "index.html").read_text(encoding="utf-8")
    markdown = (report_directory / "report.md").read_text(encoding="utf-8")
    assert "<html" in html.lower()
    assert "# JS Intelligence Scanner Report" in markdown


def test_out_of_scope_redirect_is_rejected_before_request(local_server, tmp_path, monkeypatch):
    port = local_server.server_address[1]
    output = tmp_path / "redirect-report"
    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}/redirect-outside",
        "--allow-private-targets",
        "--no-robots",
        "--retries", "0",
        "--delay", "0",
        "--output", str(output),
        "--format", "json",
        "--quiet",
    ]) == 0

    report = json.loads((_report_directory(output) / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["pages_crawled"] == 0
    assert ("/redirect-outside", "JS-Intelligence-Scanner/1.0") in local_server.requests_seen
    assert not any(path == "/outside" for path, _ in local_server.requests_seen)


def test_private_target_is_blocked_without_explicit_opt_in(local_server, tmp_path, monkeypatch):
    port = local_server.server_address[1]
    output = tmp_path / "private-report"
    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}/",
        "--no-robots",
        "--retries", "0",
        "--delay", "0",
        "--output", str(output),
        "--format", "json",
        "--quiet",
    ]) == 0

    report = json.loads((_report_directory(output) / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["pages_crawled"] == 0
    assert local_server.requests_seen == []


def test_no_html_disables_dashboard_only(local_server, tmp_path, monkeypatch):
    port = local_server.server_address[1]
    output = tmp_path / "no-html-report"
    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}/",
        "--allow-private-targets",
        "--no-robots",
        "--no-html",
        "--retries", "0",
        "--delay", "0",
        "--output", str(output),
        "--quiet",
    ]) == 0

    report_directory = _report_directory(output)
    assert (report_directory / "report.json").is_file()
    assert not (report_directory / "index.html").exists()
    assert not (report_directory / "style.css").exists()
    assert not (report_directory / "app.js").exists()


@pytest.mark.parametrize("path", ["/oversized", "/stream-oversized"])
def test_oversized_response_is_rejected_by_cli(
    local_server, tmp_path, monkeypatch, path
):
    port = local_server.server_address[1]
    output = tmp_path / "oversized-report"
    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}{path}",
        "--allow-private-targets",
        "--no-robots",
        "--max-file-size", "1024",
        "--retries", "0",
        "--delay", "0",
        "--output", str(output),
        "--format", "json",
        "--quiet",
    ]) == 0

    report = json.loads((_report_directory(output) / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["pages_crawled"] == 0
    assert len(local_server.requests_seen) == 1


@pytest.mark.parametrize("path", ["/http-error", "/missing.js"])
def test_http_errors_and_missing_javascript_are_nonfatal(
    local_server, tmp_path, monkeypatch, path
):
    port = local_server.server_address[1]
    output = tmp_path / path.strip("/")
    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}{path}",
        "--allow-private-targets",
        "--no-robots",
        "--retries", "0",
        "--delay", "0",
        "--output", str(output),
        "--format", "json",
        "--quiet",
    ]) == 0

    report_directory = _report_directory(output)
    report = json.loads((report_directory / "report.json").read_text(encoding="utf-8"))
    assert report["statistics"]["javascript_files"] == 0


def test_config_values_and_cli_overrides(local_server, tmp_path, monkeypatch):
    port = local_server.server_address[1]
    config_path = tmp_path / "scanner-config.json"
    config_path.write_text(json.dumps({
        "depth": 3,
        "delay": 1,
        "max_pages": 10,
        "max_file_size": 2048,
        "max_js_files": 10,
        "concurrency": 4,
        "retries": 0,
        "user_agent": "configured-agent",
        "allow_private_targets": True,
        "respect_robots": True,
        "formats": ["json", "html"],
    }), encoding="utf-8")
    output = tmp_path / "configured-report"

    assert _run_cli(monkeypatch, [
        f"http://127.0.0.1:{port}/",
        "--config", str(config_path),
        "--no-robots",
        "--max-pages", "1",
        "--delay", "0",
        "--user-agent", "cli-agent",
        "--format", "markdown",
        "--output", str(output),
        "--quiet",
    ]) == 0

    report_directory = _report_directory(output)
    assert (report_directory / "report.json").is_file()
    assert (report_directory / "index.html").is_file()
    assert (report_directory / "style.css").is_file()
    assert (report_directory / "app.js").is_file()
    assert (report_directory / "report.md").is_file()
    assert local_server.requests_seen == [
        ("/", "cli-agent"),
        ("/app.js", "cli-agent"),
    ]


def test_invalid_configuration_returns_input_error(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "invalid-config.json"
    config_path.write_text('{"depth": "deep"}', encoding="utf-8")
    assert _run_cli(monkeypatch, [
        "https://example.com",
        "--config", str(config_path),
        "--quiet",
    ]) == 2
    assert "depth must be an integer" in capsys.readouterr().err


def test_cli_runs_as_a_process(local_server, tmp_path):
    port = local_server.server_address[1]
    scanner_path = Path(scanner.__file__).resolve()
    output = tmp_path / "process-report"
    result = subprocess.run(
        [
            sys.executable,
            str(scanner_path),
            f"http://127.0.0.1:{port}/",
            "--allow-private-targets",
            "--no-robots",
            "--retries", "0",
            "--delay", "0",
            "--output", str(output),
            "--format", "json",
            "--quiet",
        ],
        cwd=scanner_path.parent,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report_directory = _report_directory(output)
    assert json.loads((report_directory / "report.json").read_text(encoding="utf-8"))["scan_status"] == "completed"

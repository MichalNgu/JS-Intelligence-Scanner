import pytest

from core.scope import Scope, ScopeViolation
from core.config import ScannerConfig
from core.http import SafeHttpClient


def test_scope_rejects_out_of_scope_and_credentials():
    scope = Scope.from_target("https://example.com", [], allow_private_targets=False)
    assert scope.contains("https://example.com/api")
    assert not scope.contains("https://sub.example.com/api")
    assert not scope.contains("https://example.com.evil.test/api")
    with pytest.raises(ScopeViolation):
        scope.validate_url("https://user:pass@example.com/api")


def test_scope_rejects_private_ip_even_for_numeric_private_hostname():
    scope = Scope.from_target("http://127.0.0.1", [], allow_private_targets=False)
    assert not scope.contains("http://127.0.0.1/")


def test_private_lab_target_must_be_explicit(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    blocked = Scope.from_target("http://localhost", [], allow_private_targets=False)
    allowed = Scope.from_target("http://localhost", [], allow_private_targets=True)
    assert not blocked.contains("http://localhost/")
    assert allowed.contains("http://localhost/")


def test_http_client_rejects_oversized_content(monkeypatch):
    class Response:
        status_code = 200
        headers = {"Content-Length": "2048"}
        encoding = "utf-8"
        def close(self):
            pass
        def iter_content(self, chunk_size):
            yield b"x" * 2048

    config = ScannerConfig(
        target="https://example.com",
        max_file_size=1024,
        retries=0,
        allow_private_targets=False,
    )
    scope = Scope.from_target("https://example.com", [], allow_private_targets=False)
    monkeypatch.setattr(scope, "_validate_dns", lambda host: None)
    client = SafeHttpClient(config, scope)
    monkeypatch.setattr(client.session, "get", lambda *args, **kwargs: Response())
    with pytest.raises(ValueError):
        client.get("https://example.com/file.js", max_size=1024)

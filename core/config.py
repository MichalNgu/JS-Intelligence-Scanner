from dataclasses import dataclass
import json
import math
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class ScannerConfig:
    target: str
    depth: int = 2
    timeout: float = 10.0
    delay: float = 0.2
    max_pages: int = 100
    max_file_size: int = 5 * 1024 * 1024
    max_js_files: int = 100
    concurrency: int = 1
    retries: int = 2
    retry_backoff: float = 0.5
    user_agent: str = "JS-Intelligence-Scanner/1.0"
    verify_tls: bool = True
    respect_robots: bool = True
    allow_private_targets: bool = False
    formats: tuple[str, ...] = ("json",)
    verbose: bool = False
    started_at: str = ""
    ended_at: str = ""

    def __post_init__(self) -> None:
        integer_fields = ("depth", "max_pages", "max_file_size", "max_js_files", "concurrency", "retries")
        for name in integer_fields:
            if type(getattr(self, name)) is not int:
                raise ValueError(f"{name} must be an integer")
        numeric_fields = ("timeout", "delay", "retry_backoff")
        for name in numeric_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite number")
        for name in ("verify_tls", "respect_robots", "allow_private_targets", "verbose"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if not isinstance(self.target, str):
            raise ValueError("Target must be a string")
        if not isinstance(self.user_agent, str):
            raise ValueError("user_agent must be a string")
        if not isinstance(self.formats, (list, tuple)) or not self.formats:
            raise ValueError("formats must be a non-empty list")
        if any(not isinstance(value, str) or value not in {"json", "html", "markdown", "terminal"} for value in self.formats):
            raise ValueError("formats may contain only json, html, markdown, and terminal")
        self.formats = tuple(self.formats)

        parsed = urlparse(self.target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("Target must be an absolute HTTP or HTTPS URL")
        self.target = parsed.geturl()
        self.depth = max(0, min(self.depth, 10))
        self.timeout = max(1.0, min(self.timeout, 120.0))
        self.delay = max(0.0, self.delay)
        self.max_pages = max(1, min(self.max_pages, 1000))
        self.max_file_size = max(1024, min(self.max_file_size, 50 * 1024 * 1024))
        self.max_js_files = max(1, min(self.max_js_files, 1000))
        self.concurrency = max(1, min(self.concurrency, 32))
        self.retries = max(0, min(self.retries, 10))
        self.retry_backoff = max(0.0, min(self.retry_backoff, 30.0))

    def output_directory(self, value: str) -> Path:
        return Path(value).expanduser().resolve()

    @classmethod
    def from_json(cls, path: str, target: str) -> "ScannerConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Configuration file must contain a JSON object")
        allowed = {
            "depth", "timeout", "delay", "max_pages", "max_file_size",
            "max_js_files", "concurrency", "retries", "retry_backoff",
            "user_agent", "verify_tls", "respect_robots",
            "allow_private_targets", "formats", "verbose",
        }
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"Unknown configuration option(s): {', '.join(sorted(unknown))}")
        values = dict(data)
        return cls(target=target, **values)

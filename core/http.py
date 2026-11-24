from __future__ import annotations

import time
from typing import Iterator

import requests

from core.config import ScannerConfig
from core.scope import Scope


class SafeHttpClient:
    def __init__(self, config: ScannerConfig, scope: Scope) -> None:
        self.config = config
        self.scope = scope
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self.requests_count = 0

    def close(self) -> None:
        self.session.close()

    def get(
        self,
        url: str,
        *,
        base_url: str | None = None,
        stream: bool = True,
        max_size: int | None = None,
        allow_redirects: bool = False,
    ) -> requests.Response:
        validated = self.scope.validate_url(url, base_url)
        max_size = max_size or self.config.max_file_size
        last_error: requests.RequestException | None = None
        for attempt in range(self.config.retries + 1):
            try:
                response = self.session.get(
                    validated,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    stream=stream,
                    allow_redirects=allow_redirects,
                )
                self.requests_count += 1
                if allow_redirects:
                    raise requests.RequestException(
                        "Automatic redirects are disabled; handle Location manually"
                    )
                if response.status_code in {429, 500, 502, 503, 504} and attempt < self.config.retries:
                    response.close()
                    time.sleep(self.config.retry_backoff * (2 ** attempt))
                    continue
                if stream:
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            if int(content_length) > max_size:
                                response.close()
                                raise ValueError(
                                    f"Response exceeds configured maximum size of {max_size} bytes"
                                )
                        except ValueError:
                            raise
                return response
            except requests.RequestException as exc:
                last_error = exc
                if attempt < self.config.retries:
                    time.sleep(self.config.retry_backoff * (2 ** attempt))
        if last_error:
            raise last_error
        raise requests.RequestException("HTTP request failed")

    def read_limited(
        self,
        response: requests.Response,
        max_size: int,
    ) -> bytes:
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_size:
                    raise ValueError(
                        f"Response exceeds configured maximum size of {max_size} bytes"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            response.close()

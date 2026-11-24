from __future__ import annotations

import time

import requests

from core.config import ScannerConfig
from core.scope import Scope, ScopeViolation


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
        if not stream:
            raise ValueError("SafeHttpClient requires streamed responses")
        max_size = self.config.max_file_size if max_size is None else max_size
        last_error: requests.RequestException | None = None
        for attempt in range(self.config.retries + 1):
            try:
                response = self._get_response(url, base_url, allow_redirects)
                if response.status_code in {429, 500, 502, 503, 504} and attempt < self.config.retries:
                    response.close()
                    time.sleep(self.config.retry_backoff * (2 ** attempt))
                    continue
                if stream:
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            length = int(content_length)
                        except (TypeError, ValueError) as exc:
                            response.close()
                            raise ValueError("Response has an invalid Content-Length") from exc
                        if length < 0:
                            response.close()
                            raise ValueError("Response has an invalid Content-Length")
                        if length > max_size:
                            response.close()
                            raise ValueError(
                                f"Response exceeds configured maximum size of {max_size} bytes"
                            )
                return response
            except requests.RequestException as exc:
                last_error = exc
                if attempt < self.config.retries:
                    time.sleep(self.config.retry_backoff * (2 ** attempt))
        if last_error:
            raise last_error
        raise requests.RequestException("HTTP request failed")

    def _get_response(
        self,
        url: str,
        base_url: str | None,
        follow_redirects: bool,
    ) -> requests.Response:
        redirect_statuses = {301, 302, 303, 307, 308}
        current_url = self.scope.validate_url(url, base_url)
        visited: set[str] = set()

        for redirect_count in range(11):
            if current_url in visited:
                raise requests.TooManyRedirects("Redirect loop detected")
            visited.add(current_url)
            response = self.session.get(
                current_url,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
                stream=True,
                allow_redirects=False,
            )
            self.requests_count += 1
            if response.status_code not in redirect_statuses:
                return response

            location = response.headers.get("Location")
            if not location:
                return response
            try:
                next_url = self.scope.validate_url(location, current_url)
            except (ScopeViolation, ValueError):
                response.close()
                raise
            if not follow_redirects:
                return response
            response.close()
            current_url = next_url

        raise requests.TooManyRedirects("Maximum redirect count exceeded")

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

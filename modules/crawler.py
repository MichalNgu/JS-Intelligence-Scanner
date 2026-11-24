from __future__ import annotations

import time
import logging
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.config import ScannerConfig
from core.scope import Scope
from core.http import SafeHttpClient

LOGGER = logging.getLogger(__name__)


class Crawler:
    def __init__(
        self,
        config: ScannerConfig,
        scope: Scope,
        http_client: SafeHttpClient | None = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.http = http_client or SafeHttpClient(config, scope)
        self._owns_http = http_client is None
        self.visited: set[str] = set()
        self.pages: dict[str, str] = {}
        self.stats = {"pages_crawled": 0, "requests": 0}
        self._disallowed: set[str] = set()

    def _load_robots(self) -> None:
        if not self.config.respect_robots:
            return
        parsed = urlparse(self.config.target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            response = self.http.get(robots_url, base_url=self.config.target, stream=True, max_size=self.config.max_file_size)
            if response.status_code != 200:
                response.close()
                return
            try:
                robots = self.http.read_limited(response, self.config.max_file_size).decode(
                    response.encoding or "utf-8", errors="replace"
                )
            except (requests.RequestException, ValueError) as exc:
                LOGGER.warning("Could not read robots.txt: %s", exc)
                return
            for line in robots.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        self._disallowed.add(path)
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("Could not retrieve robots.txt: %s", exc)
            return

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def _robots_allow(self, url: str) -> bool:
        path = urlparse(url).path or "/"
        return not any(path.startswith(disallowed) for disallowed in self._disallowed)

    def crawl(self) -> dict[str, str]:
        self._load_robots()
        queue = deque([(self.config.target, 0)])
        while queue and len(self.visited) < self.config.max_pages:
            url, depth = queue.popleft()
            url = urldefrag(url)[0]
            if url in self.visited or depth > self.config.depth:
                continue
            if not self.scope.contains(url) or not self._robots_allow(url):
                continue

            self.visited.add(url)
            time.sleep(self.config.delay)
            try:
                response = self.http.get(
                    url,
                    base_url=self.config.target,
                    stream=True,
                    allow_redirects=True,
                )
            except (requests.RequestException, ValueError) as exc:
                LOGGER.warning("Request failed for %s: %s", url, exc)
                continue

            url = response.url
            if 300 <= response.status_code < 400:
                response.close()
                continue

            if response.status_code >= 400:
                LOGGER.warning("HTTP %s for %s", response.status_code, url)
                response.close()
                continue
            content_type = response.headers.get("Content-Type", "").lower()
            try:
                body = self.http.read_limited(response, self.config.max_file_size)
            except (requests.RequestException, ValueError) as exc:
                LOGGER.warning("Response from %s was rejected: %s", url, exc)
                continue
            encoding = response.encoding or "utf-8"
            text = body.decode(encoding, errors="replace")
            if "text/html" not in content_type and "<html" not in text[:1000].lower():
                continue

            self.pages[url] = text
            self.stats["pages_crawled"] += 1
            if depth >= self.config.depth:
                continue

            soup = BeautifulSoup(text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link["href"])
                if self.scope.contains(href):
                    queue.append((urldefrag(href)[0], depth + 1))
        return self.pages

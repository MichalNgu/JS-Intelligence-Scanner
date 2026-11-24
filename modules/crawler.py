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
    def __init__(self, config: ScannerConfig, scope: Scope) -> None:
        self.config = config
        self.scope = scope
        self.http = SafeHttpClient(config, scope)
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
        except requests.RequestException:
            return

    def close(self) -> None:
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
                response = self.http.get(url, base_url=self.config.target, stream=True)
            except (requests.RequestException, ValueError) as exc:
                LOGGER.warning("Request failed for %s: %s", url, exc)
                continue

            redirect_count = 0
            while response.status_code in (301, 302, 303, 307, 308) and redirect_count < 10:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    break
                redirect_count += 1
                try:
                    redirect_url = self.scope.validate_url(location, url)
                    if redirect_url == url:
                        break
                    url = redirect_url
                    if not self.scope.contains(url) or url in self.visited:
                        break
                    response = self.http.get(url, base_url=self.config.target, stream=True)
                except (requests.RequestException, ValueError) as exc:
                    LOGGER.warning("Redirect rejected or failed for %s: %s", url, exc)
                    break
            if response.status_code in (301, 302, 303, 307, 308):
                response.close()
                continue

            if response.status_code >= 400:
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

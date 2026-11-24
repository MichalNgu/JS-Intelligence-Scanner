from __future__ import annotations

import hashlib
import re
import time
from urllib.parse import urldefrag, urljoin

import requests
from bs4 import BeautifulSoup

from core.config import ScannerConfig
from core.models import JavaScriptResource
from core.scope import Scope
from core.http import SafeHttpClient


SCRIPT_HINT = re.compile(r"""(?:(?:src|href)\s*=\s*["']([^"']+)|["']([^"']+\.js(?:[^"'?#]*)?)["'])""", re.I)
IMPORT_HINT = re.compile(r"""(?:import\s+(?:[^"']*\s+from\s*)?|import\s*\(|require\s*\()\s*["']([^"']+)["']""", re.I)


class JavaScriptExtractor:
    def __init__(self, config: ScannerConfig, scope: Scope) -> None:
        self.config = config
        self.scope = scope
        self.http = SafeHttpClient(config, scope)
        self.resources: list[JavaScriptResource] = []
        self.seen: set[str] = set()
        self.hashes: dict[str, str] = {}

    def extract(self, pages: dict[str, str]) -> list[JavaScriptResource]:
        candidates: dict[str, str] = {}
        for page_url, html in pages.items():
            soup = BeautifulSoup(html, "html.parser")
            inline_index = 0
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    candidates[urljoin(page_url, src)] = page_url
                inline = script.string or script.get_text()
                if inline:
                    inline_index += 1
                    digest = hashlib.sha256(inline.encode("utf-8")).hexdigest()
                    duplicate_of = self.hashes.get(digest, "")
                    if not duplicate_of:
                        self.hashes[digest] = f"{page_url}#inline-{inline_index}"
                    self.resources.append(JavaScriptResource(
                        url=f"{page_url}#inline-{inline_index}",
                        source_url=page_url,
                        status=200,
                        content_type="application/javascript",
                        size=len(inline.encode("utf-8")),
                        sha256=digest,
                        content=inline,
                        duplicate_of=duplicate_of,
                        inline=True,
                    ))
                    for match in re.finditer(r"""(?:from\s+|import\s*\(|import\s*)["']([^"']+)["']""", inline):
                        candidates[urljoin(page_url, match.group(1))] = page_url
            for match in SCRIPT_HINT.finditer(html):
                candidate = match.group(1) or match.group(2)
                if candidate:
                    absolute = urljoin(page_url, candidate)
                    if ".js" in absolute.lower() or ".mjs" in absolute.lower():
                        candidates[absolute] = page_url
            for match in IMPORT_HINT.finditer(html):
                candidates[urljoin(page_url, match.group(1))] = page_url
            for match in re.finditer(r"""(?:import|require)\s*(?:\(\s*)?["']([^"']+\.(?:js|mjs|cjs|jsx|ts|tsx))["']""", html, re.I):
                candidates[urljoin(page_url, match.group(1))] = page_url
            for match in re.finditer(r"""(?://# sourceMappingURL=|/\*# sourceMappingURL=)([^ \n*]+)""", html, re.I):
                candidates[urljoin(page_url, match.group(1))] = page_url

        queue = list(candidates.items())
        while queue:
            candidate, source_url = queue.pop(0)
            absolute = urldefrag(candidate)[0]
            if absolute in self.seen or not self.scope.contains(absolute):
                continue
            self.seen.add(absolute)
            if len(self.resources) >= self.config.max_js_files:
                break
            if not re.search(r"\.(?:js|mjs|cjs|jsx|ts|tsx|map)(?:$|[?#])", absolute, re.I):
                continue
            time.sleep(self.config.delay)
            try:
                response = self.http.get(absolute, base_url=source_url, stream=True)
                redirect_count = 0
                while response.status_code in (301, 302, 303, 307, 308) and redirect_count < 10:
                    location = response.headers.get("Location")
                    response.close()
                    if not location:
                        break
                    try:
                        absolute = self.scope.validate_url(location, absolute)
                        if absolute in self.seen:
                            break
                        response = self.http.get(absolute, base_url=source_url, stream=True)
                        redirect_count += 1
                    except (requests.RequestException, ValueError):
                        break
            except (requests.RequestException, ValueError):
                continue
            if response.status_code >= 400:
                response.close()
                continue
            try:
                content = self.http.read_limited(response, self.config.max_file_size)
            except (requests.RequestException, ValueError):
                continue
            text = content.decode("utf-8", errors="replace")
            digest = hashlib.sha256(content).hexdigest()
            duplicate_of = self.hashes.get(digest, "")
            if not duplicate_of:
                self.hashes[digest] = absolute
            self.resources.append(JavaScriptResource(
                url=absolute,
                source_url=source_url,
                status=response.status_code,
                content_type=response.headers.get("Content-Type", ""),
                size=len(content),
                sha256=digest,
                content=text,
                duplicate_of=duplicate_of,
            ))
            for match in re.finditer(
                r"""(?:import\s+(?:[^"'`]*?\s+from\s*)?|import\s*\(\s*|require\s*\(\s*|from\s*)["'`]([^"'`]+)["'`]""",
                text,
                re.I,
            ):
                referenced = urljoin(absolute, match.group(1))
                if referenced not in self.seen:
                    queue.append((referenced, absolute))
            for match in re.finditer(r"""(?:sourceMappingURL=)([^\s*]+)""", text, re.I):
                referenced = urljoin(absolute, match.group(1))
                if referenced not in self.seen:
                    queue.append((referenced, absolute))
        return self.resources

    def close(self) -> None:
        self.http.close()

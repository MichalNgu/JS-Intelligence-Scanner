from __future__ import annotations

import re
from urllib.parse import urlparse

from core.models import Finding, JavaScriptResource


ENDPOINT_PATTERNS = [
    re.compile(r"""["'`]((?:https?:|wss?:)?//[^"'`\s]+)["'`]""", re.I),
    re.compile(r"""["'`](/[^"'`\s*]{1,240})["'`]"""),
]
DYNAMIC = re.compile(r"[\{\}\[\]]")


class EndpointFinder:
    def analyze(self, resources: list[JavaScriptResource]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for resource in resources:
            if resource.duplicate_of:
                continue
            for match in re.finditer(
                r"""(?is)(?:fetch\s*\(\s*|axios(?:\.[a-z]+)?\s*\(\s*|axios\.(?:get|post|put|patch|delete)\s*\(\s*|XMLHttpRequest[\s\S]{0,200}?\.open\s*\([^,]+,\s*|new\s+WebSocket\s*\(\s*)["'`]([^"'`]+)["'`]""",
                resource.content,
            ):
                self._add(match, resource, findings, seen)
            for pattern in ENDPOINT_PATTERNS:
                for match in pattern.finditer(resource.content):
                    self._add(match, resource, findings, seen)
            concatenation = re.compile(
                r"""(?is)(["'`])((?:/{1,2}|api|v\d)[^"'`]*?)\1\s*(?:\+\s*(?:[A-Za-z_$][\w$]*|\[[^\]]+\]|["'`][^"'`]*["'`]))+"""
            )
            for match in concatenation.finditer(resource.content):
                value = match.group(2)
                if value:
                    self._add(match, resource, findings, seen, group=2)
            template = re.compile(r"""["'`]((?:https?:|wss?:)?/[^\n"'`]*\$\{[^"'`]+\})["'`]""", re.I)
            for match in template.finditer(resource.content):
                self._add(match, resource, findings, seen)
        return findings

    def _add(
        self,
        match: re.Match,
        resource: JavaScriptResource,
        findings: list[Finding],
        seen: set[tuple[str, str]],
        group: int = 1,
    ) -> None:
        value = match.group(group).rstrip(".,);")
        if len(value) < 2 or value.startswith("//cdn"):
            return
        key = (value, resource.url)
        if key in seen:
            return
        seen.add(key)
        category = self._category(value)
        dynamic = bool(DYNAMIC.search(value) or re.search(r"\b(?:baseurl|base_url|api_url)\b", value, re.I))
        risk = "medium" if category in {"Administrative", "Authentication"} else "low"
        confidence = "low" if dynamic else "medium"
        position = match.start(group)
        line = resource.content.count("\n", 0, position) + 1
        findings.append(Finding(
            type="api_endpoint",
            value=value,
            source=resource.url,
            source_url=resource.url,
            category=category,
            risk=risk,
            confidence=confidence,
            context=self._context(resource.content, position),
            reason=f"{category} route or URL reference discovered in JavaScript.",
            evidence=value,
            line_number=line,
        ))

    def _category(self, value: str) -> str:
        lower = value.lower()
        if any(word in lower for word in ("admin", "dashboard", "internal")):
            return "Administrative"
        if any(word in lower for word in ("auth", "login", "oauth", "token", "session", "password")):
            return "Authentication"
        if "/graphql" in lower:
            return "GraphQL"
        if lower.startswith(("ws://", "wss://")):
            return "WebSocket"
        if any(word in lower for word in ("upload", "file", "download")):
            return "File Operation"
        if any(word in lower for word in ("user", "account", "profile")):
            return "User Management"
        if lower.startswith(("http://", "https://")):
            return "Absolute URL"
        return "API Route"

    def _context(self, text: str, position: int) -> str:
        start = max(0, position - 70)
        end = min(len(text), position + 150)
        return " ".join(text[start:end].split())[:220]

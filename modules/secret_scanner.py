from __future__ import annotations

import math
import re
from collections import Counter

from core.models import Finding, JavaScriptResource


PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35,39}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "stripe_key": re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "database_url": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\\s\"']{8,}\b", re.I),
    "oauth_client_secret": re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
}
ASSIGNMENT = re.compile(
    r"""(?i)([A-Za-z_$][\w$]*(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|auth)[A-Za-z_$0-9]*)"""
    r"""\s*(?:[:=]\s*["']([^"'\n]{8,200})["']|["']?\s*[:=]\s*([^,\n;}]{8,200}))"""
)
PUBLIC_NAMES = ("public_key", "publishable_key", "api_key_id", "client_id")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class SecretScanner:
    def __init__(self, extra_patterns: dict[str, str] | None = None) -> None:
        self.extra_patterns = {
            name: re.compile(pattern, re.I)
            for name, pattern in (extra_patterns or {}).items()
        }

    def analyze(self, resources: list[JavaScriptResource]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for resource in resources:
            if resource.duplicate_of:
                continue
            for kind, pattern in PATTERNS.items():
                for match in pattern.finditer(resource.content):
                    value = match.group(0)
                    key = (kind, value, resource.url)
                    if key in seen:
                        continue
                    seen.add(key)
                    line = resource.content.count("\n", 0, match.start()) + 1
                    findings.append(Finding(
                        type="confirmed_secret",
                        value=value,
                        source=resource.url,
                        source_url=resource.url,
                        category="Sensitive Credential",
                        risk="high",
                        confidence="high",
                        context=self._context(resource.content, match.start()),
                        reason=f"Credential-like {kind} format detected.",
                        metadata={"detector": kind},
                        evidence=match.group(0),
                        line_number=line,
                    ))
            for kind, pattern in self.extra_patterns.items():
                for match in pattern.finditer(resource.content):
                    value = match.group(0)
                    key = (kind, value, resource.url)
                    if key not in seen:
                        seen.add(key)
                        line = resource.content.count("\n", 0, match.start()) + 1
                        findings.append(Finding(
                            type="confirmed_secret", value=value,
                            source=resource.url, source_url=resource.url,
                            category="Sensitive Credential", risk="high",
                            confidence="medium", context=self._context(resource.content, match.start()),
                            reason=f"Custom credential pattern '{kind}' detected.",
                            metadata={"detector": kind}, evidence=value, line_number=line,
                        ))
            for match in ASSIGNMENT.finditer(resource.content):
                name = match.group(1)
                value = match.group(2) or match.group(3) or ""
                value = value.strip().strip("\"'")
                if not value or any(word in name.lower() for word in PUBLIC_NAMES):
                    continue
                key = ("assignment", value, resource.url)
                if key in seen:
                    continue
                seen.add(key)
                score = entropy(value)
                line = resource.content.count("\n", 0, match.start()) + 1
                risk = "high" if score >= 3.5 and len(value) >= 16 else "medium"
                confidence = "medium" if score >= 3.5 else "low"
                findings.append(Finding(
                    type="potential_secret",
                    value=value,
                    source=resource.url,
                    source_url=resource.url,
                    category="Sensitive Configuration",
                    risk=risk,
                    confidence=confidence,
                    context=self._context(resource.content, match.start()),
                    reason=f"Sensitive variable name '{name}' assigned a high-entropy-like value.",
                    metadata={"variable": name, "entropy": f"{score:.2f}"},
                    evidence=f"{name}={value}",
                    line_number=line,
                ))
        return findings

    def _context(self, text: str, position: int) -> str:
        start = max(0, position - 70)
        end = min(len(text), position + 150)
        return " ".join(text[start:end].split())[:220]

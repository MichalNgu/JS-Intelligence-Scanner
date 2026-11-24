from __future__ import annotations

import ipaddress
import re

from core.models import Finding, JavaScriptResource


PRIVATE_IP = re.compile(
    r"(?<![\d.])(?:"
    r"10(?:\.\d{1,3}){3}|"
    r"127(?:\.\d{1,3}){3}|"
    r"169\.254(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|"
    r"192\.168(?:\.\d{1,3}){2}"
    r")(?![\d.])"
)
URL = re.compile(r"""(?<!["'])((?:https?|wss?)://[A-Za-z0-9._~-]+(?::[0-9]+)?(?:/[^\s"'<>]*)?)""", re.I)
HOSTNAME = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:local|internal|localhost|dev|test|stage|staging)\b", re.I)
ENV_INDICATOR = re.compile(r"\b(?:development|dev[_-]?(?:api|host|url|server)|staging|stage|test(?:ing)?|debug(?:[_-]mode)?|localhost)\b", re.I)
EXTERNAL_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:com|net|org|io|cloud|dev|app|ai)\b", re.I)
CLOUD_REFERENCE = re.compile(r"\b(?:s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|amazonaws\.com|azurewebsites\.net|firebaseio\.com)\b", re.I)


class InfrastructureAnalyzer:
    def analyze(self, resources: list[JavaScriptResource]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for resource in resources:
            if resource.duplicate_of:
                continue
            checks = (
                ("private_ip", PRIVATE_IP, "Private IPv4 Address", "medium", "high"),
                ("internal_hostname", HOSTNAME, "Internal Hostname", "medium", "medium"),
                ("network_url", URL, "Network Service Reference", "low", "medium"),
                ("environment_indicator", ENV_INDICATOR, "Environment Configuration", "low", "medium"),
                ("external_api_domain", EXTERNAL_DOMAIN, "External Domain Reference", "low", "low"),
                ("cloud_infrastructure", CLOUD_REFERENCE, "Cloud Infrastructure Reference", "low", "medium"),
            )
            for type_name, pattern, category, risk, confidence in checks:
                for match in pattern.finditer(resource.content):
                    value = match.group(1) if match.lastindex else match.group(0)
                    value = value.rstrip(".,);")
                    if type_name == "private_ip":
                        try:
                            ipaddress.ip_address(value)
                        except ValueError:
                            continue
                    key = (type_name, value, resource.url)
                    if key in seen:
                        continue
                    seen.add(key)
                    line = resource.content.count("\n", 0, match.start()) + 1
                    findings.append(Finding(
                        type=type_name,
                        value=value,
                        source=resource.url,
                        source_url=resource.url,
                        category=category,
                        risk=risk,
                        confidence=confidence,
                        context=self._context(resource.content, match.start()),
                        reason=f"{category} reference discovered.",
                        evidence=value,
                        line_number=line,
                    ))
        return findings

    def _context(self, text: str, position: int) -> str:
        start = max(0, position - 70)
        end = min(len(text), position + 150)
        return " ".join(text[start:end].split())[:220]

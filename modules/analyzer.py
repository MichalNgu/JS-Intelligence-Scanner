from __future__ import annotations

from core.models import Finding


class Analyzer:
    def analyze(self, findings: list[Finding]) -> list[Finding]:
        unique: dict[tuple[str, str, str], Finding] = {}
        for finding in findings:
            key = (finding.type, finding.value, finding.source)
            existing = unique.get(key)
            if existing:
                if self._rank(finding.risk) > self._rank(existing.risk):
                    existing.risk = finding.risk
                if self._rank(finding.confidence) > self._rank(existing.confidence):
                    existing.confidence = finding.confidence
                continue
            finding = self._correlate(finding, findings)
            unique[key] = finding
        return sorted(unique.values(), key=lambda item: (
            -self._rank(item.risk), -self._rank(item.confidence), item.type, item.value
        ))

    def _correlate(self, finding: Finding, all_findings: list[Finding]) -> Finding:
        related = [
            item for item in all_findings
            if item is not finding and item.source == finding.source
            and item.type in {"confirmed_secret", "potential_secret", "internal_hostname", "private_ip"}
        ]
        if finding.type == "api_endpoint" and finding.category == "Administrative" and related:
            finding.risk = "high"
            finding.confidence = "medium" if finding.confidence == "low" else finding.confidence
            finding.reason += " Related sensitive or internal infrastructure findings increase the review priority."
        if finding.type in {"confirmed_secret", "potential_secret"}:
            finding.category = "Sensitive Configuration"
        return finding

    def _rank(self, value: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value.lower(), 0)

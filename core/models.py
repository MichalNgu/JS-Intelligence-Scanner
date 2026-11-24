from dataclasses import asdict, dataclass, field
from typing import Dict, Optional


@dataclass
class JavaScriptResource:
    url: str
    source_url: str
    status: Optional[int] = None
    content_type: str = ""
    size: int = 0
    sha256: str = ""
    content: str = ""
    duplicate_of: str = ""
    inline: bool = False
    line_number: int = 0


@dataclass
class Finding:
    type: str
    value: str
    source: str
    source_url: str = ""
    category: str = "Reconnaissance"
    risk: str = "info"
    confidence: str = "low"
    context: str = ""
    reason: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    line_number: int = 0
    evidence: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["value"] = redact(self.value, self.type)
        if self.type in {"potential_secret", "confirmed_secret"}:
            data["context"] = redact(self.context, self.type)
            data["evidence"] = redact(self.evidence, self.type)
        return data


def redact(value: str, finding_type: str) -> str:
    if finding_type not in {"potential_secret", "confirmed_secret"}:
        return value
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(20, len(value) - 8) + value[-4:]

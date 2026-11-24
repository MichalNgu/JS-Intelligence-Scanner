from core.models import Finding
from modules.analyzer import Analyzer


def test_admin_endpoint_correlates_internal_findings():
    findings = [
        Finding(type="api_endpoint", value="/api/admin", source="admin.js", category="Administrative", risk="medium", confidence="medium"),
        Finding(type="potential_secret", value="redacted", source="admin.js", category="Sensitive Configuration", risk="high", confidence="medium"),
    ]
    analyzed = Analyzer().analyze(findings)
    admin = next(item for item in analyzed if item.type == "api_endpoint")
    assert admin.risk == "high"
    assert "Related" in admin.reason

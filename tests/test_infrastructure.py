from core.models import JavaScriptResource
from modules.infrastructure import InfrastructureAnalyzer


def test_detects_private_ip_internal_hostname_and_environment():
    content = "const api='https://api-dev.example.internal'; const debug=true; const ip='192.168.1.15';"
    resource = JavaScriptResource(
        url="https://example.com/app.js",
        source_url="https://example.com/",
        content=content,
    )
    findings = InfrastructureAnalyzer().analyze([resource])
    values = {finding.value for finding in findings}
    assert "192.168.1.15" in values
    assert "api-dev.example.internal" in values
    assert "debug" in values

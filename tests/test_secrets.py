from core.models import JavaScriptResource
from modules.secret_scanner import SecretScanner


def test_detects_confirmed_and_contextual_credentials():
    content = '''
    const googleKey = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXY123456789012";
    const apiSecret = "ThisIsAReallyLongRandomLookingSecretValue123!";
    const public_key = "not-a-secret";
    '''
    resource = JavaScriptResource(
        url="https://example.com/app.js",
        source_url="https://example.com/",
        content=content,
    )
    findings = SecretScanner().analyze([resource])
    assert any(finding.type == "confirmed_secret" for finding in findings)
    assert any(finding.metadata.get("variable") == "apiSecret" for finding in findings)
    assert all(finding.metadata.get("variable") != "public_key" for finding in findings)

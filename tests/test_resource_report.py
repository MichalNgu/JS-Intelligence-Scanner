import tempfile
from pathlib import Path

from core.models import Finding, JavaScriptResource
from core.reporter import Reporter
from modules.js_extractor import JavaScriptExtractor
from core.config import ScannerConfig
from core.scope import Scope


def test_inline_script_discovery():
    config = ScannerConfig(target="https://example.com", allow_private_targets=False)
    scope = Scope.from_target("https://example.com", [], allow_private_targets=False)
    extractor = JavaScriptExtractor(config, scope)
    resources = extractor.extract({
        "https://example.com/": '<script>const token="A"*16</script>'
    })
    inline = [item for item in resources if item.inline]
    assert inline
    assert inline[0].url.startswith("https://example.com/#inline-")
    assert "const token" in inline[0].content
    extractor.close()


def test_json_html_markdown_redact_and_write():
    with tempfile.TemporaryDirectory() as directory:
        reporter = Reporter("https://example.com", Path(directory))
        findings = [Finding(
            type="potential_secret",
            value="SuperSecretValue123",
            source="https://example.com/app.js",
            source_url="https://example.com/app.js",
            category="Sensitive Configuration",
            risk="medium",
            confidence="medium",
            context="password=SuperSecretValue123",
            evidence="password=SuperSecretValue123",
            line_number=12,
        )]
        resources = [JavaScriptResource(
            url="https://example.com/app.js",
            source_url="https://example.com/",
            content="",
        )]
        json_path = reporter.write_json(findings, resources, {"pages_crawled": 1, "duration_seconds": 0.25})
        html_path = reporter.write_html(findings, resources, {"pages_crawled": 1, "duration_seconds": 0.25})
        md_path = reporter.write_markdown(findings, resources, {"pages_crawled": 1, "duration_seconds": 0.25})
        assert json_path.exists() and html_path.exists() and md_path.exists()
        json_text = json_path.read_text(encoding="utf-8")
        assert "SuperSecretValue123" not in json_text

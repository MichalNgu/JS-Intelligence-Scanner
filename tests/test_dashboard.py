from __future__ import annotations

import json
from pathlib import Path

from core.dashboard import HtmlDashboardGenerator
from core.models import Finding, JavaScriptResource
from core.reporter import Reporter


def test_target_directories_are_sanitized_and_scan_directories_are_unique(tmp_path):
    root = tmp_path / "results"
    target = "http://192.168.1.100:8080/"
    timestamp = "2026-11-24_20-30-00"

    first = Reporter.create_scan_directory(root, target, timestamp)
    sentinel = first / "previous-scan.txt"
    sentinel.write_text("preserved", encoding="utf-8")
    second = Reporter.create_scan_directory(root, target, timestamp)

    assert first == root.resolve() / "192.168.1.100" / timestamp
    assert second != first
    assert second.name == f"{timestamp}_01"
    assert sentinel.read_text(encoding="utf-8") == "preserved"


def test_target_names_handle_special_and_traversal_shaped_hostnames(tmp_path):
    assert Reporter.target_directory_name("https://exämple.com") == "xn--exmple-cua.com"
    assert Reporter.target_directory_name("http://CON/") == "_con"
    assert Reporter.target_directory_name("http://CON.example/") == "_con.example"
    assert Reporter.target_directory_name("http://[2001:db8::1]/") == "ipv6_2001_db8__1"
    assert len(Reporter.target_directory_name(f"http://{'a' * 300}.example/")) <= 100

    output = Reporter.create_scan_directory(
        tmp_path / "results",
        "http://../../outside",
        "2026-11-24_20-30-00",
    )
    assert output.parent == (tmp_path / "results" / "target").resolve()
    assert output.resolve().is_relative_to((tmp_path / "results").resolve())


def test_dashboard_assets_are_utf8_local_and_separate_from_report_data(tmp_path):
    report_dir = Reporter.create_scan_directory(
        tmp_path / "results",
        "https://example.com",
        "2026-11-24_20-30-00",
    )
    assets = HtmlDashboardGenerator().write_assets(report_dir)

    assert {path.name for path in assets} == {"index.html", "style.css", "app.js"}
    for path in assets:
        path.read_text(encoding="utf-8")

    page = (report_dir / "index.html").read_text(encoding="utf-8")
    script = (report_dir / "app.js").read_text(encoding="utf-8")
    style = (report_dir / "style.css").read_text(encoding="utf-8")
    assert 'href="style.css"' in page
    assert 'src="app.js"' in page
    assert "https://" not in page
    assert "http://" not in page
    assert "fetch(\"./report.json\"" in script
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "url(http" not in style.lower()


def test_json_schema_stays_compatible_and_dashboard_never_embeds_finding_data(tmp_path):
    report_dir = Reporter.create_scan_directory(
        tmp_path / "results",
        "https://example.com",
        "2026-11-24_20-30-00",
    )
    secret_markup = '<img src=x onerror="window.pwned=1"><script>window.pwned=2</script>'
    finding = Finding(
        type="api_endpoint",
        value=secret_markup,
        source="</td><script>window.pwned=3</script>",
        category="Reconnaissance",
        risk="low",
        confidence="medium",
        reason=secret_markup,
        context=secret_markup,
        metadata={"note": secret_markup},
    )
    resource = JavaScriptResource(
        url="https://example.com/app.js",
        source_url="https://example.com/",
        status=200,
        size=12,
        sha256="abc123",
    )
    report_path = Reporter("https://example.com", report_dir).write_json(
        [finding],
        [resource],
        {"duration_seconds": 1.5, "requests": 3},
    )
    HtmlDashboardGenerator().write_assets(report_dir)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert {
        "target", "scan_status", "generated_at", "scan_duration_seconds",
        "manual_verification_steps", "statistics", "javascript_resources", "findings",
    } <= report.keys()
    assert report["findings"][0]["value"] == secret_markup
    assert report["javascript_resources"][0]["sha256"] == "abc123"
    assert report["statistics"]["http_requests"] == 3
    for asset in (report_dir / "index.html", report_dir / "style.css", report_dir / "app.js"):
        assert secret_markup not in asset.read_text(encoding="utf-8")
    assert "document.createElement" in (report_dir / "app.js").read_text(encoding="utf-8")


def test_dashboard_frontend_handles_optional_and_empty_report_fields(tmp_path):
    report_dir = Reporter.create_scan_directory(
        tmp_path / "results",
        "https://example.com",
        "2026-11-24_20-30-00",
    )
    HtmlDashboardGenerator().write_assets(report_dir)
    script = (report_dir / "app.js").read_text(encoding="utf-8")

    assert "Array.isArray(report.findings)" in script
    assert "Array.isArray(report.javascript_resources)" in script
    assert "No findings in this report." in script
    assert "No JavaScript resources in this report." in script
    assert "Could not read report JSON:" in script
    assert 'window.location.protocol === "file:"' in script
    assert 'for (const step of safeSteps)' in script

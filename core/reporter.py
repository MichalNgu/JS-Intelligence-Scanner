from __future__ import annotations

import json
import html
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from core.models import Finding, JavaScriptResource


class Reporter:
    def __init__(self, target: str, output_dir: Path) -> None:
        self.target = target
        self.output_dir = output_dir

    @staticmethod
    def target_directory_name(target: str) -> str:
        hostname = urlsplit(target).hostname
        if not hostname:
            raise ValueError("Target URL must contain a hostname")
        try:
            parsed_ip = ipaddress.ip_address(hostname)
            if isinstance(parsed_ip, ipaddress.IPv6Address):
                hostname = f"ipv6_{parsed_ip.compressed.replace(':', '_')}"
            else:
                hostname = str(parsed_ip)
        except ValueError:
            try:
                hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                pass

        name = re.sub(r"[^A-Za-z0-9._-]+", "_", hostname).strip(" ._-")
        if not name or name in {".", ".."}:
            name = "target"
        reserved_names = {
            "CON", "PRN", "AUX", "NUL",
            *(f"COM{index}" for index in range(1, 10)),
            *(f"LPT{index}" for index in range(1, 10)),
        }
        if name.split(".", 1)[0].upper() in reserved_names:
            name = f"_{name}"
        if len(name) > 100:
            suffix = hashlib.sha256(hostname.encode("utf-8", errors="replace")).hexdigest()[:10]
            name = f"{name[:89]}_{suffix}"
        return name

    @classmethod
    def create_scan_directory(
        cls,
        output_root: Path,
        target: str,
        timestamp: str | None = None,
    ) -> Path:
        root = Path(output_root).expanduser().resolve()
        target_name = cls.target_directory_name(target)
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", timestamp):
            raise ValueError("Invalid report timestamp")

        target_dir = root / target_name
        target_dir.mkdir(parents=True, exist_ok=True)
        resolved_target_dir = target_dir.resolve()
        try:
            resolved_target_dir.relative_to(root)
        except ValueError as exc:
            raise ValueError("Target report directory escapes the output root") from exc

        for suffix in range(10000):
            directory_name = timestamp if suffix == 0 else f"{timestamp}_{suffix:02d}"
            report_dir = resolved_target_dir / directory_name
            try:
                report_dir.mkdir()
                return report_dir
            except FileExistsError:
                continue
        raise FileExistsError(f"Could not allocate a unique report directory under {resolved_target_dir}")

    def write_json(
        self,
        findings: list[Finding],
        resources: list[JavaScriptResource],
        crawl_stats: dict,
    ) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.output_dir / "report.json"
        duration = crawl_stats.get("duration_seconds", 0)
        report = {
            "target": self.target,
            "scan_status": "completed",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": duration,
            "manual_verification_steps": [
                "Verify the authorization scope before testing any discovered endpoint.",
                "Confirm whether credential-like values are active without authenticating or using the credential.",
                "Manually review infrastructure and administrative references for false positives.",
            ],
            "statistics": {
                "javascript_files": len(resources),
                "javascript_downloaded": sum(1 for item in resources if item.status),
                "unique_javascript_files": sum(1 for item in resources if not item.duplicate_of),
                "endpoints": sum(1 for item in findings if item.type == "api_endpoint"),
                "potential_secrets": sum(1 for item in findings if item.type in {"potential_secret", "confirmed_secret"}),
                "confirmed_secret_candidates": sum(1 for item in findings if item.type == "confirmed_secret"),
                "internal_hosts": sum(1 for item in findings if item.type == "internal_hostname"),
                "private_ip_references": sum(1 for item in findings if item.type == "private_ip"),
                "pages_crawled": crawl_stats.get("pages_crawled", 0),
                "http_requests": crawl_stats.get("requests", 0),
                "total_findings": len(findings),
            },
            "javascript_resources": [
                {
                    "url": item.url,
                    "source_url": item.source_url,
                    "status": item.status,
                    "content_type": item.content_type,
                    "size": item.size,
                    "sha256": item.sha256,
                    "duplicate_of": item.duplicate_of,
                }
                for item in resources
            ],
            "findings": [finding.to_dict() for finding in findings],
        }
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False),
            encoding="utf-8",
        )
        return report_path

    def write_markdown(
        self,
        findings: list[Finding],
        resources: list[JavaScriptResource],
        crawl_stats: dict,
    ) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / "report.md"
        lines = [
            "# JS Intelligence Scanner Report",
            "",
            f"- Target: `{self.target}`",
            f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
            f"- Duration: `{crawl_stats.get('duration_seconds', 0):.2f}` seconds",
            f"- Pages crawled: {crawl_stats.get('pages_crawled', 0)}",
            f"- JavaScript resources: {len(resources)}",
            "",
            "## Findings",
            "",
            "| Severity | Confidence | Type | Category | Source | Line | Evidence |",
            "|---|---|---|---|---|---:|---|",
        ]
        for finding in findings:
            data = finding.to_dict()
            evidence = str(data.get("evidence") or data.get("value") or "")
            lines.append(
                f"| {finding.risk.upper()} | {finding.confidence} | {finding.type} | "
                f"{finding.category} | {finding.source} | {finding.line_number or '-'} | "
                f"{html.escape(evidence)} |"
            )
        lines.extend([
            "",
            "## Manual verification",
            "",
            "- Verify the authorization scope before testing any discovered endpoint.",
            "- Confirm credential-like values without authenticating or using the credential.",
            "- Manually review infrastructure references for false positives.",
        ])
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def write_html(
        self,
        findings: list[Finding],
        resources: list[JavaScriptResource],
        crawl_stats: dict,
    ) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / "report.html"
        rows = []
        for finding in findings:
            data = finding.to_dict()
            evidence = html.escape(str(data.get("evidence") or data.get("value") or ""))
            source = html.escape(finding.source)
            rows.append(
                "<tr>"
                f"<td>{finding.risk.upper()}</td><td>{finding.confidence}</td>"
                f"<td>{html.escape(finding.type)}</td><td>{html.escape(finding.category)}</td>"
                f"<td>{source}</td><td>{finding.line_number or '-'}</td><td>{evidence}</td>"
                "</tr>"
            )
        document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>JS Intelligence Scanner Report</title>
<style>body{{font-family:Arial,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}th{{background:#eee}}</style>
</head><body><h1>JS Intelligence Scanner Report</h1>
<p><strong>Target:</strong> {html.escape(self.target)}<br>
<strong>Generated:</strong> {html.escape(datetime.now(timezone.utc).isoformat())}<br>
<strong>Duration:</strong> {crawl_stats.get("duration_seconds", 0):.2f} seconds<br>
<strong>Pages crawled:</strong> {crawl_stats.get("pages_crawled", 0)}<br>
<strong>JavaScript resources:</strong> {len(resources)}</p>
<table><thead><tr><th>Severity</th><th>Confidence</th><th>Type</th><th>Category</th><th>Source</th><th>Line</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Manual verification</h2><ul><li>Verify the authorization scope before testing any discovered endpoint.</li><li>Confirm credential-like values without authenticating or using them.</li><li>Manually review infrastructure references for false positives.</li></ul>
</body></html>"""
        path.write_text(document, encoding="utf-8")
        return path

    def print_terminal(
        self,
        findings: list[Finding],
        resources: list[JavaScriptResource],
        crawl_stats: dict,
        report_path: Path | None,
        quiet: bool = False,
    ) -> None:
        if quiet:
            return
        try:
            from rich.console import Console
            from rich.table import Table
        except ImportError:
            self._plain_terminal(findings, resources, crawl_stats, report_path)
            return

        console = Console()
        console.print("\n[bold cyan]========================================[/]")
        console.print("[bold cyan]       JS INTELLIGENCE SCANNER[/]")
        console.print("[bold cyan]========================================[/]")
        console.print(f"Target: {self.target}")
        console.print("Status: COMPLETED")
        table = Table(title="Scan Overview")
        table.add_column("Category")
        table.add_column("Count", justify="right")
        table.add_row("Pages crawled", str(crawl_stats.get("pages_crawled", 0)))
        table.add_row("JavaScript discovered", str(len(resources)))
        table.add_row("Endpoints", str(sum(item.type == "api_endpoint" for item in findings)))
        table.add_row("Potential secrets", str(sum(item.type in {"potential_secret", "confirmed_secret"} for item in findings)))
        table.add_row("Internal hostnames", str(sum(item.type == "internal_hostname" for item in findings)))
        table.add_row("Private IP references", str(sum(item.type == "private_ip" for item in findings)))
        table.add_row("Total findings", str(len(findings)))
        console.print(table)
        if report_path is None:
            console.print("\nReport: no file format selected")
        else:
            console.print(f"\nReport: [bold]{report_path}[/]")

    def _plain_terminal(
        self,
        findings: list[Finding],
        resources: list[JavaScriptResource],
        crawl_stats: dict,
        report_path: Path | None,
    ) -> None:
        print("========================================")
        print("       JS INTELLIGENCE SCANNER")
        print("========================================")
        print(f"Target: {self.target}")
        print("Status: COMPLETED")
        print(f"Pages crawled: {crawl_stats.get('pages_crawled', 0)}")
        print(f"JavaScript discovered: {len(resources)}")
        print(f"Endpoints: {sum(item.type == 'api_endpoint' for item in findings)}")
        print(f"Potential secrets: {sum(item.type in {'potential_secret', 'confirmed_secret'} for item in findings)}")
        print(f"Internal hostnames: {sum(item.type == 'internal_hostname' for item in findings)}")
        print(f"Private IP references: {sum(item.type == 'private_ip' for item in findings)}")
        print(f"Total findings: {len(findings)}")
        if report_path is None:
            print("Report: no file format selected")
        else:
            print(f"Report: {report_path}")

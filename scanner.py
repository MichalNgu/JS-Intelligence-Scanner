#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from core.config import ScannerConfig
from core.dashboard import HtmlDashboardGenerator
from core.http import SafeHttpClient
from core.reporter import Reporter
from core.scope import Scope
from modules.analyzer import Analyzer
from modules.crawler import Crawler
from modules.endpoint_finder import EndpointFinder
from modules.infrastructure import InfrastructureAnalyzer
from modules.js_extractor import JavaScriptExtractor
from modules.secret_scanner import SecretScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passive JavaScript reconnaissance for authorized targets."
    )
    parser.add_argument("target", help="Target URL, for example https://example.com")
    parser.add_argument("--depth", type=int, default=None, help="Maximum internal crawl depth")
    parser.add_argument("--output", default="results", help="Report output directory")
    parser.add_argument(
        "--format",
        action="append",
        choices=("json", "html", "markdown", "terminal"),
        help="Add an optional report format (repeatable); JSON is always generated",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Disable the default offline HTML dashboard",
    )
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--delay", type=float, default=None, help="Delay between requests")
    parser.add_argument("--max-pages", type=int, default=None)
    parser.add_argument("--max-file-size", type=int, default=None)
    parser.add_argument("--max-js-files", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--retries", type=int, default=None)
    parser.add_argument("--retry-backoff", type=float, default=None)
    parser.add_argument("--scope", action="append", default=[], help="Additional allowed hostname")
    parser.add_argument("--user-agent", default=None)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-robots", action="store_true", help="Skip robots.txt")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--config", help="Custom JSON configuration file")
    parser.add_argument("--allow-private-targets", action="store_true",
                        help="Allow explicitly authorized private/local targets for lab use")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.config:
            config = ScannerConfig.from_json(args.config, args.target)
            for name in (
                "depth", "timeout", "delay", "max_pages", "max_file_size",
                "max_js_files", "concurrency", "retries", "retry_backoff",
                "user_agent",
            ):
                value = getattr(args, name)
                if value is not None:
                    setattr(config, name, value)
            if args.insecure:
                config.verify_tls = False
            if args.no_robots:
                config.respect_robots = False
            config.allow_private_targets = args.allow_private_targets or config.allow_private_targets
            config.verbose = args.verbose or config.verbose
            if args.format:
                config.formats = tuple(args.format)
            config.__post_init__()
        else:
            config = ScannerConfig(
                target=args.target,
                depth=args.depth if args.depth is not None else 2,
                timeout=args.timeout if args.timeout is not None else 10.0,
                delay=args.delay if args.delay is not None else 0.2,
                max_pages=args.max_pages if args.max_pages is not None else 100,
                max_file_size=args.max_file_size if args.max_file_size is not None else 5 * 1024 * 1024,
                max_js_files=args.max_js_files if args.max_js_files is not None else 100,
                concurrency=args.concurrency if args.concurrency is not None else 1,
                retries=args.retries if args.retries is not None else 2,
                retry_backoff=args.retry_backoff if args.retry_backoff is not None else 0.5,
                user_agent=args.user_agent or "JS-Intelligence-Scanner/1.0",
                verify_tls=not args.insecure,
                respect_robots=not args.no_robots,
                allow_private_targets=args.allow_private_targets,
                formats=tuple(args.format or ("json",)),
                verbose=args.verbose,
            )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.WARNING if args.quiet else (logging.DEBUG if config.verbose else logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        scope = Scope.from_target(args.target, args.scope, config.allow_private_targets)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    scan_timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    started = time.monotonic()
    http_client = SafeHttpClient(config, scope)
    crawler = Crawler(config, scope, http_client)
    extractor = JavaScriptExtractor(config, scope, http_client)
    try:
        pages = crawler.crawl()
        resources = extractor.extract(pages)
    except Exception as exc:
        logging.getLogger(__name__).exception("Scan aborted: %s", exc)
        print(f"Error: scan aborted: {exc}", file=sys.stderr)
        return 1
    finally:
        crawler.close()
        extractor.close()
        http_client.close()

    endpoint_finder = EndpointFinder()
    secret_scanner = SecretScanner()
    infrastructure = InfrastructureAnalyzer()

    raw_findings = []
    raw_findings.extend(endpoint_finder.analyze(resources))
    raw_findings.extend(secret_scanner.analyze(resources))
    raw_findings.extend(infrastructure.analyze(resources))

    findings = Analyzer().analyze(raw_findings)
    duration = time.monotonic() - started
    crawler.stats["duration_seconds"] = round(duration, 3)
    crawler.stats["requests"] = http_client.requests_count
    crawler.stats["started_at"] = started_at
    formats = config.formats
    try:
        report_directory = Reporter.create_scan_directory(
            config.output_directory(args.output),
            config.target,
            scan_timestamp,
        )
        reporter = Reporter(config.target, report_directory)
        report_path = reporter.write_json(findings, resources, crawler.stats)
        if not report_path.is_file():
            raise OSError(f"JSON report was not created: {report_path}")

        if not args.no_html:
            dashboard_assets = HtmlDashboardGenerator().write_assets(report_directory)
            if len(dashboard_assets) != 3 or not all(path.is_file() for path in dashboard_assets):
                raise OSError(f"HTML dashboard was not completely generated: {report_directory}")
            report_path = report_directory / "index.html"

        if "markdown" in formats:
            reporter.write_markdown(findings, resources, crawler.stats)
        reporter.print_terminal(
            findings,
            resources,
            crawler.stats,
            report_path,
            quiet=args.quiet or "terminal" not in formats,
        )
    except (OSError, ValueError) as exc:
        logging.getLogger(__name__).exception("Report generation failed: %s", exc)
        print(f"Error: report generation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Report directory: {report_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

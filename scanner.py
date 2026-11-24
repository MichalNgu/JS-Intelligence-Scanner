#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from core.config import ScannerConfig
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
    parser.add_argument("--depth", type=int, default=2, help="Maximum internal crawl depth")
    parser.add_argument("--output", default="results", help="Report output directory")
    parser.add_argument("--format", action="append", choices=("json", "html", "markdown", "terminal"), help="Report format (repeatable)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests")
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-file-size", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--max-js-files", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-backoff", type=float, default=0.5)
    parser.add_argument("--scope", action="append", default=[], help="Additional allowed hostname")
    parser.add_argument("--user-agent", default="JS-Intelligence-Scanner/1.0")
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
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.config:
            config = ScannerConfig.from_json(args.config, args.target)
            config.depth = args.depth if args.depth != 2 else config.depth
            config.timeout = args.timeout if args.timeout != 10.0 else config.timeout
            config.max_pages = args.max_pages if args.max_pages != 100 else config.max_pages
            config.verify_tls = not args.insecure
            config.respect_robots = not args.no_robots
            config.allow_private_targets = args.allow_private_targets or config.allow_private_targets
            config.verbose = args.verbose
            if args.format:
                config.formats = tuple(args.format)
        else:
            config = ScannerConfig(
                target=args.target,
                depth=args.depth,
                timeout=args.timeout,
                delay=args.delay,
                max_pages=args.max_pages,
                max_file_size=args.max_file_size,
                max_js_files=args.max_js_files,
                concurrency=args.concurrency,
                retries=args.retries,
                retry_backoff=args.retry_backoff,
                user_agent=args.user_agent,
                verify_tls=not args.insecure,
                respect_robots=not args.no_robots,
                allow_private_targets=args.allow_private_targets,
                formats=tuple(args.format or ("json",)),
                verbose=args.verbose,
            )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        scope = Scope.from_target(args.target, args.scope, config.allow_private_targets)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    started = time.monotonic()
    crawler = Crawler(config, scope)
    extractor = JavaScriptExtractor(config, scope)
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

    endpoint_finder = EndpointFinder()
    secret_scanner = SecretScanner()
    infrastructure = InfrastructureAnalyzer()

    raw_findings = []
    raw_findings.extend(endpoint_finder.analyze(resources))
    raw_findings.extend(secret_scanner.analyze(resources))
    raw_findings.extend(infrastructure.analyze(resources))

    findings = Analyzer().analyze(raw_findings)
    reporter = Reporter(config.target, config.output_directory(args.output))
    duration = time.monotonic() - started
    crawler.stats["duration_seconds"] = round(duration, 3)
    crawler.stats["requests"] = crawler.http.requests_count + extractor.http.requests_count
    crawler.stats["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report_path = config.output_directory(args.output) / "report.json"
    formats = config.formats
    if "json" in formats:
        report_path = reporter.write_json(findings, resources, crawler.stats)
    if "html" in formats:
        reporter.write_html(findings, resources, crawler.stats)
    if "markdown" in formats:
        reporter.write_markdown(findings, resources, crawler.stats)
    reporter.print_terminal(findings, resources, crawler.stats, report_path, quiet=args.quiet or "terminal" not in formats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

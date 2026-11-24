# JS Intelligence Scanner

Passive JavaScript reconnaissance for authorized security assessments. The scanner crawls an explicitly configured scope, discovers external and inline JavaScript, analyzes static endpoint and secret patterns, identifies infrastructure references, and produces redacted reports.

## Features

- Scope-validated HTTP crawling with hostname, DNS, private-address, port, redirect, timeout, retry, and response-size controls
- External and inline script discovery, ES/dynamic imports, source maps, and references found in downloaded JavaScript
- Relative, absolute, REST, GraphQL, WebSocket, fetch, Axios, and XMLHttpRequest endpoint extraction
- Credential-like secret detection with entropy checks and configurable custom regex rules
- Private IP, internal hostname, environment, external domain, and cloud-infrastructure intelligence
- JSON, HTML, Markdown, and terminal reports with severity, confidence, source, evidence, and line numbers
- Deduplicated and correlated findings; secret values are redacted by default

The scanner performs static analysis only. It does not execute JavaScript or use discovered credentials.

## Installation

Requires Python 3.10 or newer.

```powershell
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
py -m pip install -r requirements.txt
```

## Usage

```powershell
py scanner.py https://example.com
py scanner.py https://example.com --depth 3 --max-pages 250 --max-js-files 100
py scanner.py https://example.com --scope api.example.com --format json --format html --format markdown
py scanner.py https://example.com --config config.example.json --verbose
```

Use the tool only for systems you are explicitly authorized to assess.

## CLI options

| Option | Description | Default |
|---|---|---|
| `target` | Absolute HTTP or HTTPS target URL | Required |
| `--depth` | Maximum crawl depth | `2` |
| `--output` | Report output directory | `results` |
| `--format` | Repeatable format: `json`, `html`, `markdown`, `terminal` | `json` |
| `--timeout` | HTTP timeout in seconds | `10` |
| `--delay` | Delay between requests | `0.2` |
| `--max-pages` | Maximum crawled HTML pages | `100` |
| `--max-js-files` | Maximum discovered JavaScript/source-map resources | `100` |
| `--max-file-size` | Maximum response size per file | `5 MiB` |
| `--concurrency` | Configured concurrency limit | `1` |
| `--retries` | Retries for transient HTTP failures | `2` |
| `--retry-backoff` | Initial exponential backoff in seconds | `0.5` |
| `--scope` | Additional allowed hostname (repeatable) | Target hostname |
| `--user-agent` | HTTP User-Agent | `JS-Intelligence-Scanner/1.0` |
| `--insecure` | Disable TLS certificate verification | Disabled |
| `--no-robots` | Skip robots.txt processing | Disabled |
| `--allow-private-targets` | Allow explicitly authorized localhost/private/lab targets | Disabled |
| `--config` | JSON configuration file | None |
| `--verbose` / `-v` | Enable detailed logging | Disabled |
| `--quiet` | Suppress terminal report | Disabled |

Exit codes: `0` completed, `1` runtime failure, `2` invalid input or configuration.

## JSON configuration

```json
{
  "depth": 2,
  "timeout": 10,
  "max_pages": 100,
  "max_js_files": 100,
  "max_file_size": 5242880,
  "concurrency": 1,
  "retries": 2,
  "retry_backoff": 0.5,
  "user_agent": "Authorized-JS-Scanner/1.0",
  "respect_robots": true,
  "allow_private_targets": false,
  "formats": ["json", "html", "markdown"]
}
```

## Reports

Reports are written to `results/report.json`, `results/report.html`, and/or `results/report.md`, as selected. They include target and timing metadata, crawl statistics, JavaScript resources, deduplicated findings, severity, confidence, source URL, evidence, line number, and manual verification guidance.

Example finding shape:

```json
{
  "type": "api_endpoint",
  "value": "/api/v1/users",
  "source": "https://example.com/app.js",
  "category": "API Route",
  "risk": "low",
  "confidence": "medium",
  "line_number": 42
}
```

## Architecture

- `core/config.py`: centralized configuration and limits
- `core/scope.py`: URL normalization, scope, DNS, port, and private-address enforcement
- `core/http.py`: shared HTTP session, retries, streaming limits, and response cleanup
- `modules/crawler.py`: bounded HTML crawl
- `modules/js_extractor.py`: HTML and JavaScript resource discovery
- `modules/endpoint_finder.py`: static endpoint analysis
- `modules/secret_scanner.py`: secret and entropy analysis
- `modules/infrastructure.py`: infrastructure intelligence
- `modules/analyzer.py`: deduplication and finding correlation
- `core/reporter.py`: terminal, JSON, HTML, and Markdown reports

## Testing

The test suite uses local fixtures and mocks and does not scan external websites.

```powershell
py -m pytest -q
```

## Security limitations

- DNS rebinding is mitigated by resolving and validating every requested hostname, but there is no pinned-IP HTTP transport adapter; highly controlled networks should use an allowlisted lab proxy or host firewall.
- Static analysis can produce false positives and cannot confirm credentials or vulnerabilities.
- Redirect responses are followed only manually when the redirect remains within the configured host and port scope.
- Private, loopback, link-local, reserved, and cloud metadata addresses are blocked unless `--allow-private-targets` is explicitly set.
- Concurrency is currently exposed and bounded but HTTP processing remains intentionally sequential to preserve deterministic scope enforcement and consistent findings.

## Responsible use

Only scan systems you own or have explicit written permission to assess. Reconnaissance findings are not proof of exploitability. Do not authenticate with, disclose, store unnecessarily, or exploit discovered credentials.

## Contributing

Contributions should preserve scope safety, add focused tests, keep dependencies minimal, and avoid executing or exploiting downloaded JavaScript or credentials.

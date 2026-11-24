from scanner import build_parser


def test_cli_accepts_safe_options():
    parser = build_parser()
    args = parser.parse_args([
        "https://example.com",
        "--depth", "3",
        "--max-pages", "25",
        "--max-js-files", "40",
        "--concurrency", "4",
        "--format", "json",
        "--format", "html",
        "--no-html",
        "--scope", "example.net",
    ])
    assert args.depth == 3
    assert args.max_pages == 25
    assert args.max_js_files == 40
    assert args.concurrency == 4
    assert args.format == ["json", "html"]
    assert args.no_html
